"""Tabular views of an inventory: what each page of the desktop app lists.

Kept free of any GUI toolkit so it can be tested directly and reused by exports. A
`Snapshot` derives everything once (topology graph, IPAM, placements, findings) and the
row functions read from it. Every row is a dict; keys starting with "_" are metadata:
``_id`` is the node the row is about (for selection and "show on map"), ``_role`` and
``_kind`` pick its icon.
"""
from __future__ import annotations

import bisect
import ipaddress
import re
from functools import lru_cache
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Callable, Optional

from .graph import build_graph, edge_ports, ipam_rows, norm_port, vlan_rows
from .roles import group_key
from .model import Inventory

STATUSES = ["", "Verified", "Needs review", "Unknown owner", "To be replaced", "To decommission"]


@dataclass
class Column:
    key: str
    title: str
    kind: str = "text"  # text | int | ip | cidr | pct | time | duration | port | bool
    width: int = 0
    visible: bool = True
    tip: str = ""


def _is_ip(s) -> bool:
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


def _v4_int(s) -> Optional[int]:
    try:
        a = ipaddress.ip_address(str(s))
    except ValueError:
        return None
    return int(a) if a.version == 4 else None


def _is_ipv4(s) -> bool:
    return _v4_int(s) is not None


def ip_key(s) -> tuple:
    s = str(s or "").split("/")[0].split()[0] if s else ""
    try:
        a = ipaddress.ip_address(s)
        return (0, a.version, int(a))
    except ValueError:
        return (1, 0, str(s).lower())


def natural_key(s) -> tuple:
    return tuple((0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.split(r"(\d+)", str(s or "").lower()) if t)


def sort_key(kind: str, v):
    # sorting a large table asks for the same (kind, value) key over and over as the
    # comparison function runs; memoise so ip/natural keys aren't rebuilt each compare.
    try:
        return _sort_key_cached(kind, v)
    except TypeError:  # unhashable value - fall back to the direct computation
        return _sort_key(kind, v)


@lru_cache(maxsize=100_000)
def _sort_key_cached(kind: str, v):
    return _sort_key(kind, v)


def _sort_key(kind: str, v):
    if kind in ("ip", "cidr"):
        if kind == "cidr":
            try:
                n = ipaddress.ip_network(str(v))
                return (0, int(n.network_address), n.prefixlen)
            except ValueError:
                return (1, 0, 0)
        return ip_key(v)
    if kind in ("int", "pct", "time", "duration"):
        try:
            return (0, float(v))
        except (TypeError, ValueError):
            return (1, 0.0)
    if kind == "bool":
        return (0, 1 if v else 0)
    if kind == "severity":
        return (_SEV_ORDER.get(str(v).lower(), 9),)
    return natural_key(v)


def fmt_time(ts) -> str:
    if not ts:
        return ""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(ts)))


def fmt_duration(seconds) -> str:
    s = int(seconds or 0)
    if s <= 0:
        return ""
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s % 60}s" if m < 10 else f"{m}m"
    return f"{s}s"


_SHORT_PORTS = [
    ("hundredgigabitethernet", "Hu"), ("fortygigabitethernet", "Fo"), ("twentyfivegige", "Twe"), ("tengigabitethernet", "Te"),
    ("fivegigabitethernet", "Fi"), ("twogigabitethernet", "Tw"), ("gigabitethernet", "Gi"), ("fastethernet", "Fa"),
    ("port-channel", "Po"), ("bundle-ether", "BE"), ("ethernet", "Eth"), ("management", "Mgmt"),
]
_MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)


def short_port(name: str) -> str:
    """GigabitEthernet1/0/2 -> Gi1/0/2: the form people write on diagrams."""
    n = (name or "").strip()
    low = n.lower()
    for long, short in _SHORT_PORTS:
        if low.startswith(long):
            return short + n[len(long):].lstrip()
    return n


def is_mac(s: str) -> bool:
    return bool(_MAC_RE.match((s or "").strip()))


def fmt_speed(mbps) -> str:
    m = int(mbps or 0)
    if not m:
        return ""
    if m >= 1000 and m % 1000 == 0:
        return f"{m // 1000}G"
    if m >= 1000:
        return f"{m / 1000:.1f}G"
    return f"{m}M"


class Snapshot:
    """Everything the views need, derived once from an inventory."""

    def __init__(self, inv: Inventory):
        self.inv = inv
        self.g = build_graph(inv)
        self.ipam = {r["cidr"]: r for r in ipam_rows(inv)}
        self.vlans = vlan_rows(inv)
        self.fdb_hosts: dict[str, list[tuple[str, str, Optional[int]]]] = defaultdict(list)
        self.placement: dict[str, tuple[str, str, Optional[int]]] = {}
        for u, v, a in self.g.edges(data=True):
            if a.get("kind") == "fdb":
                dev, host = (u, v) if u in inv.devices else (v, u)
                self.fdb_hosts[dev].append((host, a.get("port", ""), a.get("vlan")))
                self.placement.setdefault(host, (dev, a.get("port", ""), a.get("vlan")))
        self.port_neighbors: dict[tuple[str, int], list[str]] = defaultdict(list)
        for d in inv.devices.values():
            for nb in d.neighbors:
                if nb.local_if_index is not None:
                    self.port_neighbors[(d.id, nb.local_if_index)].append(f"{nb.remote_name or nb.remote_chassis_id} {nb.remote_port}".strip())
        self.port_macs: Counter = Counter()
        for d in inv.devices.values():
            for f in d.fdb:
                if f.if_index is not None:
                    self.port_macs[(d.id, f.if_index)] += 1
        self.stubs = {n: a for n, a in self.g.nodes(data=True) if a.get("role") == "unpolled"}
        # switches/routers that announced themselves, answer in ARP, but did not answer SNMP
        self.silent_infra = {n: a for n, a in self.g.nodes(data=True)
                             if a.get("kind") == "host" and a.get("announced") and a.get("role") in ("switch", "l3switch", "router", "firewall")}
        infra = {"switch", "l3switch", "router", "firewall", "wireless", "unpolled"}

        def is_infra(n):
            a = self.g.nodes[n]
            return a.get("kind") == "device" or a.get("role") in infra

        # links between network kit; a phone's or server's LLDP link is on its host record instead
        self.links = [(u, v, a) for u, v, a in self.g.edges(data=True) if a.get("kind") in ("lldp", "cdp", "l3") and is_infra(u) and is_infra(v)]
        self.endpoint_links = sum(1 for u, v, a in self.g.edges(data=True) if a.get("kind") in ("lldp", "cdp") and not (is_infra(u) and is_infra(v)))
        # first-hop redundancy virtual gateways, per subnet: {cidr: [{vip, proto, active, devices}]}
        self.vgw: dict[str, list[dict]] = defaultdict(list)
        seen_vip: dict[str, dict] = {}
        for d in inv.devices.values():
            for gexp in getattr(d, "redundancy", []):
                vip = gexp.get("vip")
                if not vip:
                    continue
                cidr = inv.subnet_for_ip(vip)
                rec = seen_vip.get(vip)
                if rec is None:
                    rec = {"vip": vip, "proto": gexp["proto"], "active": "", "devices": []}
                    seen_vip[vip] = rec
                    self.vgw[cidr or ""].append(rec)
                rec["devices"].append(d.id)
                if gexp.get("state") in ("active", "master"):
                    rec["active"] = d.id

    # ---- helpers ----
    def name(self, node_id: str) -> str:
        if node_id in self.g:
            return self.g.nodes[node_id].get("label") or node_id
        return self.inv.display_name(node_id)

    def role(self, node_id: str) -> str:
        if node_id in self.g:
            return self.g.nodes[node_id].get("role") or ""
        return ""

    def kind(self, node_id: str) -> str:
        if node_id in self.g:
            return self.g.nodes[node_id].get("kind") or ""
        return ""


# ---------------------------------------------------------------- devices
DEVICE_COLUMNS = [
    Column("name", "Name", width=170),
    Column("ip", "Management IP", "ip", 120),
    Column("role", "Role", width=90),
    Column("vendor", "Vendor", width=110),
    Column("model", "Model", width=140),
    Column("os_version", "OS version", width=110),
    Column("serial", "Serial", width=120),
    Column("site", "Site / location", width=140),
    Column("ports_up", "Ports up", "int", 70, tip="interfaces operationally up / total"),
    Column("neighbors", "Neighbours", "int", 80),
    Column("hosts", "Hosts on ports", "int", 90),
    Column("free_ports", "Free ports", "int", 75, tip="enabled access ports with nothing connected (link down, no address, not a trunk or bundle member)"),
    Column("vlans", "VLANs", "int", 60),
    Column("uptime", "Uptime", "duration", 80),
    Column("status", "Status", width=100),
    Column("tags", "Tags", width=100),
    Column("notes", "Notes", width=160),
    Column("dns", "DNS name", width=160, visible=False),
    Column("first_seen", "First seen", "time", 120, visible=False),
    Column("polled", "Last polled", "time", 120),
    Column("via", "Discovered via", width=130, visible=False),
    Column("credential", "Credential", width=100, visible=False),
    Column("contact", "Contact", width=120, visible=False),
    Column("errors", "Collection errors", width=160, visible=False),
    Column("group", "Kind", width=90, visible=False, tip="broad kind for grouping: network, servers, pcs, printers… (filter with group:servers)"),
]


_PHYSICAL_IFTYPES = {0, 6, 117}  # unknown, ethernetCsmacd, gigabitEthernet


def free_ports(d) -> int:
    """Enabled access ports with nothing on them: link down, no address, not a trunk, not
    part of a bundle, not a bundle/SVI/loopback itself. What a hand-over asks: "where can I
    plug something in?"."""
    return sum(
        1 for i in d.interfaces
        if i.admin_up and not i.oper_up and not i.ips and i.mode != "trunk" and not i.lag and i.type in _PHYSICAL_IFTYPES
        and not re.match(r"^(vlan|vl\d|lo|loopback|po\d|port-?channel|null|tunnel|mgmt|management)", (i.name or i.descr or ""), re.I)
    )


def device_rows(s: Snapshot) -> list[dict]:
    inv = s.inv
    rows = []
    for d in inv.devices.values():
        note = inv.note(d.id)
        up = sum(1 for i in d.interfaces if i.oper_up)
        rows.append(
            {
                "_id": d.id, "_kind": "device", "_role": note.get("role") or d.role,
                "name": s.name(d.id), "ip": d.id, "role": note.get("role") or d.role, "vendor": d.vendor, "model": d.model,
                "os_version": d.os_version, "serial": d.serial, "site": note.get("site") or d.location,
                "ports_up": up, "_ports_total": len(d.interfaces), "neighbors": len(d.neighbors),
                "hosts": len(s.fdb_hosts.get(d.id, [])), "free_ports": free_ports(d), "vlans": len(d.vlans), "uptime": d.uptime_s,
                "status": note.get("status", ""), "tags": ", ".join(note.get("tags", [])), "notes": note.get("notes", ""),
                "dns": d.dns_name, "first_seen": d.first_seen, "polled": d.collected_at, "via": d.discovered_via,
                "credential": d.credential, "contact": d.contact, "errors": "; ".join(d.errors),
                "group": group_key(note.get("role") or d.role),
            }
        )
    # neighbours seen but never polled belong in the device list too: they are devices
    for sid, a in s.stubs.items():
        note = inv.note(sid)
        rows.append(
            {
                "_id": sid, "_kind": "device", "_role": "unpolled",
                "name": note.get("name") or a.get("label", sid), "ip": a.get("ip", ""), "role": note.get("role") or "unpolled",
                "vendor": "", "model": a.get("model", ""), "os_version": "", "serial": "", "site": note.get("site", ""),
                "ports_up": "", "neighbors": s.g.degree(sid), "hosts": "", "free_ports": "", "vlans": "", "uptime": "",
                "status": note.get("status", ""), "tags": ", ".join(note.get("tags", [])), "notes": note.get("notes", ""),
                "dns": "", "first_seen": "", "polled": "", "via": "announced by a neighbour", "credential": "", "contact": "",
                "errors": "not polled: no credentials answered, or outside the scope",
                "group": group_key(note.get("role") or "unpolled"),
            }
        )
    return rows


# ---------------------------------------------------------------- hosts
HOST_COLUMNS = [
    Column("name", "Name", width=170),
    Column("ip", "IP address", "ip", 115),
    Column("mac", "MAC", width=125),
    Column("vendor", "Vendor (OUI)", width=150),
    Column("role", "Type", width=95),
    Column("confidence", "Confidence", width=90, tip="how sure the type/OS is, from how many signals agreed"),
    Column("os", "OS", width=130),
    Column("subnet", "Subnet", "cidr", 115),
    Column("switch", "Switch", width=130),
    Column("port", "Port", "port", 80),
    Column("vlan", "VLAN", "int", 55),
    Column("services", "Open ports", width=150),
    Column("functions", "Functions", width=170, tip="server roles inferred from open ports (web, database, file, mail, DNS…)"),
    Column("model", "Model", width=140, visible=False),
    Column("identified_by", "Identified by", width=170, visible=False),
    Column("status", "Status", width=100),
    Column("tags", "Tags", width=100),
    Column("notes", "Notes", width=150),
    Column("sources", "Seen via", width=110, visible=False),
    Column("first_seen", "First seen", "time", 120, visible=False),
    Column("last_seen", "Last seen", "time", 120),
    Column("snmp", "SNMP", width=80, visible=False),
    Column("group", "Kind", width=90, visible=False, tip="broad kind for grouping: servers, pcs, printers… (filter with group:servers)"),
]


def host_rows(s: Snapshot) -> list[dict]:
    inv = s.inv
    rows = []
    for ip, h in inv.hosts.items():
        if ip in inv.ip_to_device:
            continue
        note = inv.note(ip)
        dev, port, vlan = s.placement.get(ip, ("", "", None))
        role = note.get("role") or s.role(ip) or h.role
        rows.append(
            {
                "_id": ip, "_kind": "host", "_role": role,
                "name": s.name(ip) if s.name(ip) != ip else (h.hostname or ""), "ip": ip, "mac": h.mac or "", "vendor": h.vendor,
                "role": role, "confidence": h.confidence, "os": h.os or h.os_family, "model": h.model,
                "identified_by": ", ".join(sorted({e["source"] for e in h.evidence})) if h.evidence else "",
                "subnet": inv.subnet_for_ip(ip) or "", "switch": s.name(dev) if dev else "", "_switch_id": dev,
                "port": port, "vlan": vlan if vlan is not None else "",
                "services": " ".join(f"{p['port']}/{p.get('service', '')}".rstrip("/") for p in h.ports),
                "functions": ", ".join(h.functions or []),
                "status": note.get("status", ""), "tags": ", ".join(note.get("tags", [])), "notes": note.get("notes", ""),
                "sources": " ".join(h.sources), "first_seen": h.first_seen, "last_seen": h.last_seen,
                "snmp": "no answer" if h.snmp_failed else "",
                "group": group_key(role),
            }
        )
    return rows


# ---------------------------------------------------------------- subnets / IPAM
SUBNET_COLUMNS = [
    Column("cidr", "Subnet", "cidr", 125),
    Column("vlan", "VLAN", width=55),
    Column("util", "Utilisation", "pct", 130),
    Column("used", "In use", "int", 65),
    Column("free", "Free", "int", 65),
    Column("usable", "Usable", "int", 65),
    Column("gateways", "Gateway(s)", width=170),
    Column("name", "Name", width=140),
    Column("swept", "Swept", "bool", 55, tip="whether every address was probed; if not, 'in use' is a floor"),
    Column("site", "Site", width=110),
    Column("notes", "Notes", width=160),
    Column("sources", "Found via", width=120, visible=False),
]


def subnet_rows(s: Snapshot) -> list[dict]:
    inv = s.inv
    rows = []
    for cidr, r in s.ipam.items():
        note = inv.note(cidr)
        rows.append(
            {
                "_id": cidr, "_kind": "subnet", "_role": "subnet",
                "cidr": cidr, "name": note.get("name", ""), "vlan": r["vlan"], "gateways": r["gateways"],
                "usable": r["usable"], "used": r["used"], "free": r["free"], "util": r["utilisation_pct"],
                "swept": bool(r["swept"]), "site": note.get("site", ""), "notes": note.get("notes", ""), "sources": r["sources"],
            }
        )
    return rows


def subnet_addresses(s: Snapshot, cidr: str, limit: int = 4096) -> list[dict]:
    """Every address of a subnet (up to `limit`) with what occupies it: the IP map."""
    inv = s.inv
    net = ipaddress.ip_network(cidr)
    gateways = set()
    for g in inv.subnets.get(cidr).gateways if cidr in inv.subnets else []:
        d = inv.devices.get(g)
        if d:
            for i in d.interfaces:
                for ipc in i.ips:
                    try:
                        if ipaddress.ip_interface(ipc).network == net:
                            gateways.add(ipc.split("/")[0])
                    except ValueError:
                        pass
    out = []
    for n, a in enumerate(net):
        if n >= limit:
            break
        ip = str(a)
        rec = {"ip": ip, "state": "free", "label": "", "role": "", "node": ""}
        if net.prefixlen < 31 and (a == net.network_address or a == net.broadcast_address):
            rec["state"] = "reserved"
            rec["label"] = "network" if a == net.network_address else "broadcast"
        elif ip in inv.ip_to_device:
            did = inv.ip_to_device[ip]
            rec.update(state="gateway" if ip in gateways else "device", label=s.name(did), role=s.role(did), node=did)
        elif ip in inv.hosts:
            rec.update(state="host", label=s.name(ip) if s.name(ip) != ip else (inv.hosts[ip].hostname or inv.hosts[ip].vendor), role=s.role(ip) or inv.hosts[ip].role, node=ip)
        elif ip in inv.unreachable:
            rec.update(state="silent", label="probed, no SNMP answer")
        out.append(rec)
    return out


# ---------------------------------------------------------------- VLANs
VLAN_COLUMNS = [
    Column("vlan", "VLAN", "int", 60),
    Column("names", "Name(s)", width=180),
    Column("devices", "Switches", "int", 70),
    Column("carried_on", "Carried on", width=260),
    Column("subnets", "Subnet(s)", width=160),
    Column("hosts", "Hosts learned", "int", 90),
    Column("notes", "Notes", width=160),
]


def vlan_rows_view(s: Snapshot) -> list[dict]:
    inv = s.inv
    subnets_by_vlan: dict[int, set] = defaultdict(set)
    for cidr, r in s.ipam.items():
        for v in str(r["vlan"]).split():
            if v.isdigit():
                subnets_by_vlan[int(v)].add(cidr)
    # distinct MACs per VLAN: every switch on the path learns the same address, so rows
    # would count one laptop once per switch
    macs_by_vlan: dict[int, set] = defaultdict(set)
    for d in inv.devices.values():
        for f in d.fdb:
            if f.vlan is not None:
                macs_by_vlan[f.vlan].add(f.mac)
    hosts_by_vlan = {vid: len(m) for vid, m in macs_by_vlan.items()}
    rows = []
    for vid, (names, devs) in s.vlans.items():
        note = inv.note(f"vlan:{vid}")
        rows.append(
            {
                "_id": f"vlan:{vid}", "_kind": "vlan", "_role": "",
                "vlan": vid, "names": " / ".join(sorted(names)), "_conflict": len(names) > 1, "devices": len(devs),
                "carried_on": ", ".join(sorted(devs, key=natural_key)), "subnets": ", ".join(sorted(subnets_by_vlan.get(vid, ()), key=lambda c: sort_key("cidr", c))),
                "hosts": hosts_by_vlan.get(vid, 0), "notes": note.get("notes", ""),
            }
        )
    return rows


# ---------------------------------------------------------------- links
LINK_COLUMNS = [
    Column("a", "Device A", width=160),
    Column("a_port", "Port A", "port", 110),
    Column("b", "Device B", width=160),
    Column("b_port", "Port B", "port", 110),
    Column("kind", "Learned from", width=90),
    Column("speed", "Speed", width=70),
    Column("detail", "Detail", width=200),
]


def _iface_by_label(dev, label: str):
    if dev is None or not label:
        return None
    nl = norm_port(label)
    for i in dev.interfaces:
        if norm_port(i.name) == nl or norm_port(i.descr) == nl:
            return i
    return None


def link_rows(s: Snapshot) -> list[dict]:
    inv = s.inv
    rows = []
    kinds = {"lldp": "LLDP", "cdp": "CDP", "l3": "Routing"}
    for u, v, a in s.links:
        pu, pv = edge_ports(u, v, a)
        ia = _iface_by_label(inv.devices.get(u), pu)
        ib = _iface_by_label(inv.devices.get(v), pv)
        speeds = {fmt_speed(i.speed_mbps) for i in (ia, ib) if i is not None and i.speed_mbps}
        rows.append(
            {
                "_id": u, "_other": v, "_kind": "link", "_role": s.role(u),
                "a": s.name(u), "a_port": pu, "b": s.name(v), "b_port": pv,
                "kind": kinds.get(a.get("kind"), a.get("kind")), "speed": " / ".join(sorted(speeds)), "_mismatch": len(speeds) > 1,
                "detail": a.get("label", "") if a.get("kind") == "l3" else "",
            }
        )
    return rows


# ---------------------------------------------------------------- interfaces
IFACE_COLUMNS = [
    Column("device", "Device", width=150),
    Column("name", "Interface", "port", 110),
    Column("alias", "Description", width=180),
    Column("status", "Status", width=90),
    Column("speed", "Speed", width=60),
    Column("vlan", "VLAN", "int", 55),
    Column("mode", "Mode", width=60),
    Column("duplex", "Duplex", width=60, visible=False),
    Column("lag", "LAG", width=70),
    Column("util", "Utilisation", "pct", 120, tip="busiest direction over the interval between the last two scans; rescan to measure"),
    Column("errors", "Errors", "int", 70, tip="input + output errors (cumulative counter)"),
    Column("err_rate", "Err/s", width=60, visible=False, tip="errors per second between the last two scans"),
    Column("poe", "PoE", width=110, tip="Power over Ethernet status, class and watts"),
    Column("ips", "Addresses", width=140),
    Column("neighbor", "Neighbour", width=170),
    Column("macs", "MACs learned", "int", 85),
    Column("mac", "MAC", width=125, visible=False),
    Column("last_change", "Last change", "duration", 90, visible=False, tip="time since the port last changed state"),
    Column("ifindex", "ifIndex", "int", 60, visible=False),
]


def interface_rows(s: Snapshot, device_id: Optional[str] = None) -> list[dict]:
    inv = s.inv
    rows = []
    devs = [inv.devices[device_id]] if device_id else list(inv.devices.values())
    for d in devs:
        for i in d.interfaces:
            status = ("up" if i.oper_up else "down") if i.admin_up else "disabled"
            since = (d.uptime_s - i.last_change_s) if i.last_change_s and d.uptime_s >= i.last_change_s else 0
            rows.append(
                {
                    "_id": d.id, "_kind": "iface", "_role": d.role,
                    "device": s.name(d.id), "name": i.name or i.descr or f"if{i.index}", "alias": i.alias or (i.descr if i.name and i.descr != i.name else ""),
                    "status": status, "speed": fmt_speed(i.speed_mbps), "vlan": i.vlan if i.vlan is not None else "", "mode": i.mode, "duplex": i.duplex, "lag": i.lag,
                    "util": max(i.in_util_pct, i.out_util_pct) if (i.in_util_pct or i.out_util_pct) else "",
                    "errors": (i.in_errors + i.out_errors) or "", "err_rate": i.err_rate or "",
                    "poe": (f"{i.poe_status} {('cls ' + i.poe_class) if i.poe_class else ''} {(str(i.poe_watts) + 'W') if i.poe_watts else ''}".strip()) if i.poe_status else "",
                    "ips": " ".join(i.ips), "neighbor": "; ".join(s.port_neighbors.get((d.id, i.index), [])),
                    "macs": s.port_macs.get((d.id, i.index), 0) or "", "mac": i.mac or "", "last_change": since, "ifindex": i.index,
                }
            )
    return rows


# ---------------------------------------------------------------- hardware
HARDWARE_COLUMNS = [
    Column("device", "Device", width=150),
    Column("cls", "Class", width=90),
    Column("name", "Name", width=150),
    Column("descr", "Description", width=220),
    Column("model", "Model", width=130),
    Column("serial", "Serial", width=130),
    Column("hw_rev", "HW rev", width=70),
    Column("fw_rev", "FW rev", width=90, visible=False),
    Column("sw_rev", "SW rev", width=90),
    Column("fru", "FRU", "bool", 45),
]


def hardware_rows(s: Snapshot, device_id: Optional[str] = None) -> list[dict]:
    inv = s.inv
    rows = []
    devs = [inv.devices[device_id]] if device_id else list(inv.devices.values())
    for d in devs:
        comps = list(getattr(d, "components", []) or [])
        if not comps and (d.model or d.serial):
            rows.append({"_id": d.id, "_kind": "component", "_role": d.role, "device": s.name(d.id), "cls": "chassis", "name": "", "descr": d.sysdescr[:80],
                         "model": d.model, "serial": d.serial, "hw_rev": "", "fw_rev": "", "sw_rev": d.os_version, "fru": False})
        for c in comps:
            rows.append(
                {
                    "_id": d.id, "_kind": "component", "_role": d.role, "device": s.name(d.id), "cls": c.cls, "name": c.name, "descr": c.descr,
                    "model": c.model, "serial": c.serial, "hw_rev": c.hw_rev, "fw_rev": c.fw_rev, "sw_rev": c.sw_rev, "fru": bool(c.fru),
                }
            )
    return rows


# ---------------------------------------------------------------- findings
FINDING_COLUMNS = [
    Column("severity", "Level", "severity", 85),
    Column("category", "Finding", width=190),
    Column("item", "Item", width=170),
    Column("detail", "Detail", width=260),
    Column("why", "Why it matters", width=320),
]

_SEV_ORDER = {"attention": 0, "check": 1, "info": 2}


def finding_rows(s: Snapshot) -> list[dict]:
    """What an engineer taking over this network should look at, most useful first."""
    inv = s.inv
    rows: list[dict] = []

    def add(sev, cat, node, item, detail, why):
        rows.append({"_id": node, "_kind": s.kind(node) or "", "_role": s.role(node), "severity": sev.capitalize(), "category": cat, "item": item, "detail": detail, "why": why})

    for sid, a in s.stubs.items():
        via = ", ".join(sorted({s.name(n) for n in s.g.neighbors(sid)}))
        if a.get("endpoint"):
            # a phone, access point or station that announced itself but never showed in
            # ARP: an endpoint that was quiet, not network kit that refused us
            add("info", "Endpoint announced over LLDP, address not seen", sid, a.get("label", sid),
                f"{a.get('endpoint')}  {a.get('model', '')[:60]}  on {via}",
                "It told the switch what it is over LLDP/CDP but no address was seen for it: powered off, or on a VLAN that was not swept")
            continue
        add("attention", "Neighbour not polled", sid, a.get("label", sid), f"ip={a.get('ip') or '-'}  {a.get('model', '')[:60]}  seen from {via}",
            "Announced over LLDP/CDP but no credential worked, or it is outside the scope: an unmanaged device or one missing from the handover")
    for hid, a in s.silent_infra.items():
        via = ", ".join(sorted({s.name(n) for n in s.g.neighbors(hid) if s.kind(n) == "device"}))
        add("attention", "Neighbour not polled", hid, a.get("label", hid), f"ip={hid}  {a.get('platform', '')[:60]}  seen from {via}",
            "A switch or router that announces itself over LLDP/CDP and is on the network, but no credential worked: unmanaged, or missing from the handover")
    for d in inv.devices.values():
        quiet = [e for e in d.errors if e == "no answer on rescan"]
        if quiet:
            add("attention", "Device stopped answering", d.id, s.name(d.id), "answered before, silent on the last rescan", "Down, replaced, readdressed, or its SNMP access was changed")
        errs = [e for e in d.errors if e != "no answer on rescan"]
        if errs:
            add("info", "Partial collection", d.id, s.name(d.id), "; ".join(errs)[:200], "Some tables did not answer; the device view may be incomplete")
        # a managed device with nothing to place it on the map: no neighbours, no MAC table,
        # no routes. Almost always a restricted SNMP view/community or LLDP/CDP turned off —
        # the single most common reason a topology comes out as disconnected subnet clusters.
        if d.role in ("switch", "l3switch", "wireless", "router", "firewall"):
            has_l2 = bool(d.neighbors) or bool(d.fdb)
            has_l3 = any(r.nexthop not in ("", "0.0.0.0") and r.type != 3 for r in d.routes)
            if not has_l2 and not has_l3:
                add("attention", "Limited SNMP visibility", d.id, s.name(d.id),
                    "managed, but reported no LLDP/CDP neighbours, no MAC table and no routes",
                    "Its topology MIBs (LLDP, CDP, bridge/FDB, routing) returned nothing — usually an SNMP "
                    "view or community that excludes them, or LLDP/CDP switched off. The map can't place it "
                    "until at least one of those is readable.")
    for r in link_rows(s):
        if r.get("_mismatch"):
            add("attention", "Link speed mismatch", r["_id"], f"{r['a']} {r['a_port']} - {r['b']} {r['b_port']}", r["speed"],
                "The two ends of one cable report different speeds: a negotiation problem or a mis-documented link")
    for vid, (names, devs) in s.vlans.items():
        if len(names) > 1:
            add("check", "VLAN named differently", f"vlan:{vid}", f"VLAN {vid}", " / ".join(sorted(names)), "Switches disagree on what this VLAN is for; worth confirming it is the same segment everywhere")
    # interface health: error rates, half-duplex on a link, near-saturation, PoE budget
    for d in inv.devices.values():
        for i in d.interfaces:
            if i.err_rate and i.err_rate >= 1:
                add("attention", "Interface errors", d.id, f"{s.name(d.id)} {i.name}", f"{i.err_rate}/s ({i.in_errors + i.out_errors} total)",
                    "A port taking errors at this rate drops or corrupts traffic: bad cable/optic, duplex mismatch, or a failing peer")
            elif (i.in_errors + i.out_errors) > 1000 and i.oper_up:
                add("check", "Interface errors", d.id, f"{s.name(d.id)} {i.name}", f"{i.in_errors + i.out_errors} errors since boot",
                    "Errors have accumulated on this port; rescan to see if they are still climbing")
            if i.duplex == "half" and i.oper_up and (i.speed_mbps or 0) >= 100 and i.mode != "access":
                add("check", "Half duplex", d.id, f"{s.name(d.id)} {i.name}", "operating half-duplex", "A half-duplex link between switches means a duplex mismatch and late collisions")
            if max(i.in_util_pct, i.out_util_pct) >= 90 and i.oper_up:
                add("check", "Interface near saturation", d.id, f"{s.name(d.id)} {i.name}", f"{max(i.in_util_pct, i.out_util_pct)}% of {fmt_speed(i.speed_mbps)}",
                    "This link ran near its capacity between the last two scans")
        if d.poe_budget_w and d.poe_used_w >= 0.9 * d.poe_budget_w:
            add("check", "PoE budget nearly full", d.id, s.name(d.id), f"{d.poe_used_w:.0f} W of {d.poe_budget_w:.0f} W",
                "Little PoE headroom left; another powered device may not come up")
    # first-hop redundancy: a gateway VIP with only one router behind it is a single point of failure
    fhrp: dict = defaultdict(list)
    for d in inv.devices.values():
        for g in getattr(d, "redundancy", []):
            if g.get("vip"):
                fhrp[g["vip"]].append((d.id, g))
    for vip, members in fhrp.items():
        if len(members) == 1:
            did, g = members[0]
            add("check", "Gateway with no standby", did, f"{g['proto'].upper()} {vip}", f"only {s.name(did)} advertises it ({g['state']})",
                "This first-hop gateway has no redundant partner in what was polled: a single point of failure, or its peer was not reached")
    ip_macs: dict[str, set] = defaultdict(set)
    for d in inv.devices.values():
        for a in d.arp:
            ip_macs[a.ip].add(a.mac)
    for ip, macs in ip_macs.items():
        if len(macs) > 1:
            add("check", "Address seen with several MACs", ip, ip, ", ".join(sorted(macs)),
                "Either a first-hop redundancy address (HSRP/VRRP), a recent hardware swap, or an address conflict")
    for cidr, r in s.ipam.items():
        sub = inv.subnets.get(cidr)
        if sub is not None and not sub.gateways and "target" in sub.sources:
            add("check", "Subnet with no gateway found", cidr, cidr, "no polled device has an address in it", "The router for this range was not reached: its SNMP access is missing or it is outside the scope")
        if not r["swept"]:
            add("info", "Subnet not swept", cidr, cidr, f"{r['used']} addresses known from ARP/routes", "Utilisation is a floor, not a count; sweep it to see every live address")
    for ip, h in inv.hosts.items():
        # subnet_for_ip is a cached longest-prefix lookup - O(log subnets) per host
        # instead of scanning every subnet for every host (O(hosts x subnets)). It only
        # knows IPv4 subnets, so an IPv6 host is not "outside" anything.
        if inv.subnet_for_ip(ip) is None and _is_ipv4(ip):
            add("check", "Address outside every known subnet", ip, ip, f"seen via {' '.join(h.sources)}", "In use but in no subnet a device reported: a range missing from the address plan")
    for rec in getattr(inv, "shared_macs", []) or []:
        add("info", "MAC seen on several addresses", rec["ips"][0] if rec["ips"] else rec["mac"], rec["mac"],
            f"{rec['count']} addresses in {', '.join(rec['subnets']) or 'no known subnet'}; MAC left blank on those hosts",
            "One hardware address behind many IPs is a router answering for a remote range, or a scan placeholder, not those hosts' own NIC")
    # coverage gaps: networks the routers know about that we never scanned
    known_addrs = sorted(int(n.network_address) for n in (ipaddress.ip_network(c) for c in inv.subnets) if n.version == 4)
    dev_ips = set(inv.ip_to_device) | {ipc.split("/")[0] for d in inv.devices.values() for i in d.interfaces for ipc in i.ips}
    dev_addrs = sorted(v for v in (_v4_int(ip) for ip in dev_ips) if v is not None)
    seen_gap: set = set()
    for d in inv.devices.values():
        for r in d.routes:
            try:
                net = ipaddress.ip_network(r.dest)
            except ValueError:
                continue
            # /31s are router-to-router links, /32s are host routes: neither is a range to scan
            if net.version != 4 or net.prefixlen == 0 or net.prefixlen >= 31 or net.is_loopback or not net.is_private:
                continue
            if str(net) in inv.subnets or str(net) in seen_gap:
                continue
            lo, hi = int(net.network_address), int(net.broadcast_address)
            if inv.subnet_for_ip(str(net.network_address)) is not None:
                continue  # inside a subnet we know
            if bisect.bisect_right(known_addrs, hi) > bisect.bisect_left(known_addrs, lo):
                continue  # a known subnet sits inside it (a summary route)
            if bisect.bisect_right(dev_addrs, hi) > bisect.bisect_left(dev_addrs, lo):
                continue  # a polled device has an address in it: reached, just not as a subnet
            seen_gap.add(str(net))
            add("check", "Subnet not yet scanned", str(net), str(net), f"routed by {s.name(d.id)} but no device or host was found in it",
                "A network the routing tables know about that this scan never reached: add it to the ranges to get full coverage")
    _topology_findings(s, add)
    # Silence is normal for most addresses (PCs, phones, guessed gateways); it matters for a
    # device you named as a starting point, and for a router other devices route through.
    for ip, via in inv.unreachable.items():
        if via == "seed" and ip not in inv.hosts:
            add("attention", "Starting device did not answer", ip, ip, "given as a device to start from",
                "Wrong address or credentials, SNMP not enabled for this address, or filtered between here and there")
        elif via.startswith("nexthop"):
            add("check", "Next-hop router not polled", ip, ip, f"route next-hop of {via.split(':', 1)[-1]}",
                "Traffic is routed through it but no credential worked: part of the routed path is undocumented")
    rows.sort(key=lambda r: (_SEV_ORDER.get(r["severity"].lower(), 9), r["category"], sort_key("ip", r["item"])))
    return rows


def _topology_findings(s: Snapshot, add) -> None:
    """Cheap structural checks that matter to whoever inherits the network: switches with
    one way out, overlapping address ranges, a spanning-tree root in the wrong place, and
    VLAN settings that disagree across a cable."""
    inv = s.inv
    infra_roles = {"switch", "l3switch", "router", "firewall"}
    # (a) a switch with exactly one link to the rest of the network kit
    link_count: Counter = Counter()
    for u, v, a in s.links:
        if u in inv.devices and (v in inv.devices or s.kind(v) == "device"):
            link_count[u] += 1
        if v in inv.devices and (u in inv.devices or s.kind(u) == "device"):
            link_count[v] += 1
    for d in inv.devices.values():
        if d.role in ("switch", "l3switch") and link_count.get(d.id, 0) == 1 and len(inv.devices) > 1:
            other = next((v if u == d.id else u for u, v, _ in s.links if d.id in (u, v)), "")
            add("info", "Single uplink", d.id, s.name(d.id), f"one link to the network, via {s.name(other)}" if other else "one link to the network",
                "Everything on this switch depends on one cable and one upstream port; fine for an access switch if that is the design, worth knowing either way")
    # (b) overlapping subnets served by different devices
    devs_of: dict[str, set] = defaultdict(set)
    for d in inv.devices.values():
        for i in d.interfaces:
            for ipc in i.ips:
                try:
                    devs_of[str(ipaddress.ip_network(ipc, strict=False))].add(d.id)
                except ValueError:
                    pass
    nets = sorted((ipaddress.ip_network(c) for c in inv.subnets if ipaddress.ip_network(c).version == 4), key=lambda n: (int(n.network_address), n.prefixlen))
    stack: list = []
    for net in nets:
        while stack and not net.subnet_of(stack[-1]):
            stack.pop()
        if stack:
            outer = stack[-1]
            a, b = devs_of.get(str(outer), set()), devs_of.get(str(net), set())
            if a and b and a != b:
                add("attention", "Overlapping subnets", str(net), str(net), f"inside {outer}; {', '.join(sorted(s.name(x) for x in b))} vs {', '.join(sorted(s.name(x) for x in a))}",
                    "Two devices address ranges that contain each other: hosts in the overlap reach one of them by accident, and a migration or an addressing mistake is usually behind it")
        stack.append(net)
    # (c) spanning tree: the root should be the core, and every switch should agree on it
    roots: dict[str, list[str]] = defaultdict(list)
    has_core = any(d.role in ("l3switch", "router") for d in inv.devices.values())
    for d in inv.devices.values():
        stp = getattr(d, "stp", {}) or {}
        if stp.get("root"):
            roots[str(stp["root"]).lower()].append(d.id)
        if stp.get("is_root") and d.role == "switch" and has_core:
            add("check", "Spanning-tree root is an access switch", d.id, s.name(d.id), f"priority {stp.get('priority', '?')}",
                "The root bridge decides which links block; an access switch as root sends core traffic the long way round and fails the tree when it is unplugged")
    if len(roots) > 1:
        detail = "; ".join(f"{r}: {', '.join(sorted(s.name(x) for x in ids))}" for r, ids in sorted(roots.items(), key=lambda kv: -len(kv[1])))
        first = roots[max(roots, key=lambda r: len(roots[r]))][0]
        add("check", "Switches disagree on the spanning-tree root", first, "spanning tree", detail[:300],
            "Polled switches report different root bridges for the default instance: separate layer-2 domains, or a link that does not carry BPDUs")
    # (d) the two ends of a cable disagree on the VLAN
    for u, v, a in s.links:
        if a.get("kind") not in ("lldp", "cdp") or u not in inv.devices or v not in inv.devices:
            continue
        pu, pv = edge_ports(u, v, a)
        ia = _iface_by_label(inv.devices[u], pu)
        ib = _iface_by_label(inv.devices[v], pv)
        if ia is None or ib is None or ia.vlan is None or ib.vlan is None or ia.vlan == ib.vlan:
            continue
        what = "native VLAN" if ia.mode == "trunk" or ib.mode == "trunk" else "VLAN"
        add("check", "VLAN mismatch on link", u, f"{s.name(u)} {pu} - {s.name(v)} {pv}", f"{what} {ia.vlan} vs {ib.vlan}",
            "The two ends of one cable put untagged frames in different VLANs: traffic leaks between segments, or the link was meant to be a trunk on both sides")


# ---------------------------------------------------------------- history
HISTORY_COLUMNS = [
    Column("started", "Started", "time", 130),
    Column("seconds", "Duration", "duration", 80),
    Column("what", "What was scanned", width=280),
    Column("devices", "Devices", "int", 70),
    Column("new_devices", "New devices", "int", 85),
    Column("refreshed", "Re-polled", "int", 75),
    Column("new_hosts", "New hosts", "int", 75),
    Column("result", "Result", width=90),
]


def history_rows(s: Snapshot) -> list[dict]:
    rows = []
    for i, h in enumerate(s.inv.history):
        req = h.get("request", {})
        what = []
        if req.get("targets"):
            what.append("targets " + ", ".join(req["targets"][:4]) + (" …" if len(req["targets"]) > 4 else ""))
        if req.get("seeds"):
            what.append("seeds " + ", ".join(req["seeds"][:4]) + (" …" if len(req["seeds"]) > 4 else ""))
        if req.get("refresh"):
            what.append("rescan")
        found = h.get("found", {})
        rows.append(
            {
                "_id": f"history:{i}", "_kind": "history", "_role": "",
                "started": h.get("started"), "seconds": h.get("seconds") or 0, "what": "; ".join(what),
                "devices": found.get("devices", ""), "new_devices": len(found.get("new_devices", [])), "refreshed": found.get("refreshed", 0),
                "new_hosts": found.get("new_hosts", 0), "result": "stopped" if h.get("cancelled") else "complete",
            }
        )
    return rows


COMPLIANCE_COLUMNS = [
    Column("severity", "Level", "severity", 80),
    Column("category", "Standard", width=210),
    Column("item", "Item", width=180),
    Column("found", "Finding", width=240),
    Column("standard", "What the standard expects", width=360),
]


def compliance_rows(s: Snapshot) -> list[dict]:
    from .compliance import compliance_checks

    rows = []
    for c in compliance_checks(s):
        rows.append({"_id": c.node, "_kind": s.kind(c.node) or "device", "_role": s.role(c.node),
                     "severity": c.severity.capitalize(), "category": c.category, "item": c.item, "found": c.found, "standard": c.standard})
    return rows


DEPENDENCY_COLUMNS = [
    Column("client", "Client", width=180),
    Column("server", "Server", width=180),
    Column("service", "Service", width=100),
    Column("port", "Port", "int", 60),
    Column("proto", "Proto", width=55),
    Column("count", "Connections", "int", 90),
    Column("processes", "Process", width=160),
]


def dependency_rows_view(s: Snapshot) -> list[dict]:
    from .deps import dependency_rows

    return dependency_rows(s.inv, s)


PAGES: dict[str, tuple[list[Column], Callable[[Snapshot], list[dict]]]] = {
    "devices": (DEVICE_COLUMNS, device_rows),
    "hosts": (HOST_COLUMNS, host_rows),
    "subnets": (SUBNET_COLUMNS, subnet_rows),
    "vlans": (VLAN_COLUMNS, vlan_rows_view),
    "links": (LINK_COLUMNS, link_rows),
    "interfaces": (IFACE_COLUMNS, interface_rows),
    "hardware": (HARDWARE_COLUMNS, hardware_rows),
    "findings": (FINDING_COLUMNS, finding_rows),
    "compliance": (COMPLIANCE_COLUMNS, compliance_rows),
    "dependencies": (DEPENDENCY_COLUMNS, dependency_rows_view),
    "history": (HISTORY_COLUMNS, history_rows),
}
