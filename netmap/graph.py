"""Turn the inventory into a topology graph (nodes + typed edges) and export it."""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from collections import Counter, defaultdict
from typing import Optional

import networkx as nx

from .model import Inventory
from .sweep import classify_host
from .util import oui_vendor, short_name

TRUNK_MAC_THRESHOLD = 8

_PORT_ABBREV = [
    (r"^hundredgigabitethernet", "hu"), (r"^fortygigabitethernet", "fo"), (r"^twentyfivegige", "twe"), (r"^tengigabitethernet", "te"),
    (r"^twogigabitethernet", "tw"), (r"^gigabitethernet", "gi"), (r"^fastethernet", "fa"), (r"^ethernet", "et"), (r"^port-channel", "po"),
    (r"^bundle-ether", "be"), (r"^xe-", "xe-"), (r"^ge-", "ge-"), (r"^et-", "et-"), (r"^mgmt", "mgmt"),
]


def norm_port(name: str) -> str:
    """'GigabitEthernet1/0/2' == 'Gi1/0/2' == 'gi 1/0/2' for link de-duplication."""
    n = (name or "").strip().lower().replace(" ", "")
    for pat, short in _PORT_ABBREV:
        if re.match(pat, n):
            return re.sub(pat, short, n, count=1)
    return n  # a port with more MACs than this is treated as an uplink/trunk, not a host port


def enrich_inventory(inv: Inventory) -> None:
    """Fill in what can be derived offline, so a crawl without nmap still types its kit.

    Every MAC we learned - from ARP, from a bridge table, from a sweep - carries the
    organization that owns its OUI, which is often the only clue a host gives us.
    """
    for h in inv.hosts.values():
        if not h.vendor and h.mac:
            h.vendor = oui_vendor(h.mac)
        if h.role in ("host", "", None):
            h.role = classify_host(h.ports, h.vendor, h.hostname)
    for d in inv.devices.values():
        if not d.vendor:
            for mac in [d.lldp_chassis_id, *d.macs]:
                v = oui_vendor(mac)
                if v:
                    d.vendor = v
                    break


def ipam_rows(inv: Inventory) -> list[dict]:
    """Per-subnet address accounting, the IPAM view of a crawl.

    `used` counts addresses we actually saw in use (device interfaces, ARP/sweep hosts,
    route gateways), so utilisation is evidence-based and reads low for a subnet that was
    never swept. `swept` says whether to trust it.
    """
    rows = []
    for cidr, s in inv.subnets.items():
        net = ipaddress.ip_network(cidr)
        usable = max(net.num_addresses - 2, 1) if net.prefixlen < 31 else net.num_addresses
        seen: set[str] = set()
        for ip in inv.ip_to_device:
            try:
                if ipaddress.ip_address(ip) in net:
                    seen.add(ip)
            except ValueError:
                continue
        for ip in inv.hosts:
            try:
                if ipaddress.ip_address(ip) in net:
                    seen.add(ip)
            except ValueError:
                continue
        vlans = set()
        for d in inv.devices.values():
            for i in d.interfaces:
                if any(ipaddress.ip_network(x, strict=False) == net for x in i.ips):
                    m = re.search(r"vlan\s*0*(\d+)", f"{i.name} {i.descr}", re.I)
                    if m:
                        vlans.add(int(m.group(1)))
        if s.vlan:
            vlans.add(s.vlan)
        rows.append(
            {
                "cidr": cidr,
                "size": net.num_addresses,
                "usable": usable,
                "used": len(seen),
                "free": max(usable - len(seen), 0),
                "utilisation_pct": round(100.0 * len(seen) / usable, 1),
                "gateways": " ".join(inv.devices[g].name or g for g in s.gateways if g in inv.devices),
                "vlan": " ".join(str(v) for v in sorted(vlans)),
                "sources": " ".join(s.sources),
                "swept": s.swept,
            }
        )
    return sorted(rows, key=lambda r: ipaddress.ip_network(r["cidr"]))


def vlan_rows(inv: Inventory) -> dict:
    """VLAN id -> (names seen for it, devices that carry it). Names differ between switches
    more often than anyone expects, so keep every spelling rather than picking one."""
    out: dict[int, tuple[set, set]] = defaultdict(lambda: (set(), set()))
    for d in inv.devices.values():
        for vid, name in d.vlans.items():
            names, devs = out[vid]
            if name:
                names.add(name)
            devs.add(d.name or d.id)
    return out


def build_graph(inv: Inventory, include_hosts: bool = True, include_subnets: bool = True, fdb_links: bool = True) -> nx.MultiGraph:
    enrich_inventory(inv)
    g = nx.MultiGraph()
    # --- device nodes ---
    for d in inv.devices.values():
        g.add_node(
            d.id,
            kind="device",
            label=d.name or d.id,
            ip=d.id,
            ips=list(d.ips),
            role=d.role,
            vendor=d.vendor,
            model=d.model,
            serial=d.serial,
            sysdescr=d.sysdescr[:200],
            location=d.location,
            depth=d.depth,
            via=d.discovered_via,
            interfaces=len(d.interfaces),
            vlans=len(d.vlans),
            errors=len(d.errors),
        )

    # --- L2 adjacency (LLDP/CDP) ---
    mac_ip = inv.mac_to_ip()

    def resolve_neighbor(nb) -> Optional[str]:
        for ip in nb.remote_mgmt_ips:
            if ip in inv.ip_to_device:
                return inv.ip_to_device[ip]
        if nb.remote_chassis_id and nb.remote_chassis_id in inv.mac_to_device:
            return inv.mac_to_device[nb.remote_chassis_id]
        d = inv.device_for_name(nb.remote_name)
        if d:
            return d.id
        # not an SNMP device we polled: maybe a host we know from ARP/sweep (AP, phone, server)
        for ip in nb.remote_mgmt_ips:
            if ip in inv.hosts:
                return ip
        hip = mac_ip.get(nb.remote_chassis_id) if nb.remote_chassis_id else None
        if hip and hip in inv.hosts:
            return hip
        return None

    if include_hosts:
        _add_host_nodes(g, inv)
    seen_l2: set = set()
    for d in inv.devices.values():
        for nb in d.neighbors:
            tgt = resolve_neighbor(nb)
            if tgt is not None and tgt not in g:
                tgt = None
            if tgt is None:
                # stub for something we saw but could not poll
                sid = "stub:" + (short_name(nb.remote_name) or nb.remote_chassis_id or (nb.remote_mgmt_ips[0] if nb.remote_mgmt_ips else "?"))
                if sid not in g:
                    g.add_node(
                        sid,
                        kind="device",
                        label=nb.remote_name or nb.remote_chassis_id or sid,
                        ip=nb.remote_mgmt_ips[0] if nb.remote_mgmt_ips else "",
                        ips=list(nb.remote_mgmt_ips),
                        role="unpolled",
                        vendor="",
                        model=nb.remote_platform,
                        chassis_id=nb.remote_chassis_id,
                        caps=nb.remote_caps,
                    )
                tgt = sid
            if tgt == d.id:
                continue
            if g.nodes[tgt].get("kind") == "host":
                _upgrade_host(g.nodes[tgt], nb)
            key = tuple(sorted([(d.id, norm_port(nb.local_port)), (tgt, norm_port(nb.remote_port))]))
            if key in seen_l2:
                continue
            seen_l2.add(key)
            g.add_edge(d.id, tgt, kind=nb.proto, src_port=nb.local_port, dst_port=nb.remote_port, label=f"{nb.local_port} - {nb.remote_port}")

    # --- L3 adjacency (routes) ---
    seen_l3: set = set()
    for d in inv.devices.values():
        nh_count: Counter = Counter()
        for r in d.routes:
            if r.nexthop in ("0.0.0.0", "") or r.nexthop in d.ips:
                continue
            tgt = inv.ip_to_device.get(r.nexthop)
            if tgt and tgt != d.id:
                nh_count[tgt] += 1
        for tgt, n in nh_count.items():
            key = tuple(sorted([d.id, tgt]))
            if key in seen_l3 or g.has_edge(d.id, tgt):
                # don't clutter a LLDP-linked pair with a parallel l3 edge, but keep the count
                seen_l3.add(key)
                continue
            seen_l3.add(key)
            g.add_edge(d.id, tgt, kind="l3", label=f"{n} routes", routes=n)

    # --- subnets ---
    if include_subnets:
        for cidr, s in inv.subnets.items():
            g.add_node(cidr, kind="subnet", label=cidr, cidr=cidr, sources=list(s.sources), swept=s.swept, vlan=s.vlan)
        for d in inv.devices.values():
            for i in d.interfaces:
                for ipc in i.ips:
                    try:
                        net = ipaddress.ip_network(ipc, strict=False)
                    except ValueError:
                        continue
                    cidr = str(net)
                    if cidr in g and net.prefixlen < 31:
                        g.add_edge(d.id, cidr, kind="member", label=f"{i.name or i.descr} {ipc}", port=i.name or i.descr, addr=ipc)
                        if d.id not in inv.subnets[cidr].gateways:
                            inv.subnets[cidr].gateways.append(d.id)

    # --- hosts ---
    if include_hosts:
        uplink_ports: dict[str, set] = defaultdict(set)
        for d in inv.devices.values():
            for nb in d.neighbors:
                if nb.local_if_index is not None:
                    uplink_ports[d.id].add(nb.local_if_index)
        for ip, h in inv.hosts.items():
            if ip in inv.ip_to_device:
                continue
            if include_subnets:
                cidr = inv.subnet_for_ip(ip)
                if cidr and cidr in g:
                    g.add_edge(ip, cidr, kind="member", label="")
        if fdb_links:
            for d in inv.devices.values():
                per_port: dict = defaultdict(set)
                for f in d.fdb:
                    if f.if_index is not None:
                        per_port[f.if_index].add(f.mac)
                for ifidx, macs in per_port.items():
                    if ifidx in uplink_ports[d.id] or len(macs) > TRUNK_MAC_THRESHOLD:
                        continue
                    for mac in macs:
                        hip = mac_ip.get(mac)
                        if not hip or hip not in g or hip in inv.ip_to_device:
                            continue
                        if g.has_edge(d.id, hip):
                            continue
                        vlan = next((f.vlan for f in d.fdb if f.mac == mac and f.if_index == ifidx), None)
                        g.add_edge(d.id, hip, kind="fdb", label=d.iface_label(ifidx), port=d.iface_label(ifidx), vlan=vlan)
                        inv.hosts[hip].seen_on.append({"device": d.id, "interface": d.iface_label(ifidx), "vlan": vlan, "via": "fdb"})
    return g


def _add_host_nodes(g: nx.MultiGraph, inv: Inventory) -> None:
    for ip, h in inv.hosts.items():
        if ip in inv.ip_to_device or ip in g:
            continue
        g.add_node(
            ip,
            kind="host",
            label=h.hostname or ip,
            ip=ip,
            mac=h.mac or "",
            vendor=h.vendor,
            hostname=h.hostname,
            role=h.role,
            sources=list(h.sources),
            ports=[f"{p['port']}/{p['proto']} {p['service']} {p['product']}".strip() for p in h.ports],
            snmp_failed=h.snmp_failed,
        )


def _upgrade_host(attrs: dict, nb) -> None:
    """A host that announces itself over LLDP/CDP tells us what it is."""
    caps = (nb.remote_caps or "").lower()
    plat = (nb.remote_platform or "").lower()
    if attrs.get("role") in ("host", "workstation", "unknown"):
        if "wlan-ap" in caps or re.search(r"\bap\b|access point|aironet|air-", plat):
            attrs["role"] = "wireless"
        elif "telephone" in caps or "phone" in caps or "phone" in plat:
            attrs["role"] = "phone"
        elif "router" in caps:
            attrs["role"] = "router"
        elif "bridge" in caps or "switch" in caps:
            attrs["role"] = "switch"
    if nb.remote_name and attrs.get("label") == attrs.get("ip"):
        attrs["label"] = nb.remote_name
        attrs["hostname"] = nb.remote_name
    if nb.remote_platform and not attrs.get("vendor"):
        attrs["vendor"] = nb.remote_platform[:60]


def graph_to_dict(g: nx.MultiGraph) -> dict:
    nodes = [{"id": n, **{k: v for k, v in a.items()}} for n, a in g.nodes(data=True)]
    edges = [{"source": u, "target": v, **{k: w for k, w in a.items()}} for u, v, a in g.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


def _flatten(attrs: dict) -> dict:
    out = {}
    for k, v in attrs.items():
        if v is None:
            continue
        if isinstance(v, (list, dict, set)):
            out[k] = json.dumps(list(v) if isinstance(v, set) else v)
        else:
            out[k] = v
    return out


def export_graphml(g: nx.MultiGraph, path: str) -> None:
    h = nx.MultiGraph()
    for n, a in g.nodes(data=True):
        h.add_node(n, **_flatten(a))
    for u, v, a in g.edges(data=True):
        h.add_edge(u, v, **_flatten(a))
    nx.write_graphml(h, path)


def export_dot(g: nx.MultiGraph, path: str) -> None:
    shapes = {"device": "box", "host": "ellipse", "subnet": "hexagon"}
    styles = {"lldp": "solid", "cdp": "solid", "l3": "dashed", "member": "dotted", "fdb": "dotted"}
    lines = ["graph netmap {", "  overlap=false; splines=true; node [fontname=Helvetica, fontsize=9];"]
    for n, a in g.nodes(data=True):
        lbl = a.get("label", n).replace('"', "'")
        if a.get("kind") == "device":
            lbl += f"\\n{a.get('ip','')}\\n{a.get('role','')}"
        lines.append(f'  "{n}" [label="{lbl}", shape={shapes.get(a.get("kind"), "ellipse")}];')
    for u, v, a in g.edges(data=True):
        lbl = str(a.get("label", "")).replace('"', "'")
        lines.append(f'  "{u}" -- "{v}" [label="{lbl}", style={styles.get(a.get("kind"), "solid")}];')
    lines.append("}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def export_csv(inv: Inventory, g: nx.MultiGraph, prefix: str) -> list[str]:
    files = []
    p = f"{prefix}devices.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "name", "role", "vendor", "model", "serial", "location", "contact", "all_ips", "interfaces", "vlans", "lldp_neighbors", "cdp_neighbors", "arp_entries", "routes", "fdb_entries", "uptime_days", "sysdescr", "discovered_via", "depth", "credential", "errors"])
        for d in inv.devices.values():
            w.writerow([d.id, d.name, d.role, d.vendor, d.model, d.serial, d.location, d.contact, " ".join(d.ips), len(d.interfaces), len(d.vlans), sum(n.proto == "lldp" for n in d.neighbors), sum(n.proto == "cdp" for n in d.neighbors), len(d.arp), len(d.routes), len(d.fdb), d.uptime_s // 86400, d.sysdescr[:200], d.discovered_via, d.depth, d.credential, "; ".join(d.errors)[:300]])
    files.append(p)
    p = f"{prefix}links.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["a", "a_name", "a_port", "b", "b_name", "b_port", "kind", "detail"])
        for u, v, a in g.edges(data=True):
            if a.get("kind") in ("lldp", "cdp", "l3"):
                w.writerow([u, g.nodes[u].get("label"), a.get("src_port", ""), v, g.nodes[v].get("label"), a.get("dst_port", ""), a["kind"], a.get("label", "")])
    files.append(p)
    p = f"{prefix}hosts.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "hostname", "mac", "vendor", "role", "subnet", "sources", "switch", "port", "vlan", "open_ports"])
        for ip, h in sorted(inv.hosts.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
            if ip in inv.ip_to_device:
                continue
            fdb = next((s for s in h.seen_on if s["via"] == "fdb"), None)
            sw = inv.devices.get(fdb["device"]).name if fdb and fdb["device"] in inv.devices else (fdb["device"] if fdb else "")
            w.writerow([ip, h.hostname, h.mac or "", h.vendor, h.role, inv.subnet_for_ip(ip) or "", " ".join(h.sources), sw, fdb["interface"] if fdb else "", fdb["vlan"] if fdb else "", " ".join(f"{x['port']}/{x['service']}" for x in h.ports)])
    files.append(p)
    p = f"{prefix}subnets.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cidr", "size", "gateways", "hosts_seen", "sources", "swept"])
        for cidr, s in sorted(inv.subnets.items(), key=lambda kv: ipaddress.ip_network(kv[0])):
            n = ipaddress.ip_network(cidr)
            hosts = sum(1 for ip in inv.hosts if ip not in inv.ip_to_device and ipaddress.ip_address(ip) in n)
            w.writerow([cidr, n.num_addresses, " ".join(inv.devices[gid].name or gid for gid in s.gateways if gid in inv.devices), hosts, " ".join(s.sources), s.swept])
    files.append(p)
    p = f"{prefix}ipam.csv"
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cidr", "size", "usable", "used", "free", "utilisation_pct", "vlan", "gateways", "sources", "swept"])
        w.writeheader()
        w.writerows(ipam_rows(inv))
    files.append(p)
    p = f"{prefix}vlans.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["vlan", "name", "devices", "device_names"])
        for vid, (names, devs) in sorted(vlan_rows(inv).items()):
            w.writerow([vid, " / ".join(sorted(names)), len(devs), " ".join(sorted(devs))])
    files.append(p)
    p = f"{prefix}interfaces.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["device", "device_name", "ifindex", "name", "descr", "alias", "mac", "speed_mbps", "admin", "oper", "ips"])
        for d in inv.devices.values():
            for i in d.interfaces:
                w.writerow([d.id, d.name, i.index, i.name, i.descr, i.alias, i.mac or "", i.speed_mbps, "up" if i.admin_up else "down", "up" if i.oper_up else "down", " ".join(i.ips)])
    files.append(p)
    return files


def text_summary(inv: Inventory, g: nx.MultiGraph) -> str:
    lines = [f"== {inv.summary()} ==", ""]
    roles = Counter(d.role for d in inv.devices.values())
    vendors = Counter(d.vendor or "?" for d in inv.devices.values())
    lines.append("Devices by role:   " + ", ".join(f"{r}={n}" for r, n in roles.most_common()))
    lines.append("Devices by vendor: " + ", ".join(f"{v}={n}" for v, n in vendors.most_common()))
    kinds = Counter(a["kind"] for _, _, a in g.edges(data=True))
    lines.append("Edges:             " + ", ".join(f"{k}={n}" for k, n in kinds.most_common()))
    lines.append("")
    lines.append(f"{'IP':16} {'NAME':28} {'ROLE':10} {'VENDOR':14} {'MODEL':22} {'DEPTH':5} VIA")
    for d in sorted(inv.devices.values(), key=lambda x: (x.depth, ipaddress.ip_address(x.id))):
        lines.append(f"{d.id:16} {d.name[:28]:28} {d.role:10} {d.vendor[:14]:14} {d.model[:22]:22} {d.depth:<5} {d.discovered_via}")
    stubs = [(n, a) for n, a in g.nodes(data=True) if a.get("role") == "unpolled"]
    if stubs:
        lines += ["", f"Seen via LLDP/CDP but not polled ({len(stubs)}):"]
        for n, a in stubs:
            lines.append(f"  {a.get('label')}  ip={a.get('ip') or '-'}  chassis={a.get('chassis_id','') or '-'}  {a.get('model','')[:60]}")
    lines += ["", "Links (L2/L3):"]
    for u, v, a in g.edges(data=True):
        if a["kind"] in ("lldp", "cdp", "l3"):
            lines.append(f"  {g.nodes[u]['label']:28} {a.get('src_port',''):22} <-{a['kind']:4}-> {g.nodes[v]['label']:28} {a.get('dst_port','') or a.get('label','')}")
    vl = vlan_rows(inv)
    if vl:
        lines += ["", f"VLANs ({len(vl)}):"]
        for vid, (names, devs) in sorted(vl.items()):
            lines.append(f"  {vid:<6} {' / '.join(sorted(names))[:36]:36} on {len(devs)} device(s)")
    lines += ["", f"{'SUBNET':20} {'USED':>6} {'FREE':>7} {'UTIL':>6} {'VLAN':6} GATEWAY"]
    for r in ipam_rows(inv):
        lines.append(
            f"  {r['cidr']:18} {r['used']:>6} {r['free']:>7} {str(r['utilisation_pct']) + '%':>6} {r['vlan'][:6]:6} "
            f"{r['gateways'][:40] or '-'}{'' if r['swept'] else '  (not swept)'}"
        )
    return "\n".join(lines)
