"""What changed between two scans of the same network.

Devices are matched by management address, and failing that by serial number, so a
switch that was readdressed shows up as *moved* rather than as one removal and one
addition. Hosts are matched by address, then by MAC (a host that got a new address is
*readdressed*). Links are compared as unordered pairs of (device, normalised port).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .graph import build_graph, edge_ports, norm_port
from .model import Inventory

DEVICE_FIELDS = [("name", "Name"), ("model", "Model"), ("serial", "Serial"), ("os_version", "OS version"), ("vendor", "Vendor"),
                 ("role", "Role"), ("location", "Location"), ("contact", "Contact")]

# what vendors put in the serial field when there is none
_PLACEHOLDER_SERIALS = {"", "n/a", "na", "none", "null", "0", "00000000", "not specified", "not available", "unknown", "unspecified",
                        "to be filled by o.e.m.", "default string", "system serial number", "-"}
REBOOT_MARGIN_S = 3600  # clock skew between the two collections we tolerate


def _serial_key(serial: str) -> str:
    """A serial that can identify a device, normalised, or "" for a placeholder."""
    s = (serial or "").strip()
    if len(s) < 5 or s.lower() in _PLACEHOLDER_SERIALS or set(s) <= set("0-. "):
        return ""
    return s.upper()


def _serial_index(inv: Inventory) -> dict[str, str]:
    """serial -> device id, for serials that are real and unique within this inventory
    (two devices reporting the same serial is a shared placeholder, or a stack member's)."""
    keys = {did: _serial_key(d.serial) for did, d in inv.devices.items()}
    counts = Counter(k for k in keys.values() if k)
    return {k: did for did, k in keys.items() if k and counts[k] == 1}


@dataclass
class Change:
    kind: str  # device | host | subnet | link | vlan
    change: str  # added | removed | changed | moved | readdressed
    item: str  # node id or description
    name: str = ""
    detail: str = ""


@dataclass
class Diff:
    changes: list[Change] = field(default_factory=list)

    def of(self, kind: str, change: str = "") -> list[Change]:
        return [c for c in self.changes if c.kind == kind and (not change or c.change == change)]

    def summary(self) -> dict:
        out: dict = {}
        for c in self.changes:
            out.setdefault(c.kind, {}).setdefault(c.change, 0)
            out[c.kind][c.change] += 1
        return out

    def text(self) -> str:
        if not self.changes:
            return "No differences."
        lines = []
        for kind in ("device", "link", "subnet", "vlan", "host"):
            items = self.of(kind)
            if not items:
                continue
            lines.append(f"{kind.upper()}S ({len(items)} changes)")
            for c in items:
                sign = {"added": "+", "removed": "-", "changed": "~", "moved": ">", "readdressed": ">"}.get(c.change, "?")
                lines.append(f"  {sign} {c.name or c.item:32} {c.detail}")
            lines.append("")
        return "\n".join(lines).rstrip()


UPTIME_WRAP_S = 2**32 / 100  # sysUpTime is a 32-bit count of centiseconds: 497.1 days


def _rebooted(od, nd) -> bool:
    """Did the device restart between the two collections? The uptime went down, and it is
    shorter than the time between the collections (a device that stayed up has an uptime
    at least that long). A counter that wrapped also went down, but then the new value is
    what the old one plus the elapsed time would read modulo the wrap - not a reboot."""
    if not (od.uptime_s and nd.uptime_s and nd.uptime_s < od.uptime_s):
        return False
    elapsed = nd.collected_at - od.collected_at
    if elapsed <= 0 or nd.uptime_s >= elapsed + REBOOT_MARGIN_S:
        return False
    expected_after_wrap = od.uptime_s + elapsed - UPTIME_WRAP_S
    if abs(nd.uptime_s - expected_after_wrap) <= REBOOT_MARGIN_S:
        return False
    return True


def _ip_key(ip: str):
    import ipaddress

    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def _links(inv: Inventory) -> dict[tuple, str]:
    g = build_graph(inv, include_hosts=False, include_subnets=False)
    out = {}
    for u, v, a in g.edges(data=True):
        if a.get("kind") not in ("lldp", "cdp"):
            continue
        pu, pv = edge_ports(u, v, a)
        nu = g.nodes[u].get("label") or u
        nv = g.nodes[v].get("label") or v
        key = tuple(sorted([(nu.lower(), norm_port(pu)), (nv.lower(), norm_port(pv))]))
        out[key] = f"{nu} {pu} — {nv} {pv}"
    return out


def compare(old: Inventory, new: Inventory) -> Diff:
    d = Diff()
    add = d.changes.append
    old_by_serial = _serial_index(old)
    new_by_serial = _serial_index(new)
    matched_old = set()
    for did, nd in new.devices.items():
        od = old.devices.get(did)
        sk = _serial_key(nd.serial)
        if od is None and sk and sk in old_by_serial and new_by_serial.get(sk) == did and old_by_serial[sk] not in new.devices:
            od = old.devices[old_by_serial[sk]]
            add(Change("device", "moved", did, nd.name or did, f"was {od.id}, now {did} (same serial {nd.serial.strip()})"))
        if od is None:
            add(Change("device", "added", did, nd.name or did, " ".join(x for x in (nd.vendor, nd.model, nd.os_version) if x)))
            continue
        matched_old.add(od.id)
        diffs = []
        for attr, title in DEVICE_FIELDS:
            a, b = getattr(od, attr, ""), getattr(nd, attr, "")
            if (a or b) and a != b:
                diffs.append(f"{title}: {a or '—'} → {b or '—'}")
        oup = {i.name or i.descr for i in od.interfaces if i.oper_up}
        nup = {i.name or i.descr for i in nd.interfaces if i.oper_up}
        if oup != nup:
            went_down, came_up = sorted(oup - nup), sorted(nup - oup)
            bits = []
            if came_up:
                bits.append(f"{len(came_up)} port(s) up" + (f" ({', '.join(came_up[:4])}{'…' if len(came_up) > 4 else ''})" if came_up else ""))
            if went_down:
                bits.append(f"{len(went_down)} port(s) down" + (f" ({', '.join(went_down[:4])}{'…' if len(went_down) > 4 else ''})" if went_down else ""))
            diffs.append("; ".join(bits))
        if _rebooted(od, nd):
            diffs.append("rebooted since the earlier scan")
        if diffs:
            add(Change("device", "changed", did, nd.name or did, "; ".join(diffs)))
    for did, od in old.devices.items():
        if did not in matched_old and did not in new.devices:
            add(Change("device", "removed", did, od.name or did, " ".join(x for x in (od.vendor, od.model) if x)))

    ol, nl = _links(old), _links(new)
    for k in nl.keys() - ol.keys():
        add(Change("link", "added", nl[k], nl[k]))
    for k in ol.keys() - nl.keys():
        add(Change("link", "removed", ol[k], ol[k]))

    for cidr in sorted(new.subnets.keys() - old.subnets.keys()):
        add(Change("subnet", "added", cidr, cidr))
    for cidr in sorted(old.subnets.keys() - new.subnets.keys()):
        add(Change("subnet", "removed", cidr, cidr))

    ov = {vid: name for dv in old.devices.values() for vid, name in dv.vlans.items()}
    nv = {vid: name for dv in new.devices.values() for vid, name in dv.vlans.items()}
    for vid in sorted(nv.keys() - ov.keys()):
        add(Change("vlan", "added", f"vlan:{vid}", f"VLAN {vid}", nv[vid]))
    for vid in sorted(ov.keys() - nv.keys()):
        add(Change("vlan", "removed", f"vlan:{vid}", f"VLAN {vid}", ov[vid]))

    oh = {ip: h for ip, h in old.hosts.items() if ip not in old.ip_to_device}
    nh = {ip: h for ip, h in new.hosts.items() if ip not in new.ip_to_device}
    added_ips = nh.keys() - oh.keys()
    removed_ips = oh.keys() - nh.keys()
    # a host that went away at one address and appeared at another with the same MAC moved
    # address (DHCP, a re-IP), it was not replaced. Only unambiguous MACs pair up.
    def _unique_macs(ips, hosts):
        c = Counter(hosts[ip].mac for ip in ips if hosts[ip].mac)
        return {hosts[ip].mac: ip for ip in ips if hosts[ip].mac and c[hosts[ip].mac] == 1}

    old_mac = _unique_macs(removed_ips, oh)
    new_mac = _unique_macs(added_ips, nh)
    readdressed = {}  # new ip -> old ip
    for mac, old_ip in old_mac.items():
        new_ip = new_mac.get(mac)
        if new_ip:
            readdressed[new_ip] = old_ip
    for ip in sorted(readdressed, key=_ip_key):
        h = nh[ip]
        add(Change("host", "readdressed", ip, h.hostname or oh[readdressed[ip]].hostname or ip, f"was {readdressed[ip]}, now {ip} (same MAC {h.mac})"))
    for ip in sorted(added_ips - readdressed.keys(), key=_ip_key):
        h = nh[ip]
        add(Change("host", "added", ip, h.hostname or ip, " ".join(x for x in (h.mac or "", h.vendor) if x)))
    for ip in sorted(removed_ips - set(readdressed.values()), key=_ip_key):
        h = oh[ip]
        add(Change("host", "removed", ip, h.hostname or ip, " ".join(x for x in (h.mac or "", h.vendor) if x)))
    for ip in sorted(nh.keys() & oh.keys()):
        a, b = oh[ip].mac, nh[ip].mac
        if a and b and a != b:
            add(Change("host", "changed", ip, nh[ip].hostname or ip, f"MAC {a} → {b} ({nh[ip].vendor or 'unknown vendor'})"))
    return d
