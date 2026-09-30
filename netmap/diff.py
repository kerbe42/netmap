"""What changed between two scans of the same network.

Devices are matched by management address, and failing that by serial number, so a
switch that was readdressed shows up as *moved* rather than as one removal and one
addition. Hosts are matched by address. Links are compared as unordered pairs of
(device, normalised port).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .graph import build_graph, edge_ports, norm_port
from .model import Inventory

DEVICE_FIELDS = [("name", "Name"), ("model", "Model"), ("serial", "Serial"), ("os_version", "OS version"), ("vendor", "Vendor"),
                 ("role", "Role"), ("location", "Location"), ("contact", "Contact")]


@dataclass
class Change:
    kind: str  # device | host | subnet | link | vlan
    change: str  # added | removed | changed | moved
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
                sign = {"added": "+", "removed": "-", "changed": "~", "moved": ">"}.get(c.change, "?")
                lines.append(f"  {sign} {c.name or c.item:32} {c.detail}")
            lines.append("")
        return "\n".join(lines).rstrip()


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
    old_by_serial = {x.serial: x for x in old.devices.values() if x.serial}
    matched_old = set()
    for did, nd in new.devices.items():
        od = old.devices.get(did)
        if od is None and nd.serial and nd.serial in old_by_serial:
            od = old_by_serial[nd.serial]
            add(Change("device", "moved", did, nd.name or did, f"was {od.id}, now {did} (same serial {nd.serial})"))
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
        if od.uptime_s and nd.uptime_s and nd.uptime_s < od.uptime_s and nd.collected_at > od.collected_at:
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
    for ip in sorted(nh.keys() - oh.keys()):
        h = nh[ip]
        add(Change("host", "added", ip, h.hostname or ip, " ".join(x for x in (h.mac or "", h.vendor) if x)))
    for ip in sorted(oh.keys() - nh.keys()):
        h = oh[ip]
        add(Change("host", "removed", ip, h.hostname or ip, " ".join(x for x in (h.mac or "", h.vendor) if x)))
    for ip in sorted(nh.keys() & oh.keys()):
        a, b = oh[ip].mac, nh[ip].mac
        if a and b and a != b:
            add(Change("host", "changed", ip, nh[ip].hostname or ip, f"MAC {a} → {b} ({nh[ip].vendor or 'unknown vendor'})"))
    return d
