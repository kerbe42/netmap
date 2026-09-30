"""Work out the path through the network to a device or host - both the routed (L3) path
and the switched (L2) path - so you can see how traffic actually reaches something.

Two complementary methods:

* `route_path` follows the collected routing tables hop by hop from a starting router
  toward a destination IP (a traceroute reconstructed from SNMP, so it works even where
  ICMP is filtered).
* `topo_path` is the shortest path across the discovered topology graph (LLDP/CDP cabling
  and routing adjacencies), which also covers the switched core between routers.

`path_to` ties them together: from an origin (a core device, or one you pick) across the
graph to the device a host hangs off, then the final switch-port hop down to the host.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

from .graph import edge_ports, norm_port


@dataclass
class Hop:
    node: str  # device id / host id / subnet cidr
    name: str = ""
    role: str = ""
    kind: str = ""  # how we got here: lldp | cdp | l3 | route | access | gateway | start
    out_port: str = ""  # egress port on the previous hop
    in_port: str = ""  # ingress port on this hop
    detail: str = ""


@dataclass
class Path:
    ok: bool
    target: str
    origin: str
    hops: list[Hop] = field(default_factory=list)
    note: str = ""

    def nodes(self) -> list[str]:
        return [h.node for h in self.hops]


def _name(inv, nid: str) -> str:
    d = inv.devices.get(nid)
    if d:
        return d.name or d.dns_name or nid
    h = inv.hosts.get(nid)
    if h:
        return h.hostname or nid
    return nid


def route_path(inv, src: str, dst_ip: str, max_hops: int = 32) -> list[Hop]:
    """Follow routing tables from device `src` toward `dst_ip`. Each hop is the device that
    owns the current next-hop; stops when the destination is directly connected, unknown, or
    a loop is hit."""
    hops: list[Hop] = []
    try:
        dst = ipaddress.ip_address(dst_ip)
    except ValueError:
        return hops
    cur = src
    seen: set[str] = set()
    for _ in range(max_hops):
        dev = inv.devices.get(cur)
        if dev is None or cur in seen:
            break
        seen.add(cur)
        # directly connected? (dst inside one of this device's interface subnets)
        connected = None
        for i in dev.interfaces:
            for ipc in i.ips:
                try:
                    net = ipaddress.ip_network(ipc, strict=False)
                except ValueError:
                    continue
                if dst in net:
                    connected = i.name or i.descr
                    break
            if connected:
                break
        if connected:
            hops.append(Hop(node=cur, name=_name(inv, cur), role=dev.role, kind="route",
                            detail=f"{dst_ip} is directly connected on {connected}"))
            return hops
        # longest-prefix match among this device's routes
        best = None
        best_len = -1
        for r in dev.routes:
            try:
                net = ipaddress.ip_network(r.dest, strict=False)
            except ValueError:
                continue
            if dst in net and net.prefixlen > best_len and r.nexthop not in ("", "0.0.0.0"):
                best, best_len = r, net.prefixlen
        if best is None:
            hops.append(Hop(node=cur, name=_name(inv, cur), role=dev.role, kind="route",
                            detail=f"no route to {dst_ip}"))
            break
        nxt = inv.ip_to_device.get(best.nexthop)
        egress = dev.iface_label(best.if_index) if best.if_index else ""
        hops.append(Hop(node=cur, name=_name(inv, cur), role=dev.role, kind="route", out_port=egress,
                        detail=f"via {best.nexthop} (route {best.dest})"))
        if nxt is None or nxt == cur:
            hops.append(Hop(node=best.nexthop, name=inv.display_name(best.nexthop) if hasattr(inv, "display_name") else best.nexthop,
                            role="", kind="route", detail="next hop not in the inventory"))
            break
        cur = nxt
    return hops


def _topo_graph(g: nx.MultiGraph) -> nx.Graph:
    """A simple graph of the routed/switched backbone (device-to-device links only)."""
    h = nx.Graph()
    for u, v, a in g.edges(data=True):
        if a.get("kind") in ("lldp", "cdp", "l3") and g.nodes[u].get("kind") == "device" and g.nodes[v].get("kind") == "device":
            if not h.has_edge(u, v):
                pu, pv = edge_ports(u, v, a)
                # record which endpoint pu belongs to, so a traversal in the opposite
                # direction still labels the egress/ingress ports the right way round
                h.add_edge(u, v, kind=a.get("kind"), pu=pu, pv=pv, src=u)
    return h


def topo_path(g: nx.MultiGraph, a: str, b: str) -> Optional[list[Hop]]:
    """Shortest device-to-device path across cabling/routing adjacencies."""
    h = _topo_graph(g)
    if a not in h or b not in h:
        return None
    try:
        nodes = nx.shortest_path(h, a, b)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None
    hops = [Hop(node=nodes[0], name=g.nodes[nodes[0]].get("label", nodes[0]), role=g.nodes[nodes[0]].get("role", ""), kind="start")]
    for prev, node in zip(nodes, nodes[1:]):
        e = h.edges[prev, node]
        # pu belongs to e["src"]; if we're traversing from src, pu is the egress port
        fwd = e.get("src") == prev
        out_port, in_port = (e.get("pu"), e.get("pv")) if fwd else (e.get("pv"), e.get("pu"))
        hops.append(Hop(node=node, name=g.nodes[node].get("label", node), role=g.nodes[node].get("role", ""),
                        kind=e.get("kind", ""), out_port=out_port or "", in_port=in_port or ""))
    return hops


def host_access(inv, g: nx.MultiGraph, host_ip: str) -> Optional[tuple[str, str]]:
    """The switch and port a host hangs off: from an FDB placement if we have one, else the
    gateway of its subnet."""
    h = inv.hosts.get(host_ip)
    if h:
        for s in h.seen_on:
            if s.get("via") == "fdb" and s.get("device") in inv.devices:
                return s["device"], s.get("interface", "")
    cidr = inv.subnet_for_ip(host_ip)
    if cidr and cidr in inv.subnets:
        for gw in inv.subnets[cidr].gateways:
            if gw in inv.devices:
                return gw, ""
    return None


def _pick_origin(inv, g: nx.MultiGraph) -> Optional[str]:
    """A sensible default starting point: the most connected router/L3 device (the core)."""
    cands = [n for n, a in g.nodes(data=True) if a.get("kind") == "device" and a.get("role") in ("router", "l3switch", "firewall")]
    if not cands:
        cands = [n for n, a in g.nodes(data=True) if a.get("kind") == "device"]
    if not cands:
        return None
    return max(cands, key=lambda n: g.degree(n))


def path_to(inv, g: nx.MultiGraph, target: str, origin: Optional[str] = None) -> Path:
    """Full path from `origin` (default: the core) to `target` (a device or a host).

    For a device: the device-to-device path across the backbone. For a host: the path to the
    switch it is on, then the access-port hop down to it. Falls back to the routed path when
    the graph has no cabling between the endpoints.
    """
    origin = origin or _pick_origin(inv, g)
    if origin is None:
        return Path(ok=False, target=target, origin="", note="no devices to trace from")

    # resolve a host target to the device it attaches to, remembering the final hop
    final: Optional[Hop] = None
    attach = target
    if target in inv.hosts and target not in inv.devices:
        acc = host_access(inv, g, target)
        if acc is None:
            return Path(ok=False, target=target, origin=origin, note="the switch this host connects to was not found")
        attach, port = acc
        final = Hop(node=target, name=_name(inv, target), role=inv.hosts[target].role, kind="access", in_port=port,
                    detail=f"learned on {port}" if port else "in this subnet")
    elif target in inv.ip_to_device:
        attach = inv.ip_to_device[target]

    if attach == origin:
        hops = [Hop(node=origin, name=_name(inv, origin), role=g.nodes[origin].get("role", "") if origin in g else "", kind="start")]
    else:
        hops = topo_path(g, origin, attach)
        if hops is None:
            # no cabled/adjacency path known: reconstruct the routed path from tables
            r = route_path(inv, origin, _target_ip(inv, target))
            if not r:
                return Path(ok=False, target=target, origin=origin, note="no path found in the collected topology or routing tables")
            hops = r
    if final is not None:
        hops = list(hops) + [final]
    return Path(ok=True, target=target, origin=origin, hops=hops)


def _target_ip(inv, target: str) -> str:
    if target in inv.devices:
        return target
    if target in inv.hosts:
        return target
    return target
