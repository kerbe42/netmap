"""Application dependency mapping from the connections deep-inspection collected.

Each inspected host reports its active connections; aggregated across the estate this becomes
a 'what talks to what' map - which clients depend on which server ports - the way an
application-dependency map (ADM) is built. Nothing here does I/O; it works off the
connection lists already on the hosts.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from .util import is_usable_ip

# server port -> service label, for naming a dependency
SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 69: "tftp",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpc", 123: "ntp", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2379: "etcd", 3268: "gc-ldap", 3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres",
    5985: "winrm", 5986: "winrm-tls", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9100: "print",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb", 5672: "amqp", 1883: "mqtt",
}


def service_name(port: int) -> str:
    return SERVICE.get(port, str(port))


def _is_server_side(lport: int, rport: int) -> bool:
    """True if the local end is the server (so the remote is the client). The server usually
    holds the lower / well-known port."""
    lknown, rknown = lport in SERVICE, rport in SERVICE
    if lknown != rknown:
        return lknown
    return lport < rport


@dataclass
class Dependency:
    client: str  # ip
    server: str  # ip
    port: int
    proto: str = "tcp"
    service: str = ""
    count: int = 0
    processes: set = field(default_factory=set)


def build_dependencies(inv) -> list[Dependency]:
    """Aggregate every inspected host's connections into client -> server:port dependencies."""
    agg: dict[tuple, Dependency] = {}
    for ip, h in inv.hosts.items():
        for c in getattr(h, "connections", []) or []:
            dep = _edge_from_conn(ip, c)
            if dep is None:
                continue
            key = (dep.client, dep.server, dep.port, dep.proto)
            cur = agg.get(key)
            if cur is None:
                agg[key] = dep
                cur = dep
            cur.count += 1
            if c.get("process"):
                cur.processes.add(c["process"])
    # also fold in connections reported on devices, if any inspection stored them there
    return sorted(agg.values(), key=lambda d: (-d.count, d.client, d.server, d.port))


def _edge_from_conn(local_ip: str, c: dict):
    raddr = c.get("raddr")
    if not raddr or not is_usable_ip(raddr):
        return None
    try:
        r = ipaddress.ip_address(raddr)
    except ValueError:
        return None
    if r.is_loopback or r.is_multicast or raddr == local_ip:
        return None
    lport, rport = int(c.get("lport") or 0), int(c.get("rport") or 0)
    proto = (c.get("proto") or "tcp").lower()
    if _is_server_side(lport, rport):
        server, sport, client = local_ip, lport, raddr
    else:
        server, sport, client = raddr, rport, local_ip
    if not sport:
        return None
    d = Dependency(client=client, server=server, port=sport, proto=proto, service=service_name(sport))
    if c.get("process"):
        d.processes = {c["process"]}
    return d


def dependency_rows(inv, snapshot=None) -> list[dict]:
    name = (snapshot.name if snapshot else (lambda x: x))
    rows = []
    for d in build_dependencies(inv):
        rows.append({
            "_id": d.client, "_other": d.server, "_role": "", "_kind": "dependency",
            "client": name(d.client), "server": name(d.server), "service": d.service, "port": d.port,
            "proto": d.proto, "count": d.count, "processes": ", ".join(sorted(d.processes))[:60],
        })
    return rows


def dependencies_of(inv, node_id: str, snapshot=None) -> dict:
    """What one node depends on (as client) and what depends on it (as server)."""
    name = (snapshot.name if snapshot else (lambda x: x))
    deps = build_dependencies(inv)
    ids = {node_id}
    d = inv.devices.get(node_id)
    if d:
        ids |= set(d.ips)
    uses = [{"server": name(x.server), "_id": x.server, "service": x.service, "port": x.port, "count": x.count} for x in deps if x.client in ids]
    used_by = [{"client": name(x.client), "_id": x.client, "service": x.service, "port": x.port, "count": x.count} for x in deps if x.server in ids]
    return {"uses": uses, "used_by": used_by}


def service_graph(inv):
    """Nodes and edges for a dependency overlay on the map: node per host that talks, edge per
    client->server pair, labelled with the top service."""
    deps = build_dependencies(inv)
    nodes: set = set()
    edges = []
    best: dict[tuple, Dependency] = {}
    for d in deps:
        nodes.add(d.client)
        nodes.add(d.server)
        key = (d.client, d.server)
        if key not in best or d.count > best[key].count:
            best[key] = d
    for (c, s), d in best.items():
        edges.append({"source": c, "target": s, "label": d.service, "count": d.count})
    return nodes, edges
