"""Data model: what we learned about each device/host/subnet, plus JSON persistence.

The same JSON file is the CLI's inventory and the desktop app's project. Besides what a
scan collects it carries what people add while working through an inherited network -
notes, sites, tags, names, hand-placed map positions and the history of scans - so a
rescan never loses the documentation built on top of it.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

FORMAT_VERSION = 2


def _build(cls, d: dict):
    """Instantiate a dataclass from a dict, ignoring keys it does not know.

    Files move between versions in both directions: an older build opening a newer
    project, or a newer build reading a v0.1 inventory. Unknown keys are dropped
    rather than fatal, and missing ones take their defaults.
    """
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in d.items() if k in names})


@dataclass
class Interface:
    index: int
    name: str = ""
    descr: str = ""
    alias: str = ""
    mac: Optional[str] = None
    type: int = 0
    speed_mbps: int = 0
    admin_up: bool = False
    oper_up: bool = False
    ips: list[str] = field(default_factory=list)  # "a.b.c.d/nn"
    vlan: Optional[int] = None  # access VLAN / native VLAN (PVID)
    mode: str = ""  # access | trunk | "" (unknown / routed)
    lag: str = ""  # name of the port-channel / aggregate this port belongs to
    last_change_s: int = 0  # sysUpTime at the last oper-status change, in seconds
    duplex: str = ""  # full | half | ""
    in_octets: int = 0
    out_octets: int = 0
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    counters_at: float = 0.0  # when the counters above were read
    in_util_pct: float = 0.0  # utilisation over the last interval (needs two scans)
    out_util_pct: float = 0.0
    err_rate: float = 0.0  # errors per second over the last interval
    poe_class: str = ""  # PoE class (e.g. "3", "4")
    poe_watts: float = 0.0  # power drawn, watts
    poe_status: str = ""  # delivering | searching | fault | disabled | ""


@dataclass
class Component:
    """One ENTITY-MIB physical entity worth putting in an asset register:
    chassis, stack members, line cards, supplies, fans, transceivers."""

    index: int
    cls: str = ""  # chassis | module | powerSupply | fan | stack | port | other
    name: str = ""
    descr: str = ""
    model: str = ""
    serial: str = ""
    hw_rev: str = ""
    fw_rev: str = ""
    sw_rev: str = ""
    fru: bool = False
    parent: int = 0


@dataclass
class Neighbor:
    proto: str  # lldp | cdp
    local_if_index: Optional[int] = None
    local_port: str = ""
    remote_name: str = ""
    remote_port: str = ""
    remote_chassis_id: str = ""  # MAC or other id
    remote_mgmt_ips: list[str] = field(default_factory=list)
    remote_platform: str = ""
    remote_caps: str = ""


@dataclass
class Route:
    dest: str  # cidr
    nexthop: str
    if_index: Optional[int] = None
    proto: int = 0
    type: int = 0


@dataclass
class ArpEntry:
    if_index: int
    ip: str
    mac: str


@dataclass
class FdbEntry:
    mac: str
    if_index: Optional[int]
    vlan: Optional[int] = None


@dataclass
class Device:
    id: str  # IP we polled
    name: str = ""
    sysdescr: str = ""
    sysobjectid: str = ""
    location: str = ""
    contact: str = ""
    uptime_s: int = 0
    services: int = 0
    vendor: str = ""
    model: str = ""
    serial: str = ""
    os_version: str = ""
    os_family: str = ""  # windows | linux | ios | nx-os | junos | fortios | network | …
    dns_name: str = ""
    role: str = "unknown"
    credential: str = ""
    depth: int = 0
    discovered_via: str = ""
    lldp_chassis_id: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    fdb: list[FdbEntry] = field(default_factory=list)
    vlans: dict[int, str] = field(default_factory=dict)
    components: list[Component] = field(default_factory=list)
    redundancy: list = field(default_factory=list)  # FHRP groups: {proto:hsrp|vrrp, group, vip, state, priority, if_index}
    peers: list = field(default_factory=list)  # routing adjacencies: {proto:ospf|bgp, addr, state, extra}
    stp: dict = field(default_factory=dict)  # {root, root_port, priority, is_root}
    ports: list = field(default_factory=list)  # open ports from an nmap scan: {port, proto, service, product}
    functions: list = field(default_factory=list)  # server functions inferred from open ports
    os_detail: str = ""  # OS guess from nmap -O (SNMP sysDescr still wins for os_version)
    poe_budget_w: float = 0.0  # total PoE the switch can supply (watts)
    poe_used_w: float = 0.0  # PoE currently drawn (watts)
    mgmt: dict = field(default_factory=dict)  # exposed management planes: {telnet,http,https,ssh,snmp: bool}
    ips: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    collected_at: float = 0.0
    collect_seconds: float = 0.0
    first_seen: float = 0.0
    errors: list[str] = field(default_factory=list)

    def iface(self, index: Optional[int]) -> Optional[Interface]:
        if index is None:
            return None
        for i in self.interfaces:
            if i.index == index:
                return i
        return None

    def iface_label(self, index: Optional[int]) -> str:
        i = self.iface(index)
        if not i:
            return f"if{index}" if index is not None else ""
        return i.name or i.descr or f"if{i.index}"

    def subnets(self) -> list[str]:
        out = []
        for i in self.interfaces:
            for cidr in i.ips:
                try:
                    n = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                # /31,/32 are point-to-point/host, /0 is a bogus mask (0.0.0.0 on a
                # tunnel/unnumbered iface) that would become a catch-all subnet
                if n.prefixlen >= 31 or n.prefixlen == 0 or n.is_loopback:
                    continue
                out.append(str(n))
        return sorted(set(out))


@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    mac_source: str = ""  # where the MAC came from: fdb | arp | sweep | netbios | lldp
    hostname: str = ""
    vendor: str = ""
    role: str = "host"
    os: str = ""  # e.g. "Windows 10/11", "iOS", "Linux 5.x", "IOS-XE 17.9"
    os_family: str = ""  # windows | linux | macos | ios | android | network | embedded | printer
    model: str = ""  # product/model where a probe revealed it
    confidence: str = ""  # how sure the role/os is: high | medium | low
    sources: list[str] = field(default_factory=list)  # arp | fdb | sweep | lldp | cdp | netbios | mdns | ssdp
    names: dict = field(default_factory=dict)  # {dns|netbios|mdns|ssdp|lldp: name} - every name seen
    seen_on: list[dict] = field(default_factory=list)  # {device, interface, vlan, via}
    ports: list[dict] = field(default_factory=list)  # {port, proto, service, product}
    probes: dict = field(default_factory=dict)  # raw results per probe: netbios | mdns | ssdp | http | tls
    evidence: list[dict] = field(default_factory=list)  # {source, observed, implies} - why we think what we think
    # agentless deep inspection (SSH / WinRM), when credentials allow it
    system: dict = field(default_factory=dict)  # {os, kernel, cpu, cores, memory_mb, serial, manufacturer, product, uptime_s, domain, logged_on}
    software: list[dict] = field(default_factory=list)  # [{name, version}]
    services: list[dict] = field(default_factory=list)  # [{name, state, ...}]
    connections: list[dict] = field(default_factory=list)  # [{proto, laddr, lport, raddr, rport, state, process}]
    inspected_at: float = 0.0
    inspect_source: str = ""  # ssh | winrm
    functions: list = field(default_factory=list)  # server functions from open ports: web, SQL Server, file, mail, DNS, ....
    snmp_failed: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class Subnet:
    cidr: str
    sources: list[str] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    vlan: Optional[int] = None
    swept: bool = False


class Inventory:
    def __init__(self):
        self.devices: dict[str, Device] = {}
        self.hosts: dict[str, Host] = {}
        self.subnets: dict[str, Subnet] = {}
        self.unreachable: dict[str, str] = {}  # ip -> reason (no snmp)
        self.ip_to_device: dict[str, str] = {}
        self.mac_to_device: dict[str, str] = {}
        self.meta: dict = {"created": time.time(), "version": FORMAT_VERSION}
        # Documentation layered on top of what scans find. Keyed by node id: a device's
        # management IP, a host IP, a subnet CIDR, or "stub:<name>" for an unpolled neighbour.
        self.annotations: dict[str, dict] = {}
        self.layout: dict[str, dict[str, list[float]]] = {}  # view name -> node id -> [x, y]
        self.project: dict = {}  # name, description, saved scan settings (never secrets)
        self.history: list[dict] = []  # one entry per scan: when, what was asked, what was found
        self.configs: dict[str, list[dict]] = {}  # device id -> [{captured_at, text, sha}] newest last
        self.dhcp_scopes: dict[str, dict] = {}  # subnet cidr -> {leases, imported_at} from an imported DHCP export

    # ---- devices ----
    def add_device(self, dev: Device) -> None:
        if not dev.first_seen:
            dev.first_seen = dev.collected_at or time.time()
        self.devices[dev.id] = dev
        for ip in dev.ips:
            self.ip_to_device.setdefault(ip, dev.id)
        self.ip_to_device[dev.id] = dev.id
        for mac in dev.macs:
            self.mac_to_device.setdefault(mac, dev.id)
        if dev.lldp_chassis_id:
            self.mac_to_device.setdefault(dev.lldp_chassis_id, dev.id)
        for cidr in dev.subnets():
            self.add_subnet(cidr, "device")

    def replace_device(self, dev: Device) -> None:
        """Swap in a freshly collected copy of a device we already had (a rescan)."""
        old = self.devices.get(dev.id)
        if old is not None and old.first_seen:
            dev.first_seen = old.first_seen
        self.devices[dev.id] = dev
        self.reindex()
        for cidr in dev.subnets():
            self.add_subnet(cidr, "device")

    def remove_device(self, did: str) -> None:
        self.devices.pop(did, None)
        self.reindex()

    def reindex(self) -> None:
        """Rebuild the address/MAC lookups from the devices themselves."""
        self.ip_to_device = {}
        self.mac_to_device = {}
        for d in self.devices.values():
            self.ip_to_device[d.id] = d.id
        for d in self.devices.values():
            for ip in d.ips:
                self.ip_to_device.setdefault(ip, d.id)
            for mac in d.macs:
                self.mac_to_device.setdefault(mac, d.id)
            if d.lldp_chassis_id:
                self.mac_to_device.setdefault(d.lldp_chassis_id, d.id)

    def device_for_ip(self, ip: str) -> Optional[Device]:
        did = self.ip_to_device.get(ip)
        return self.devices.get(did) if did else None

    def device_for_name(self, name: str) -> Optional[Device]:
        from .util import short_name

        target = short_name(name)
        if not target:
            return None
        for d in self.devices.values():
            if short_name(d.name) == target:
                return d
        return None

    # ---- hosts ----
    def touch_host(self, ip: str, source: str, mac: Optional[str] = None) -> Host:
        h = self.hosts.get(ip)
        now = time.time()
        if h is None:
            h = Host(ip=ip, first_seen=now)
            self.hosts[ip] = h
        h.last_seen = now
        if source not in h.sources:
            h.sources.append(source)
        if mac and not h.mac:
            h.mac = mac
        return h

    def mac_to_ip(self) -> dict[str, str]:
        m: dict[str, str] = {}
        for h in self.hosts.values():
            if h.mac:
                m.setdefault(h.mac, h.ip)
        for d in self.devices.values():
            for a in d.arp:
                m.setdefault(a.mac, a.ip)
        return m

    # ---- subnets ----
    def add_subnet(self, cidr: str, source: str) -> Subnet:
        s = self.subnets.get(cidr)
        if s is None:
            s = Subnet(cidr=cidr)
            self.subnets[cidr] = s
        if source not in s.sources:
            s.sources.append(source)
        return s

    def subnet_for_ip(self, ip: str) -> Optional[str]:
        """Most specific known subnet containing `ip` (longest-prefix match)."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        key = (len(self.subnets), id(self.subnets))
        if getattr(self, "_lpm_key", None) != key:
            by_len: dict[int, dict[int, str]] = {}
            for cidr in self.subnets:
                n = ipaddress.ip_network(cidr)
                if n.version == 4:
                    by_len.setdefault(n.prefixlen, {})[int(n.network_address) >> (32 - n.prefixlen) if n.prefixlen else 0] = cidr
            self._lpm = sorted(by_len.items(), reverse=True)
            self._lpm_key = key
        if a.version != 4:
            return None
        v = int(a)
        for plen, table in self._lpm:
            hit = table.get(v >> (32 - plen) if plen else 0)
            if hit:
                return hit
        return None

    # ---- persistence ----
    def to_dict(self) -> dict:
        return {
            "meta": {**self.meta, "version": FORMAT_VERSION},
            "project": self.project,
            "devices": {k: asdict(v) for k, v in self.devices.items()},
            "hosts": {k: asdict(v) for k, v in self.hosts.items()},
            "subnets": {k: asdict(v) for k, v in self.subnets.items()},
            "unreachable": self.unreachable,
            "annotations": self.annotations,
            "layout": self.layout,
            "history": self.history,
            "configs": self.configs,
            "dhcp_scopes": self.dhcp_scopes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Inventory":
        inv = cls()
        inv.meta = d.get("meta", inv.meta)
        for k, dv in d.get("devices", {}).items():
            dev = _build(
                Device,
                {
                    **dv,
                    "interfaces": [_build(Interface, i) for i in dv.get("interfaces", [])],
                    "neighbors": [_build(Neighbor, n) for n in dv.get("neighbors", [])],
                    "routes": [_build(Route, r) for r in dv.get("routes", [])],
                    "arp": [_build(ArpEntry, a) for a in dv.get("arp", [])],
                    "fdb": [_build(FdbEntry, f) for f in dv.get("fdb", [])],
                    "components": [_build(Component, c) for c in dv.get("components", [])],
                    "vlans": {int(a): b for a, b in dv.get("vlans", {}).items()},
                },
            )
            inv.add_device(dev)
        for k, hv in d.get("hosts", {}).items():
            inv.hosts[k] = _build(Host, hv)
        for k, sv in d.get("subnets", {}).items():
            inv.subnets[k] = _build(Subnet, sv)
        inv.unreachable = dict(d.get("unreachable", {}))
        inv.annotations = {k: dict(v) for k, v in (d.get("annotations") or {}).items()}
        inv.layout = {k: dict(v) for k, v in (d.get("layout") or {}).items()}
        inv.project = dict(d.get("project") or {})
        inv.history = list(d.get("history") or [])
        inv.configs = {k: list(v) for k, v in (d.get("configs") or {}).items()}
        inv.dhcp_scopes = {k: dict(v) for k, v in (d.get("dhcp_scopes") or {}).items()}
        return inv

    def copy(self) -> "Inventory":
        """A deep, independent copy (a scan works on one while the app shows the other)."""
        return Inventory.from_dict(json.loads(json.dumps(self.to_dict(), default=list)))

    def save(self, path: str) -> None:
        self.meta["saved"] = time.time()
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=1, default=list)
        os.replace(tmp, path)

    # ---- documentation layered on top ----
    def note(self, node_id: str) -> dict:
        """The annotation record for a node (empty dict if none; not created)."""
        return self.annotations.get(node_id, {})

    def annotate(self, node_id: str, **fields) -> dict:
        """Set/clear annotation fields; empty values remove the field, an empty record is dropped."""
        rec = dict(self.annotations.get(node_id, {}))
        for k, v in fields.items():
            if v in (None, "", [], {}):
                rec.pop(k, None)
            else:
                rec[k] = v
        if rec:
            self.annotations[node_id] = rec
        else:
            self.annotations.pop(node_id, None)
        return rec

    def display_name(self, node_id: str) -> str:
        """What people call it: the annotated name, else sysName/hostname/DNS, else the id."""
        name = self.note(node_id).get("name")
        if name:
            return name
        d = self.devices.get(node_id)
        if d:
            return d.name or d.dns_name or d.id
        h = self.hosts.get(node_id)
        if h:
            return h.hostname or h.ip
        return node_id

    @classmethod
    def load(cls, path: str) -> "Inventory":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def summary(self) -> str:
        return (
            f"{len(self.devices)} devices, {len(self.hosts)} hosts, {len(self.subnets)} subnets, "
            f"{len(self.unreachable)} addresses without SNMP"
        )
