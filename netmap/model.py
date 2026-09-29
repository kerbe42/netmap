"""Data model: what we learned about each device/host/subnet, plus JSON persistence."""
from __future__ import annotations

import ipaddress
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


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
    ips: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    collected_at: float = 0.0
    collect_seconds: float = 0.0
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
                if n.prefixlen >= 31 or n.is_loopback:
                    continue
                out.append(str(n))
        return sorted(set(out))


@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    hostname: str = ""
    vendor: str = ""
    role: str = "host"
    sources: list[str] = field(default_factory=list)  # arp | fdb | sweep | lldp | cdp
    seen_on: list[dict] = field(default_factory=list)  # {device, interface, vlan, via}
    ports: list[dict] = field(default_factory=list)  # {port, proto, service, product}
    snmp_failed: bool = False


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
        self.meta: dict = {"created": time.time(), "version": 1}

    # ---- devices ----
    def add_device(self, dev: Device) -> None:
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
        if h is None:
            h = Host(ip=ip)
            self.hosts[ip] = h
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
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best = None
        for cidr in self.subnets:
            n = ipaddress.ip_network(cidr)
            if a in n and (best is None or n.prefixlen > best.prefixlen):
                best = n
        return str(best) if best else None

    # ---- persistence ----
    def to_dict(self) -> dict:
        return {
            "meta": self.meta,
            "devices": {k: asdict(v) for k, v in self.devices.items()},
            "hosts": {k: asdict(v) for k, v in self.hosts.items()},
            "subnets": {k: asdict(v) for k, v in self.subnets.items()},
            "unreachable": self.unreachable,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Inventory":
        inv = cls()
        inv.meta = d.get("meta", inv.meta)
        for k, dv in d.get("devices", {}).items():
            dev = Device(
                **{
                    **dv,
                    "interfaces": [Interface(**i) for i in dv.get("interfaces", [])],
                    "neighbors": [Neighbor(**n) for n in dv.get("neighbors", [])],
                    "routes": [Route(**r) for r in dv.get("routes", [])],
                    "arp": [ArpEntry(**a) for a in dv.get("arp", [])],
                    "fdb": [FdbEntry(**f) for f in dv.get("fdb", [])],
                    "vlans": {int(a): b for a, b in dv.get("vlans", {}).items()},
                }
            )
            inv.add_device(dev)
        for k, hv in d.get("hosts", {}).items():
            inv.hosts[k] = Host(**hv)
        for k, sv in d.get("subnets", {}).items():
            inv.subnets[k] = Subnet(**sv)
        inv.unreachable = dict(d.get("unreachable", {}))
        return inv

    def save(self, path: str) -> None:
        self.meta["saved"] = time.time()
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=1, default=list)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "Inventory":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def summary(self) -> str:
        return (
            f"{len(self.devices)} devices, {len(self.hosts)} hosts, {len(self.subnets)} subnets, "
            f"{len(self.unreachable)} addresses without SNMP"
        )
