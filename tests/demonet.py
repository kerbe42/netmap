"""A simulated mid-sized campus network, expressed as raw SNMP tables like `labnet`.

Northwind HQ: an edge firewall, a pair of core switches, four floor access stacks, two
warehouse switches from another vendor, a server switch and a WAN router with a branch
behind it - about 500 endpoints between them: PCs, phones, printers, cameras, access
points, servers, a NAS and a UPS. It carries the untidiness real networks have: a VLAN
named differently on two switches, an uplink negotiated at the wrong speed, a switch
nobody has the SNMP community for, and a branch router outside the agreed ranges.

It exercises the crawler and collector end to end in-process (through the fake SNMP
session), and `build_project()` produces the sample project the desktop app ships with.
Everything is deterministic: the same code always produces the same network.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import random

from netmap import oids as O
from netmap.util import resource_path

from .labnet import Dev

CISCO_9500 = "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)"
CISCO_9300 = "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)"
CISCO_9200 = "Cisco IOS Software [Bengaluru], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.6.5, RELEASE SOFTWARE (fc2)"
CISCO_ISR = "Cisco IOS Software [Amsterdam], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.3.4a, RELEASE SOFTWARE (fc3)"
ARUBA_2930 = "Aruba JL260A 2930F-48G-4SFP Switch, revision WC.16.10.0021, ROM WC.16.01.0010 (/ws/swbuildm/rel_orlando_qaoff/code/build/anm(swbuildm_rel_orlando_qaoff_rel_orlando))"
FORTIGATE = "FortiGate-100F v7.2.8,build1639,240313 (GA.M)"

_OUI_CACHE: dict[str, list[str]] = {}


def oui(vendor: str) -> list[str]:
    """OUI prefixes the bundled IEEE table assigns to exactly this organization name."""
    if vendor not in _OUI_CACHE:
        out = []
        with open(resource_path("data", "oui.tsv"), encoding="utf-8") as f:
            for line in f:
                if "\t" in line and not line.startswith("#"):
                    p, v = line.rstrip("\n").split("\t", 1)
                    if v == vendor and len(p) == 6:
                        out.append(p)
        _OUI_CACHE[vendor] = out or ["02AA00"]
    return _OUI_CACHE[vendor]


class Macs:
    """Deterministic, unique MACs under a vendor's real OUIs."""

    def __init__(self, seed: int = 7):
        self.rng = random.Random(seed)
        self.used: set[str] = set()

    def __call__(self, vendor: str) -> str:
        pfx = self.rng.choice(oui(vendor))
        while True:
            tail = self.rng.getrandbits(24)
            mac = ":".join([pfx[0:2], pfx[2:4], pfx[4:6], f"{tail >> 16:02x}", f"{(tail >> 8) & 0xff:02x}", f"{tail & 0xff:02x}"]).lower()
            if mac not in self.used:
                self.used.add(mac)
                return mac


VLANS = {10: "USERS", 20: "Voice", 30: "SERVERS", 40: "PRINTERS", 50: "WIFI-CORP", 60: "CAMERAS", 99: "MGMT"}
NETS = {10: "10.10.0.0/22", 20: "10.20.0.0/23", 30: "10.30.0.0/24", 40: "10.40.0.0/24", 50: "10.50.0.0/22", 60: "10.60.0.0/24", 99: "10.99.0.0/24"}


def _host(net: str, n: int) -> str:
    return str(ipaddress.ip_network(net).network_address + n)


def build(seed: int = 7) -> tuple[dict[str, Dev], dict[str, str]]:
    """({mgmt_ip: Dev}, {ip: PTR name}) for the whole campus."""
    rng = random.Random(seed)
    mac = Macs(seed)
    ptr: dict[str, str] = {}
    devs: dict[str, Dev] = {}

    FW, C1, C2 = "10.0.0.1", "10.99.0.2", "10.99.0.3"
    SRV, WAN = "10.99.0.20", "10.0.1.1"
    fw_mac, c1_mac, c2_mac = mac("Fortinet"), mac("Cisco Systems"), mac("Cisco Systems")
    srv_mac, wan_mac = mac("Cisco Systems"), mac("Cisco Systems")

    # ---------------------------------------------------------------- core pair
    cores = {}
    for n, (ip, cmac, name) in enumerate(((C1, c1_mac, "core-sw-01"), (C2, c2_mac, "core-sw-02"))):
        d = Dev()
        d.system(name, CISCO_9500, "1.3.6.1.4.1.9.1.2494", 6, uptime=86400 * 212 * 100 + n * 7777)
        d.s(O.SYS_LOCATION, "HQ, ground floor, comms room A, rack 2")
        d.ent(1, 3, "Cisco Catalyst 9500 Series Chassis", "Chassis", model="C9500-24Y4C", serial=f"FDO2533{n}1QX", hw="V02", sw="17.9.4a", fru=False)
        d.ent(2, 6, "Cisco Catalyst 9500 950W AC Power Supply", "Power Supply Module 0", parent=1, model="C9K-PWR-950WAC-R", serial=f"DTN2531V{n}8A", fru=True)
        d.ent(3, 6, "Cisco Catalyst 9500 950W AC Power Supply", "Power Supply Module 1", parent=1, model="C9K-PWR-950WAC-R", serial=f"DTN2531V{n}8B", fru=True)
        for f in range(4):
            d.ent(10 + f, 7, "Cisco Catalyst 9500 Fan Module", f"Fan Tray {f}", parent=1, model="C9K-T1-FANTRAY", serial=f"FDO2530{n}{f}FN", fru=True)
        cores[ip] = d
        # interfaces: 1-24 Twe1/0/x downlinks, 23-24 port-channel to the other core, 30+ SVIs
        for p in range(1, 25):
            d.iface(p, f"Twe1/0/{p}", f"TwentyFiveGigE1/0/{p}", f"{cmac[:-2]}{p:02x}", speed=10000 if p < 23 else 25000, up=p <= 12 or p >= 23)
        d.iface(100, "Po1", "Port-channel1", cmac, speed=50000, alias="core interconnect", iftype=161)
        d.lag({23: 100, 24: 100})
        d.iface(40, "Te1/1/1", "TenGigabitEthernet1/1/1", f"{cmac[:-2]}40", speed=10000, alias="to fw-edge-01")
        d.addr(f"10.0.0.{2 + n}", 40, "255.255.255.248")
        for vid, net in NETS.items():
            idx = 1000 + vid
            d.iface(idx, f"Vl{vid}", f"Vlan{vid}", cmac, iftype=53)
            d.addr(_host(net, 2 + n), idx, str(ipaddress.ip_network(net).netmask))
            d.vlan(vid, VLANS[vid])
            d.cidr_route(str(ipaddress.ip_network(net).network_address), str(ipaddress.ip_network(net).netmask), "0.0.0.0", idx, rtype=3)
            if vid != 99:  # HSRP: .1 is the shared gateway; core-sw-01 active, core-sw-02 standby
                d.hsrp(idx, vid, _host(net, 1), state=6 if n == 0 else 5, priority=110 if n == 0 else 100)
        d.ospf_nbr(C2 if n == 0 else C1), d.ospf_nbr(WAN)  # OSPF full mesh across the core and to the WAN router
        d.stp(c1_mac, priority=4096, own_mac=cmac)  # core-sw-01 is the STP root for the campus
        d.cidr_route("0.0.0.0", "0.0.0.0", FW, 40, proto=3)
        d.cidr_route("10.0.0.0", "255.255.255.248", "0.0.0.0", 40, rtype=3)
        d.lldp_local(cmac, name, {p: (f"Twe1/0/{p}", f"TwentyFiveGigE1/0/{p}") for p in range(1, 25)} | {40: ("Te1/1/1", "TenGigabitEthernet1/1/1")})
        d.bridge_ports({p: p for p in range(1, 25)} | {40: 40})
        for p in range(1, 13):
            d.cisco_port(p, trunk=True, native=99)
        d.cisco_port(23, trunk=True, native=99), d.cisco_port(24, trunk=True, native=99)
        for k, (pid, cls, mdl) in enumerate((("Twe1/0/1", "SFP-10G-SR", "SFP-10G-SR"), ("Twe1/0/2", "SFP-10G-SR", "SFP-10G-SR"), ("Twe1/0/23", "SFP-25G-SR-S", "SFP-25G-SR-S"), ("Twe1/0/24", "SFP-25G-SR-S", "SFP-25G-SR-S"))):
            d.ent(100 + k, 10, f"{mdl} transceiver", pid, parent=1, model=mdl, serial=f"AVD{n}{k}23{rng.randint(1000, 9999)}", fru=True)
        ptr[ip] = f"{name}.mgmt.northwind.example"
    c1, c2 = cores[C1], cores[C2]
    # core interconnect: LLDP on both members, both directions
    for a, b, amac, bname, bip in ((c1, c2, c2_mac, "core-sw-02", C2), (c2, c1, c1_mac, "core-sw-01", C1)):
        a.lldp_rem(23, 1, amac, "Twe1/0/23", "TwentyFiveGigE1/0/23", bname, CISCO_9500, 0x14, mgmt_ip=bip)
        a.lldp_rem(24, 2, amac, "Twe1/0/24", "TwentyFiveGigE1/0/24", bname, CISCO_9500, 0x14, mgmt_ip=bip)

    # ---------------------------------------------------------------- firewall
    fw = Dev()
    fw.system("fw-edge-01", FORTIGATE, "1.3.6.1.4.1.12356.101.1.1004", 76, uptime=86400 * 97 * 100)
    fw.s(O.SYS_LOCATION, "HQ, ground floor, comms room A, rack 1")
    fw.ent(1, 3, "Fortinet FortiGate-100F", "Chassis", model="FG-100F", serial="FG100FTK21009876", fru=False)
    fw.iface(1, "wan1", "wan1", fw_mac, speed=1000, alias="ISP circuit NW-44213")
    fw.iface(2, "port1", "port1", f"{fw_mac[:-2]}02", speed=10000, alias="core-sw-01")
    fw.iface(3, "port2", "port2", f"{fw_mac[:-2]}03", speed=10000, alias="core-sw-02")
    fw.iface(10, "internal", "internal", f"{fw_mac[:-2]}0a", speed=10000, iftype=6)
    fw.addr("203.0.113.10", 1, "255.255.255.248")
    fw.addr(FW, 10, "255.255.255.248")
    fw.cidr_route("0.0.0.0", "0.0.0.0", "203.0.113.9", 1, proto=3)
    fw.cidr_route("10.0.0.0", "255.0.0.0", "10.0.0.2", 10, proto=3)
    fw.arp(10, "10.0.0.2", c1_mac), fw.arp(10, "10.0.0.3", c2_mac), fw.arp(1, "203.0.113.9", mac("Juniper Networks"))
    fw.lldp_local(fw_mac, "fw-edge-01", {2: ("port1", "port1"), 3: ("port2", "port2")})
    fw.lldp_rem(2, 1, c1_mac, "Te1/1/1", "TenGigabitEthernet1/1/1", "core-sw-01", CISCO_9500, 0x14, mgmt_ip="10.0.0.2")
    fw.lldp_rem(3, 2, c2_mac, "Te1/1/1", "TenGigabitEthernet1/1/1", "core-sw-02", CISCO_9500, 0x14, mgmt_ip="10.0.0.3")
    for n, core in enumerate((c1, c2)):
        core.lldp_rem(40, 5, fw_mac, f"port{n + 1}", f"port{n + 1}", "fw-edge-01", FORTIGATE, 0x10, mgmt_ip=FW)
        core.arp(40, FW, fw_mac)
    devs[FW] = fw
    ptr[FW] = "fw-edge-01.mgmt.northwind.example"

    # ---------------------------------------------------------------- endpoints helpers
    host_seq = {vid: 20 for vid in NETS}

    def next_ip(vid):
        host_seq[vid] += 1
        return _host(NETS[vid], host_seq[vid])

    def learn(sw: Dev, bport: int, vid: int, m: str, ip: str | None):
        sw.fdb_q(vid, m, bport)
        if ip:
            for core in (c1, c2):
                core.arp(1000 + vid, ip, m)
        for core_port, core in ((acc_uplink[sw], c1), (acc_uplink[sw], c2)):
            core.fdb_q(vid, m, core_port)

    acc_uplink: dict = {}

    # ---------------------------------------------------------------- access stacks (Cisco, floors 1-4)
    ap_models = ("Aruba AP-515", "Aruba AP-535")
    access = []
    for fl in range(1, 5):
        name = f"acc-fl{fl}-01"
        ip = f"10.99.0.{10 + fl}"
        smac = mac("Cisco Systems")
        d = Dev()
        d.system(name, CISCO_9200, "1.3.6.1.4.1.9.1.2753", 6, uptime=86400 * (40 + fl * 17) * 100)
        d.s(O.SYS_LOCATION, f"HQ, floor {fl}, comms cupboard {fl}A")
        d.ent(1, 11, "c92xxL Stack", "Stack", fru=False)
        for m in (1, 2):
            d.ent(1000 * m, 3, "Cisco Catalyst 9200L 48-port PoE+ switch", f"Switch {m}", parent=1, model="C9200L-48P-4X", serial=f"JAE24{fl}{m}0{rng.randint(100, 999)}", hw="V02", sw="17.6.5", fru=True)
            d.ent(1000 * m + 1, 6, "Cisco Catalyst 9200L 600W AC power supply", f"Switch {m} - Power Supply A", parent=1000 * m, model="PWR-C5-600WAC", serial=f"DCC24{fl}{m}{rng.randint(1000, 9999)}", fru=True)
        d.ent(3001, 10, "SFP-10G-LR", "Te1/1/1", parent=1000, model="SFP-10G-LR", serial=f"FNS2{fl}1{rng.randint(10000, 99999)}", fru=True)
        d.ent(3002, 10, "SFP-10G-LR", "Te2/1/1", parent=2000, model="SFP-10G-LR", serial=f"FNS2{fl}2{rng.randint(10000, 99999)}", fru=True)
        ports = {}
        idx = 0
        for m in (1, 2):
            for p in range(1, 49):
                idx += 1
                ports[idx] = f"Gi{m}/0/{p}"
        up1, up2 = 97, 98
        # the floor-3 stack's second uplink came up at 1G: a mismatch against the core's 10G port
        wrong_speed = fl == 3
        d.iface(up1, "Te1/1/1", "TenGigabitEthernet1/1/1", f"{smac[:-2]}61", speed=10000, alias="uplink core-sw-01")
        d.iface(up2, "Te2/1/1", "TenGigabitEthernet2/1/1", f"{smac[:-2]}62", speed=1000 if wrong_speed else 10000, alias="uplink core-sw-02")
        d.iface(99, "Po1", "Port-channel1", smac, speed=11000 if wrong_speed else 20000, alias="uplink to core", iftype=161)
        d.lag({up1: 99, up2: 99})
        d.iface(199, "Vl99", "Vlan99", smac, iftype=53)
        d.addr(ip, 199, "255.255.255.0")
        d.cidr_route("0.0.0.0", "0.0.0.0", "10.99.0.1", 199, proto=3)
        for v, n in VLANS.items():
            if v != 30:
                d.vlan(v, n)
        d.bridge_ports({i: i for i in list(ports) + [up1, up2]})
        d.cisco_port(up1, trunk=True, native=99), d.cisco_port(up2, trunk=True, native=99)
        d.lldp_local(smac, name, {up1: ("Te1/1/1", "TenGigabitEthernet1/1/1"), up2: ("Te2/1/1", "TenGigabitEthernet2/1/1")} | {i: (n, n) for i, n in ports.items()})
        d.lldp_rem(up1, 1, c1_mac, f"Twe1/0/{fl}", f"TwentyFiveGigE1/0/{fl}", "core-sw-01", CISCO_9500, 0x14, mgmt_ip=C1)
        d.lldp_rem(up2, 2, c2_mac, f"Twe1/0/{fl}", f"TwentyFiveGigE1/0/{fl}", "core-sw-02", CISCO_9500, 0x14, mgmt_ip=C2)
        c1.lldp_rem(fl, 10 + fl, smac, "Te1/1/1", "TenGigabitEthernet1/1/1", name, CISCO_9200, 0x14, mgmt_ip=ip)
        c2.lldp_rem(fl, 10 + fl, smac, "Te2/1/1", "TenGigabitEthernet2/1/1", name, CISCO_9200, 0x14, mgmt_ip=ip)
        for core in (c1, c2):
            core.arp(1099, ip, smac)
        acc_uplink[d] = fl
        # endpoints
        free = list(ports)
        rem = 10
        def port_iface(i, alias=""):
            d.iface(i, ports[i], ports[i].replace("Gi", "GigabitEthernet"), None, speed=1000, alias=alias)

        for i in free:
            port_iface(i)
        cur = iter(free)
        # 2 APs per floor (trunk ports, native 99, LLDP with a management address)
        for a in range(2):
            i = next(cur)
            am = mac("Hewlett Packard Enterprise")
            aip = f"10.99.0.{100 + fl * 10 + a}"
            aname = f"ap-fl{fl}-{a + 1:02d}"
            d.iface(i, ports[i], ports[i], None, speed=2500 if a == 0 else 1000, alias=aname)
            d.cisco_port(i, trunk=True, native=99)
            d.lldp_rem(i, rem, am, am, "eth0", aname, f"ArubaOS (MODEL: {ap_models[a]}), Version 8.10.0.7", 0x18, mgmt_ip=aip)
            rem += 1
            learn(d, i, 99, am, aip)
            ptr[aip] = f"{aname}.mgmt.northwind.example"
            # wireless clients behind the AP: only in the core's ARP, on the AP's trunk
            for c in range(rng.randint(12, 22)):
                cm = mac(rng.choice(["Apple", "Samsung Electronics", "Intel Corporate", "Apple"]))
                cip = next_ip(50)
                learn(d, i, 50, cm, cip)
        # PCs with a phone in front (phone on the port, PC behind it), plus some PCs direct
        n_desks = rng.randint(28, 40)
        for k in range(n_desks):
            i = next(cur)
            pm = mac(rng.choice(["Dell", "Dell", "Lenovo", "Intel Corporate"]))
            pip = next_ip(10)
            d.cisco_port(i, access=10)
            learn(d, i, 10, pm, pip)
            ptr[pip] = f"nw-pc-{fl}{k + 1:03d}.corp.northwind.example"
            if k % 3 != 2:
                ym = mac(rng.choice(["Yealink(Xiamen) Network Technology", "Polycom"]))
                yip = next_ip(20)
                learn(d, i, 20, ym, yip)
                d.lldp_rem(i, rem, ym, ym, "WAN PORT", f"SEP{ym.replace(':', '').upper()}", "Yealink SIP-T54W 96.86.0.70" if ym[:8] != "00:04:f2" else "Polycom VVX 450", 0x24, mgmt_ip=yip)
                rem += 1
        # printers and a camera
        for k in range(2):
            i = next(cur)
            prm = mac(rng.choice(["HP", "Kyocera", "Brother Industries"]))
            prip = next_ip(40)
            d.cisco_port(i, access=40)
            learn(d, i, 40, prm, prip)
            ptr[prip] = f"prn-fl{fl}-{k + 1:02d}.corp.northwind.example"
        for k in range(2):
            i = next(cur)
            cam = mac(rng.choice(["Axis Communications AB", "Hangzhou Hikvision Digital Technology"]))
            cip = next_ip(60)
            d.cisco_port(i, access=60)
            learn(d, i, 60, cam, cip)
            ptr[cip] = f"cam-fl{fl}-{k + 1:02d}.sec.northwind.example"
        # a few shut / unused ports
        for i in list(cur)[: rng.randint(4, 12)]:
            d.iface(i, ports[i], ports[i], None, up=False)
        devs[ip] = d
        access.append((ip, d, smac, name))
        ptr[ip] = f"{name}.mgmt.northwind.example"
        if fl == 1:
            # an old unmanaged-looking switch in the basement: LLDP says who it is, no community works
            ng = mac("Netgear")
            i = 96
            d.iface(i, ports[i], ports[i], None, alias="basement ??")
            d.lldp_rem(i, rem, ng, "g24", "g24", "GS724T-basement", "GS724Tv4 ProSafe 24-port Gigabit Smart Switch", 0x20, mgmt_ip="10.99.0.250")
            for core in (c1, c2):
                core.arp(1099, "10.99.0.250", ng)

    # ---------------------------------------------------------------- warehouse (Aruba / HPE, Q-BRIDGE)
    for w in (1, 2):
        name = f"wh-sw-0{w}"
        ip = f"10.99.0.{30 + w}"
        smac = mac("Hewlett Packard Enterprise")
        d = Dev()
        d.system(name, ARUBA_2930, "1.3.6.1.4.1.11.2.3.7.11.181", 2, uptime=86400 * (300 + w) * 100)
        d.s(O.SYS_LOCATION, f"Warehouse, bay {w * 4}")
        d.ent(1, 3, "Aruba JL260A 2930F-48G-4SFP Switch", "Chassis", model="JL260A", serial=f"SG9{w}KHM{rng.randint(100, 999)}", fru=False)
        for p in range(1, 53):
            d.iface(p, str(p), str(p), None, speed=10000 if p > 48 else 1000, up=p <= 30 or p in (49, 50))
        d.iface(100, "DEFAULT_VLAN", "DEFAULT_VLAN", smac, iftype=53)
        d.iface(199, "VLAN99", "VLAN99", smac, iftype=53)
        d.addr(ip, 199, "255.255.255.0")
        d.cidr_route("0.0.0.0", "0.0.0.0", "10.99.0.1", 199, proto=3)
        for v, n in VLANS.items():
            if v in (10, 20, 40, 60, 99):
                d.vlan(v, "VOICE" if v == 20 else n)  # the other vendor spelled it differently
        d.bridge_ports({p: p for p in range(1, 53)})
        up = 49
        d.lldp_local(smac, name, {p: (str(p), str(p)) for p in range(1, 53)})
        core_port = 4 + w
        d.lldp_rem(up, 1, c1_mac, f"Twe1/0/{core_port}", f"TwentyFiveGigE1/0/{core_port}", "core-sw-01", CISCO_9500, 0x14, mgmt_ip=C1)
        c1.lldp_rem(core_port, 20 + w, smac, "49", "49", name, ARUBA_2930, 0x04 | 0x20, mgmt_ip=ip)
        c1.arp(1099, ip, smac), c2.arp(1099, ip, smac)
        acc_uplink[d] = core_port
        pv = {}
        for i in range(1, 25):
            vid = 60 if i in (23, 24) else (40 if i == 22 else 10)
            pv[i] = vid
            m = mac({10: "Zebra Technologies", 40: "Zebra Technologies", 60: "Axis Communications AB"}[vid] if i > 16 else rng.choice(["Dell", "Intel Corporate", "Lenovo"]))
            hip = next_ip(vid)
            learn(d, i, vid, m, hip)
            ptr[hip] = (f"wh{w}-scanner-{i:02d}" if i > 16 and vid == 10 else f"wh{w}-pc-{i:02d}" if vid == 10 else f"wh{w}-prn-{i:02d}" if vid == 40 else f"cam-wh{w}-{i:02d}") + ".corp.northwind.example"
        pv[up] = 99
        d.pvids(pv)
        for vid in (10, 20, 40, 60, 99):
            d.vlan_ports(vid, [p for p, v in pv.items() if v == vid] + [up], [p for p, v in pv.items() if v == vid])
        devs[ip] = d
        ptr[ip] = f"{name}.mgmt.northwind.example"

    # ---------------------------------------------------------------- server switch
    d = Dev()
    d.system("srv-sw-01", CISCO_9300, "1.3.6.1.4.1.9.1.2586", 6, uptime=86400 * 212 * 100)
    d.s(O.SYS_LOCATION, "HQ, ground floor, comms room A, rack 3")
    d.ent(1, 3, "Cisco Catalyst 9300 48-port data switch", "Switch 1", model="C9300-48T", serial="FOC2418Y0ZK", hw="V02", sw="17.9.4a", fru=True)
    d.ent(2, 6, "Cisco Catalyst 9300 715W AC power supply", "Power Supply A", parent=1, model="PWR-C1-715WAC", serial="LIT2412ABCD", fru=True)
    d.ent(3, 6, "Cisco Catalyst 9300 715W AC power supply", "Power Supply B", parent=1, model="PWR-C1-715WAC", serial="LIT2412ABCE", fru=True)
    d.ent(4, 9, "8x10G Uplink Module", "Network Module 1", parent=1, model="C9300-NM-8X", serial="FOC24170NM1", fru=True)
    for p in range(1, 49):
        d.iface(p, f"Gi1/0/{p}", f"GigabitEthernet1/0/{p}", None, speed=1000, up=p <= 20)
    d.iface(49, "Te1/1/1", "TenGigabitEthernet1/1/1", f"{srv_mac[:-2]}49", speed=10000, alias="uplink core-sw-01")
    d.iface(50, "Te1/1/2", "TenGigabitEthernet1/1/2", f"{srv_mac[:-2]}50", speed=10000, alias="uplink core-sw-02")
    d.iface(199, "Vl99", "Vlan99", srv_mac, iftype=53)
    d.addr(SRV, 199, "255.255.255.0")
    d.vlan(30, "SERVERS"), d.vlan(99, "MGMT")
    d.bridge_ports({p: p for p in range(1, 51)})
    d.cisco_port(49, trunk=True, native=99), d.cisco_port(50, trunk=True, native=99)
    d.lldp_local(srv_mac, "srv-sw-01", {49: ("Te1/1/1", "TenGigabitEthernet1/1/1"), 50: ("Te1/1/2", "TenGigabitEthernet1/1/2")})
    d.lldp_rem(49, 1, c1_mac, "Twe1/0/7", "TwentyFiveGigE1/0/7", "core-sw-01", CISCO_9500, 0x14, mgmt_ip=C1)
    d.lldp_rem(50, 2, c2_mac, "Twe1/0/7", "TwentyFiveGigE1/0/7", "core-sw-02", CISCO_9500, 0x14, mgmt_ip=C2)
    c1.lldp_rem(7, 30, srv_mac, "Te1/1/1", "TenGigabitEthernet1/1/1", "srv-sw-01", CISCO_9300, 0x14, mgmt_ip=SRV)
    c2.lldp_rem(7, 30, srv_mac, "Te1/1/2", "TenGigabitEthernet1/1/2", "srv-sw-01", CISCO_9300, 0x14, mgmt_ip=SRV)
    c1.arp(1099, SRV, srv_mac), c2.arp(1099, SRV, srv_mac)
    acc_uplink[d] = 7
    srv_names = []
    for k in range(3):  # ESXi hosts, each with a handful of VMs behind the same port
        i = k + 1
        hm = mac("Dell")
        hip = next_ip(30)
        d.cisco_port(i, access=30)
        learn(d, i, 30, hm, hip)
        ptr[hip] = f"esx-hq-0{k + 1}.corp.northwind.example"
        d.lldp_rem(i, 10 + k, hm, "vmnic0", "vmnic0", f"esx-hq-0{k + 1}", "VMware ESX Releasebuild-22380479", 0x80, mgmt_ip=hip)
        for v in range(4 + k * 2):
            vm = mac("VMware")
            vip = next_ip(30)
            learn(d, i, 30, vm, vip)
            nm = rng.choice(["dc", "file", "sql", "app", "print", "backup", "web", "erp", "mail", "monitor"])
            ptr[vip] = f"{nm}{v + 1:02d}.corp.northwind.example"
            srv_names.append(vip)
    for k, (vendor, label) in enumerate((("Synology Incorporated", "nas-hq-01"), ("American Power Conversion", "ups-hq-01"), ("Super Micro Computer", "backup-hq-01"), ("Dell", "idrac-esx-01"))):
        i = 10 + k
        m = mac(vendor)
        hip = next_ip(30)
        d.cisco_port(i, access=30)
        learn(d, i, 30, m, hip)
        ptr[hip] = f"{label}.corp.northwind.example"
    devs[SRV] = d
    ptr[SRV] = "srv-sw-01.mgmt.northwind.example"

    # ---------------------------------------------------------------- WAN router and the branch behind it
    r = Dev()
    r.system("rtr-wan-01", CISCO_ISR, "1.3.6.1.4.1.9.1.2068", 6, uptime=86400 * 5 * 100)
    r.s(O.SYS_LOCATION, "HQ, ground floor, comms room A, rack 1")
    r.ent(1, 3, "Cisco ISR4331 Chassis", "Chassis", model="ISR4331/K9", serial="FDO2319A0B7", hw="V05", fru=False)
    r.ent(2, 6, "450W AC Power Supply for Cisco ISR 4330", "Power Supply Module 0", parent=1, model="PWR-4330-AC", serial="PST2317Z1XY", fru=True)
    r.iface(1, "Gi0/0/0", "GigabitEthernet0/0/0", wan_mac, alias="core-sw-01 Twe1/0/10")
    r.iface(2, "Gi0/0/1", "GigabitEthernet0/0/1", f"{wan_mac[:-2]}02", alias="MPLS to branch Leeds (circuit 7781-L)")
    r.addr(WAN, 1, "255.255.255.252"), r.addr("172.16.100.1", 2, "255.255.255.252")
    r.cidr_route("0.0.0.0", "0.0.0.0", "10.0.1.2", 1, proto=3)
    r.cidr_route("10.110.0.0", "255.255.255.0", "172.16.100.2", 2, proto=13)
    r.cidr_route("10.111.0.0", "255.255.255.0", "172.16.100.2", 2, proto=13)
    r.ospf_nbr("10.0.1.2"), r.bgp_peer("203.0.113.9", 64512)  # OSPF to the core, eBGP to the ISP
    r.arp(1, "10.0.1.2", c1_mac), r.arp(2, "172.16.100.2", mac("Cisco Systems"))
    r.cdp(1, 1, "core-sw-01.northwind.example", "TwentyFiveGigE1/0/10", "cisco C9500-24Y4C", C1)
    r.cdp(2, 2, "rtr-branch-leeds", "GigabitEthernet0/0/0", "cisco ISR1111-8P", "172.16.100.2")
    c1.iface(10, "Twe1/0/10", "TwentyFiveGigE1/0/10", f"{c1_mac[:-2]}0a", speed=1000, alias="rtr-wan-01")
    c1.addr("10.0.1.2", 10, "255.255.255.252")
    c1.cdp(10, 1, "rtr-wan-01.northwind.example", "GigabitEthernet0/0/0", "cisco ISR4331/K9", WAN)
    c1.cidr_route("10.110.0.0", "255.255.255.0", WAN, 10, proto=13)
    c1.cidr_route("10.111.0.0", "255.255.255.0", WAN, 10, proto=13)
    c1.arp(10, WAN, wan_mac)
    devs[WAN] = r
    ptr[WAN] = "rtr-wan-01.mgmt.northwind.example"

    devs[C1], devs[C2] = c1, c2
    return devs, ptr


def build_project(path: str | None = None, name: str = "Northwind HQ (sample)"):
    """Crawl the simulated campus into an inventory (and save it if `path` is given)."""
    from netmap.dns import resolve_names
    from netmap.graph import enrich_inventory
    from netmap.model import Inventory
    from netmap.scan import ScanRequest, run_scan
    from netmap.snmp import Credential

    from .fake_snmp import make_prober

    devs, ptr = build()
    prober = make_prober({ip: d.values() for ip, d in devs.items()})
    inv = Inventory()
    req = ScanRequest(
        seeds=["10.99.0.2"],
        scope=["10.0.0.0/8"],
        exclude=[],
        credentials=[Credential(kind="v3", user="netmap-ro", auth="SHA", priv="AES", label="hq-snmpv3")],
        workers=8,
        timeout=0.1,
        retries=0,
    )

    async def go():
        await run_scan(inv, req, prober=prober, engine=object())
        await resolve_names(inv, lookup=lambda ip: ptr.get(ip))

    asyncio.run(go())
    _inject_probes(inv, rng=random.Random(11))
    enrich_inventory(inv)
    inv.project = {
        "name": name,
        "description": "A simulated campus: edge firewall, core pair, four floor stacks, warehouse and server switches, a WAN router. "
                       "Explore it to see what NetMap does before scanning a real network.",
        "scan": {"targets": [], "seeds": ["10.99.0.2"], "scope": ["10.0.0.0/8"], "exclude": [], "max_depth": 6},
    }
    for h in inv.history:  # the sample should not claim to have been scanned at build time
        h["request"]["credentials"] = ["hq-snmpv3"]
    # a couple of compliance/EoL signals so the sample shows those pages doing something
    if "10.0.1.1" in inv.devices:  # the WAN router still has Telnet and cleartext web open
        inv.devices["10.0.1.1"].mgmt = {"telnet": True, "ssh": True, "http": True, "https": False}
    if "10.99.0.31" in inv.devices:  # an older access switch, past vendor end-of-support
        wh = inv.devices["10.99.0.31"]
        wh.model = "J9147A"
        wh.sysdescr = "ProCurve J9147A 2910al-48G Switch, revision W.15.14.0013"
        wh.os_family = "hp-provision"
    # a little documentation, the way someone taking the network over would start it
    inv.annotate("10.99.0.2", site="HQ comms room A", owner="Network team", status="Verified", tags=["core"],
                 notes="Core pair with core-sw-02 (StackWise Virtual). Default route to fw-edge-01.")
    inv.annotate("10.0.0.1", site="HQ comms room A", owner="Network team", tags=["edge", "internet"],
                 notes="ISP circuit NW-44213, support contract ends 2027-03.")
    inv.annotate("10.99.0.250", status="Unknown owner", notes="Not in the handover list and no community works. Find out who put it there.")
    if path:
        inv.save(path)
    return inv


def _inject_probes(inv, rng):
    """Give a slice of the hosts realistic active-probe results, as if NetBIOS/mDNS/SSDP/HTTP
    had answered, so the sample shows off identification and its evidence. Shapes match
    netmap.discover output."""
    import ipaddress as _ip

    hosts = [(ip, h) for ip, h in inv.hosts.items() if ip not in inv.ip_to_device]
    for ip, h in hosts:
        role = h.role
        sub = inv.subnet_for_ip(ip) or ""
        last = ip.rsplit(".", 1)[-1]
        if role in ("workstation", "windows", "host") and sub.startswith(("10.10.", "10.20.", "10.30.")):
            name = (h.hostname.split(".")[0] if h.hostname else f"WS-{last}").upper()[:15]
            h.probes["netbios"] = {"hostname": name, "domain": "NORTHWIND", "user": rng.choice(["", "", "jsmith", "adesai"]),
                                   "is_dc": False, "mac": h.mac, "names": []}
            h.names["netbios"] = name
            h.sources.append("netbios") if "netbios" not in h.sources else None
            if rng.random() < 0.15:
                h.probes["mdns"] = {"hostname": f"{name}.local", "services": ["_smb._tcp", "_device-info._tcp"], "model": "", "vendor": ""}
        elif role == "printer":
            h.probes["mdns"] = {"hostname": f"{(h.hostname or 'PRN'+last).split('.')[0]}.local",
                                "services": ["_ipp._tcp", "_pdl-datastream._tcp", "_scanner._tcp"],
                                "model": rng.choice(["MFC-L8900CDW", "LaserJet M507", "TASKalfa 3554ci"]), "vendor": h.vendor}
            h.probes["http"] = {"80": {"port": 80, "tls": False, "server": "HP HTTP Server", "title": "HP LaserJet", "realm": "", "cert_cn": "", "cert_san": []}}
            h.names["mdns"] = h.probes["mdns"]["hostname"]
        elif role == "camera":
            h.probes["http"] = {"443": {"port": 443, "tls": True, "server": "Boa/0.94", "title": "Web Service", "realm": "",
                                        "cert_cn": h.vendor.split()[0].lower() + "-cam", "cert_san": [], "cert_issuer": h.vendor, "cert_expires": "2027-01-01"}}
            h.probes["ssdp"] = {"server": f"{h.vendor} IP Camera", "st": "urn:schemas-upnp-org:device:Basic:1",
                                "manufacturer": h.vendor.split()[0], "model": "IPC-" + last, "device_type": "urn:...:Basic:1"}
        elif role == "phone":
            h.names.setdefault("sweep", h.hostname)
        elif role in ("nas",):
            h.probes["ssdp"] = {"server": "Linux/3.10 UPnP/1.0 Synology/1.0", "manufacturer": "Synology", "model": "DS920+",
                                "device_type": "urn:schemas-upnp-org:device:MediaServer:1", "friendly_name": h.hostname or "nas"}
            h.probes["http"] = {"5000": {"port": 5000, "tls": False, "server": "nginx", "title": "Synology DiskStation", "realm": "", "cert_cn": "", "cert_san": []}}
    # a Windows domain controller among the servers
    for ip, h in hosts:
        if (h.hostname or "").startswith("dc") or ip.endswith(".31"):
            h.probes["netbios"] = {"hostname": (h.hostname or "DC01").split(".")[0].upper(), "domain": "NORTHWIND",
                                   "user": "", "is_dc": True, "mac": h.mac, "names": []}
            h.names["netbios"] = h.probes["netbios"]["hostname"]
            break


if __name__ == "__main__":
    import sys

    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join("netmap", "data", "sample-campus.netmap")
    inv = build_project(out)
    print(out, inv.summary())
