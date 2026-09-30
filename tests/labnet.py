"""A simulated three-device lab (router, L3 distribution switch, L2 access switch) expressed as raw OID tables.

Used both by the in-memory fake SNMP session and to emit snmpsim .snmprec files, so the same
topology is asserted against pysnmp for real.

Addresses are <base>.0.0.x (router<->dist), <base>.1.0.x (VLAN10 users), <base>.2.0.x (VLAN20 servers).
"""
from __future__ import annotations

from netmap import oids as O

MAC_R1 = "00:11:22:33:44:01"
MAC_SW1 = "00:11:22:33:44:10"
MAC_SW2 = "00:11:22:33:44:20"
MAC_AP = "aa:bb:cc:00:00:01"
MAC_PHONE = "aa:bb:cc:00:00:02"
MAC_A = "de:ad:be:ef:00:0a"
MAC_B = "de:ad:be:ef:00:0b"
MAC_C = "de:ad:be:ef:00:0c"


def mac_bytes(m: str) -> bytes:
    return bytes.fromhex(m.replace(":", ""))


def mac_oid(m: str) -> str:
    return ".".join(str(b) for b in mac_bytes(m))


def ip_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def portlist(ports, size=40) -> bytes:
    """Q-BRIDGE PortList: one bit per bridge port, MSB of the first octet is port 1."""
    b = bytearray(size)
    for p in ports:
        b[(p - 1) // 8] |= 0x80 >> ((p - 1) % 8)
    return bytes(b)


class Dev:
    """OID -> (snmprec type, python value). Types: 2 int, 4 octets, 6 oid, 64 ipaddr, 66 gauge32, 67 timeticks."""

    def __init__(self):
        self.t: dict[str, tuple[int, object]] = {}

    def i(self, oid, v):
        self.t[oid] = (2, int(v))

    def u(self, oid, v):
        self.t[oid] = (66, int(v))

    def s(self, oid, v):
        self.t[oid] = (4, v.encode() if isinstance(v, str) else bytes(v))

    def o(self, oid, v):
        self.t[oid] = (6, v)

    def ip(self, oid, v):
        self.t[oid] = (64, v)

    def tt(self, oid, v):
        self.t[oid] = (67, int(v))

    def system(self, name, descr, soid, services, uptime=123456):
        self.s(O.SYS_DESCR, descr), self.o(O.SYS_OBJECTID, soid), self.tt(O.SYS_UPTIME, uptime)
        self.s(O.SYS_CONTACT, "netops@example.test"), self.s(O.SYS_NAME, name), self.s(O.SYS_LOCATION, "DC1"), self.i(O.SYS_SERVICES, services)

    def iface(self, idx, name, descr=None, mac=None, speed=1000, up=True, alias="", last_change=None, iftype=6):
        self.s(f"{O.IF_DESCR}.{idx}", descr or name), self.i(f"{O.IF_TYPE}.{idx}", iftype), self.i(f"{O.IF_SPEED}.{idx}", min(speed * 1_000_000, 4294967295))
        self.s(f"{O.IF_PHYS}.{idx}", mac_bytes(mac) if mac else b""), self.i(f"{O.IF_ADMIN}.{idx}", 1), self.i(f"{O.IF_OPER}.{idx}", 1 if up else 2)
        self.s(f"{O.IF_NAME}.{idx}", name), self.i(f"{O.IF_HIGHSPEED}.{idx}", speed), self.s(f"{O.IF_ALIAS}.{idx}", alias)
        self.tt(f"{O.IF_LAST_CHANGE}.{idx}", 100 * (idx + 10) if last_change is None else last_change)  # default: idx+10 seconds

    def addr(self, ip, idx, mask):
        self.ip(f"1.3.6.1.2.1.4.20.1.1.{ip}", ip), self.i(f"{O.IP_AD_IFINDEX}.{ip}", idx), self.ip(f"{O.IP_AD_NETMASK}.{ip}", mask)

    def arp(self, idx, ip, mac):
        self.i(f"1.3.6.1.2.1.4.22.1.1.{idx}.{ip}", idx), self.s(f"{O.ARP_PHYS}.{idx}.{ip}", mac_bytes(mac))
        self.ip(f"1.3.6.1.2.1.4.22.1.3.{idx}.{ip}", ip), self.i(f"{O.ARP_TYPE}.{idx}.{ip}", 3)

    def cidr_route(self, dest, mask, nh, idx, rtype=4, proto=2):
        sfx = f"{dest}.{mask}.0.{nh}"
        self.ip(f"1.3.6.1.2.1.4.24.4.1.1.{sfx}", dest), self.ip(f"1.3.6.1.2.1.4.24.4.1.2.{sfx}", mask), self.ip(f"1.3.6.1.2.1.4.24.4.1.4.{sfx}", nh)
        self.i(f"{O.CIDR_ROUTE_IFINDEX}.{sfx}", idx), self.i(f"{O.CIDR_ROUTE_TYPE}.{sfx}", rtype), self.i(f"{O.CIDR_ROUTE_PROTO}.{sfx}", proto)

    def lldp_local(self, chassis_mac, name, ports: dict):
        self.i(O.LLDP_LOC_CHASSIS_SUBTYPE, 4), self.s(O.LLDP_LOC_CHASSIS_ID, mac_bytes(chassis_mac)), self.s(O.LLDP_LOC_SYSNAME, name)
        for num, (pid, pdesc) in ports.items():
            self.i(f"{O.LLDP_LOC_PORT_ID_SUBTYPE}.{num}", 5), self.s(f"{O.LLDP_LOC_PORT_ID}.{num}", pid), self.s(f"{O.LLDP_LOC_PORT_DESC}.{num}", pdesc)

    def lldp_rem(self, local_port, rem_idx, chassis_mac, port_id, port_desc, sysname, sysdesc, caps: int, mgmt_ip=None, tm=0):
        sfx = f"{tm}.{local_port}.{rem_idx}"
        self.i(f"{O.LLDP_REM_CHASSIS_SUBTYPE}.{sfx}", 4), self.s(f"{O.LLDP_REM_CHASSIS_ID}.{sfx}", mac_bytes(chassis_mac))
        self.i(f"{O.LLDP_REM_PORT_SUBTYPE}.{sfx}", 5), self.s(f"{O.LLDP_REM_PORT_ID}.{sfx}", port_id), self.s(f"{O.LLDP_REM_PORT_DESC}.{sfx}", port_desc)
        self.s(f"{O.LLDP_REM_SYSNAME}.{sfx}", sysname), self.s(f"{O.LLDP_REM_SYSDESC}.{sfx}", sysdesc), self.s(f"{O.LLDP_REM_CAPS_ENABLED}.{sfx}", bytes([caps]))
        if mgmt_ip:
            self.i(f"{O.LLDP_REM_MAN_ADDR_IFSUBTYPE}.{sfx}.1.4.{mgmt_ip}", 2)
            self.i(f"1.0.8802.1.1.2.1.4.2.1.4.{sfx}.1.4.{mgmt_ip}", 0)

    def cdp(self, ifidx, dev_idx, device_id, port, platform, ip=None, caps=b"\x00\x00\x00\x29"):
        sfx = f"{ifidx}.{dev_idx}"
        self.i(f"{O.CDP_ADDR_TYPE}.{sfx}", 1 if ip else 0), self.s(f"{O.CDP_ADDR}.{sfx}", ip_bytes(ip) if ip else b"")
        self.s(f"{O.CDP_DEVICE_ID}.{sfx}", device_id), self.s(f"{O.CDP_DEVICE_PORT}.{sfx}", port), self.s(f"{O.CDP_PLATFORM}.{sfx}", platform), self.s(f"{O.CDP_CAPS}.{sfx}", caps)

    def bridge_ports(self, mapping: dict):
        for bp, ifidx in mapping.items():
            self.i(f"{O.DOT1D_BASE_PORT_IFINDEX}.{bp}", ifidx)

    def fdb_q(self, vlan, mac, bport):
        self.i(f"{O.DOT1Q_FDB_PORT}.{vlan}.{mac_oid(mac)}", bport), self.i(f"{O.DOT1Q_FDB_STATUS}.{vlan}.{mac_oid(mac)}", 3)

    def fdb_d(self, mac, bport):
        self.s(f"1.3.6.1.2.1.17.4.3.1.1.{mac_oid(mac)}", mac_bytes(mac)), self.i(f"{O.DOT1D_FDB_PORT}.{mac_oid(mac)}", bport), self.i(f"{O.DOT1D_FDB_STATUS}.{mac_oid(mac)}", 3)

    def vlan(self, vid, name):
        self.s(f"{O.DOT1Q_VLAN_NAME}.{vid}", name)

    def pvids(self, mapping: dict):
        for bport, vid in mapping.items():
            self.u(f"{O.DOT1Q_PVID}.{bport}", vid)

    def vlan_ports(self, vid, egress, untagged):
        self.s(f"{O.DOT1Q_VLAN_CUR_EGRESS}.0.{vid}", portlist(egress)), self.s(f"{O.DOT1Q_VLAN_CUR_UNTAGGED}.0.{vid}", portlist(untagged))

    def cisco_port(self, ifidx, access=None, trunk=False, native=1):
        """vlanTrunkPortTable row for any switchport; vmMembership row (static) for an access port."""
        self.i(f"{O.CISCO_TRUNK_NATIVE}.{ifidx}", native), self.i(f"{O.CISCO_TRUNK_STATUS}.{ifidx}", 1 if trunk else 2)
        if access is not None:
            self.i(f"1.3.6.1.4.1.9.9.68.1.2.2.1.1.{ifidx}", 1), self.i(f"{O.CISCO_VM_VLAN}.{ifidx}", access)

    def lag(self, members: dict):
        for ifidx, agg in members.items():
            self.i(f"{O.LAG_ATTACHED_AGG}.{ifidx}", agg)

    def counters(self, idx, in_oct=0, out_oct=0, in_err=0, out_err=0, in_dis=0, out_dis=0, duplex=3):
        self.i(f"{O.IF_HC_IN_OCTETS}.{idx}", in_oct), self.i(f"{O.IF_HC_OUT_OCTETS}.{idx}", out_oct)
        self.i(f"{O.IF_IN_ERRORS}.{idx}", in_err), self.i(f"{O.IF_OUT_ERRORS}.{idx}", out_err)
        self.i(f"{O.IF_IN_DISCARDS}.{idx}", in_dis), self.i(f"{O.IF_OUT_DISCARDS}.{idx}", out_dis)
        self.i(f"{O.DOT3_DUPLEX}.{idx}", duplex)

    def poe_port(self, port, status=3, cls=4, milliwatts=0, group=1):
        self.i(f"{O.PETH_PORT_STATUS}.{group}.{port}", status), self.i(f"{O.PETH_PORT_CLASS}.{group}.{port}", cls)
        if milliwatts:
            self.i(f"{O.CISCO_PETH_PORT_POWER}.{group}.{port}", milliwatts)

    def poe_main(self, budget, used, pse=1):
        self.i(f"{O.PETH_MAIN_POWER}.{pse}", budget), self.i(f"{O.PETH_MAIN_CONSUMPTION}.{pse}", used)

    def hsrp(self, ifidx, group, vip, state=6, priority=100):
        self.i(f"{O.HSRP_STATE}.{ifidx}.{group}", state), self.ip(f"{O.HSRP_VIP}.{ifidx}.{group}", vip), self.i(f"{O.HSRP_PRIORITY}.{ifidx}.{group}", priority)

    def vrrp(self, ifidx, vrid, vip, state=3, priority=100):
        self.i(f"{O.VRRP_STATE}.{ifidx}.{vrid}", state), self.i(f"{O.VRRP_PRIORITY}.{ifidx}.{vrid}", priority)
        self.i(f"{O.VRRP_ASSOIP}.{ifidx}.{vrid}.{vip}", 1)

    def ospf_nbr(self, addr, state=8):
        self.i(f"{O.OSPF_NBR_STATE}.{addr}.0", state)

    def bgp_peer(self, addr, remote_as, state=6):
        self.i(f"{O.BGP_PEER_STATE}.{addr}", state), self.ip(f"{O.BGP_PEER_REMADDR}.{addr}", addr), self.i(f"{O.BGP_PEER_REMAS}.{addr}", remote_as)

    def stp(self, root_mac, priority=32768, root_port=0, own_mac=None):
        root = priority.to_bytes(2, "big") + mac_bytes(root_mac)
        self.s(O.STP_DESIGNATED_ROOT, root), self.i(O.STP_ROOT_PORT, root_port), self.i(O.STP_PRIORITY, priority)
        self.s(O.BRIDGE_ADDRESS, mac_bytes(own_mac or root_mac))

    def ent(self, idx, cls, descr, name="", parent=0, model="", serial="", hw="", fw="", sw="", fru=False):
        self.s(f"{O.ENT_DESCR}.{idx}", descr), self.i(f"{O.ENT_CONTAINED_IN}.{idx}", parent), self.i(f"{O.ENT_CLASS}.{idx}", cls)
        self.s(f"{O.ENT_NAME}.{idx}", name), self.s(f"{O.ENT_HW_REV}.{idx}", hw), self.s(f"{O.ENT_FW_REV}.{idx}", fw), self.s(f"{O.ENT_SW_REV}.{idx}", sw)
        self.s(f"{O.ENT_SERIAL}.{idx}", serial), self.s(f"{O.ENT_MODEL}.{idx}", model), self.i(f"{O.ENT_IS_FRU}.{idx}", 1 if fru else 2)

    def entity(self, model, serial):
        self.ent(1, 3, model, "Chassis", model=model, serial=serial, fru=True)

    # --- outputs ---
    def values(self) -> dict[str, object]:
        return {k: v for k, (_, v) in self.t.items()}

    def snmprec(self) -> str:
        def key(oid):
            return tuple(int(x) for x in oid.split("."))

        lines = []
        for oid in sorted(self.t, key=key):
            typ, v = self.t[oid]
            if typ == 4:
                lines.append(f"{oid}|4x|{bytes(v).hex()}")
            else:
                lines.append(f"{oid}|{typ}|{v}")
        return "\n".join(lines) + "\n"


def build(base: str = "10") -> dict[str, Dev]:
    """Return {mgmt_ip: Dev}. `base` is the first octet, so tests can run on 127/8."""
    A = lambda net, h: f"{base}.{net}.0.{h}"  # noqa: E731
    R1_IP, SW1_IP, SW1_V10, SW1_V20, SW2_IP = A(0, 1), A(0, 2), A(1, 1), A(2, 1), A(1, 2)
    HOST_A, HOST_B, HOST_C, AP_IP, PHONE_IP = A(1, 50), A(1, 51), A(2, 10), A(1, 60), A(1, 90)
    WAN_IP, WAN_GW = "203.0.113.2", "203.0.113.1"

    # ---- R1: Cisco ISR, CDP only, static routes toward SW1 ----
    r1 = Dev()
    r1.system("core-rtr", "Cisco IOS Software, ISR4300 Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.6.4", "1.3.6.1.4.1.9.1.2068", 6)
    r1.entity("ISR4331/K9", "FDO2222R1XX")
    r1.iface(1, "Gi0/0/0", "GigabitEthernet0/0/0", MAC_R1, alias="to dist-sw1")
    r1.iface(2, "Gi0/0/1", "GigabitEthernet0/0/1", "00:11:22:33:44:02", alias="WAN")
    r1.addr(R1_IP, 1, "255.255.255.252"), r1.addr(WAN_IP, 2, "255.255.255.252")
    r1.arp(1, SW1_IP, MAC_SW1), r1.arp(2, WAN_GW, "00:00:5e:00:01:01")
    r1.cidr_route("0.0.0.0", "0.0.0.0", WAN_GW, 2, rtype=4, proto=3)
    r1.cidr_route(A(0, 0), "255.255.255.252", "0.0.0.0", 1, rtype=3)
    r1.cidr_route(A(1, 0), "255.255.255.0", SW1_IP, 1, proto=3)
    r1.cidr_route(A(2, 0), "255.255.255.0", SW1_IP, 1, proto=3)
    r1.cdp(1, 1, "dist-sw1.example.test", "GigabitEthernet1/0/1", "cisco WS-C3850-24T", SW1_IP)
    r1.bgp_peer(WAN_GW, 65001), r1.ospf_nbr(SW1_IP)

    # ---- SW1: Cisco 3850 L3 switch, LLDP + CDP, dot1q FDB, SVIs ----
    sw1 = Dev()
    sw1.system("dist-sw1", "Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4", "1.3.6.1.4.1.9.1.1745", 6)
    # a two-member stack as IOS-XE reports it; containers, the sensor, the copper port, the empty
    # SFP cage and the anonymous entity must not reach the asset register
    sw1.ent(1, 11, "c38xx Stack", "c38xx Stack")
    sw1.ent(1000, 3, "WS-C3850-24T-S", "Switch 1", 1, "WS-C3850-24T", "FOC1234SW1X", hw="V07", fw="16.12.2r", sw="16.12.4", fru=True)
    sw1.ent(1001, 5, "Switch 1 - Power Supply A Container", "Switch 1 - Power Supply A Container", 1000)
    sw1.ent(1002, 6, "Switch 1 - Power Supply A", "Switch 1 - Power Supply A", 1001, "PWR-C1-350WAC", "LIT21330ABC", hw="V02", fru=True)
    sw1.ent(1003, 7, "Switch 1 - FAN - T1 1", "Switch 1 - FAN - T1 1", 1000, fru=True)
    sw1.ent(1004, 8, "Switch 1 - Inlet Temp Sensor", "Switch 1 - Inlet", 1000)
    sw1.ent(1005, 9, "4x10G Uplink Module", "Switch 1 FRU Uplink Module 1", 1000, "C3850-NM-4-10G", "FOC2210X1AB", hw="V01", fru=True)
    sw1.ent(1006, 10, "GigabitEthernet1/0/1", "Gi1/0/1", 1000)
    sw1.ent(1007, 10, "TenGigabitEthernet1/1/1", "Te1/1/1", 1005)
    sw1.ent(1008, 10, "SFP-10GBase-SR", "subslot 1/1 transceiver 1", 1007, "SFP-10G-SR", "AVD2045K1LM", hw="V03", fru=True)
    sw1.ent(2000, 3, "WS-C3850-24T-S", "Switch 2", 1, "WS-C3850-24T", "FOC1234SW2Y", hw="V07", fw="16.12.2r", sw="16.12.4", fru=True)
    sw1.ent(2002, 6, "Switch 2 - Power Supply A", "Switch 2 - Power Supply A", 2000, "PWR-C1-350WAC", "LIT21330DEF", hw="V02", fru=True)
    sw1.ent(2010, 1, "", "", 2000)
    sw1.iface(1, "Gi1/0/1", "GigabitEthernet1/0/1", "00:11:22:33:44:11", alias="uplink core-rtr")
    sw1.iface(2, "Gi1/0/2", "GigabitEthernet1/0/2", "00:11:22:33:44:12", alias="to acc-sw2")
    sw1.iface(5, "Gi1/0/5", "GigabitEthernet1/0/5", "00:11:22:33:44:15", alias="srv-c", last_change=98765)
    sw1.iface(24, "Gi1/0/24", "GigabitEthernet1/0/24", "00:11:22:33:44:1f", alias="ap-1")
    sw1.iface(10, "Vlan10", "Vlan10", MAC_SW1)
    sw1.iface(20, "Vlan20", "Vlan20", MAC_SW1)
    sw1.iface(30, "Vlan30", "Vlan30", MAC_SW1)  # out-of-scope segment
    sw1.addr(SW1_IP, 1, "255.255.255.252"), sw1.addr(SW1_V10, 10, "255.255.255.0"), sw1.addr(SW1_V20, 20, "255.255.255.0")
    sw1.addr("192.168.99.1", 30, "255.255.255.0")
    sw1.arp(10, SW2_IP, MAC_SW2), sw1.arp(10, HOST_A, MAC_A), sw1.arp(10, HOST_B, MAC_B), sw1.arp(10, AP_IP, MAC_AP), sw1.arp(10, PHONE_IP, MAC_PHONE)
    sw1.arp(20, HOST_C, MAC_C), sw1.arp(1, R1_IP, MAC_R1), sw1.arp(30, "192.168.99.7", "de:ad:be:ef:99:07")
    sw1.cidr_route("0.0.0.0", "0.0.0.0", R1_IP, 1, proto=3)
    sw1.cidr_route(A(1, 0), "255.255.255.0", "0.0.0.0", 10, rtype=3)
    sw1.cidr_route(A(2, 0), "255.255.255.0", "0.0.0.0", 20, rtype=3)
    sw1.lldp_local(MAC_SW1, "dist-sw1", {2: ("Gi1/0/2", "GigabitEthernet1/0/2"), 24: ("Gi1/0/24", "GigabitEthernet1/0/24"), 30: ("Gi1/0/30", "GigabitEthernet1/0/30")})
    sw1.lldp_rem(2, 1, MAC_SW2, "24", "24", "acc-sw2", "HP J9772A 2530-48G-PoEP Switch", 0x20, mgmt_ip=SW2_IP)
    sw1.lldp_rem(24, 2, MAC_AP, MAC_AP, "eth0", "ap-lobby", "Ubiquiti UniFi AP U6-Pro", 0x10)  # wlan-ap, no mgmt address
    sw1.lldp_rem(30, 3, "00:11:22:33:44:99", "ge-0/0/0", "ge-0/0/0", "branch-fw", "Juniper SRX300", 0x08, mgmt_ip="192.168.99.2")  # out of scope
    sw1.cdp(1, 1, "core-rtr.example.test", "GigabitEthernet0/0/0", "cisco ISR4331/K9", R1_IP)
    sw1.bridge_ports({1: 1, 2: 2, 5: 5, 24: 24})
    for mac in (MAC_A, MAC_B, MAC_SW2, MAC_PHONE, "00:11:22:33:44:21", "00:11:22:33:44:22"):
        sw1.fdb_q(10, mac, 2)  # everything behind acc-sw2 shows on the uplink port
    sw1.fdb_q(10, MAC_AP, 24), sw1.fdb_q(20, MAC_C, 5)
    sw1.vlan(10, "USERS"), sw1.vlan(20, "SERVERS"), sw1.vlan(30, "BRANCH")
    sw1.hsrp(10, 1, A(1, 254), state=6, priority=110), sw1.ospf_nbr(R1_IP), sw1.stp(MAC_SW1, priority=24576, own_mac=MAC_SW1)
    sw1.counters(1, in_oct=1_000_000_000, out_oct=2_000_000_000, in_err=0, out_err=0)
    sw1.counters(2, in_oct=500_000_000, out_oct=400_000_000, in_err=1200, out_err=5, duplex=2)  # errors + half duplex
    sw1.counters(5, in_oct=10_000_000, out_oct=8_000_000)
    sw1.poe_main(740, 130), sw1.poe_port(24, status=3, cls=4, milliwatts=25500), sw1.poe_port(5, status=2, cls=0)
    # Gi1/0/1 is routed (no switchport row); the uplink to acc-sw2 trunks; server and AP ports are access
    sw1.cisco_port(2, trunk=True, native=1), sw1.cisco_port(5, access=20), sw1.cisco_port(24, access=10)

    # ---- SW2: HP ProCurve L2 access switch, LLDP only, dot1d FDB, uplink with many MACs ----
    sw2 = Dev()
    sw2.system("acc-sw2", "HP J9772A 2530-48G-PoEP Switch, revision YA.16.10.0016, ROM YA.15.20", "1.3.6.1.4.1.11.2.3.7.11.155", 2)
    sw2.entity("J9772A", "CN51ABC123")
    for p in (1, 2, 3, 4, 21, 22, 24):
        sw2.iface(p, str(p), str(p), f"00:11:22:33:55:{p:02x}", speed=1000)
    sw2.iface(289, "Trk1", "Trk1", "00:11:22:33:55:f1", speed=2000, alias="nas-01", iftype=161)  # ports 21-22, LACP
    sw2.iface(100, "VLAN10", "VLAN10", MAC_SW2, alias="mgmt")
    sw2.addr(SW2_IP, 100, "255.255.255.0")
    sw2.arp(100, SW1_V10, MAC_SW1), sw2.arp(100, PHONE_IP, MAC_PHONE)
    sw2.lldp_local(MAC_SW2, "acc-sw2", {24: ("24", "24"), 3: ("3", "3"), 4: ("4", "4"), 5: ("5", "5")})
    sw2.lldp_rem(24, 1, MAC_SW1, "Gi1/0/2", "GigabitEthernet1/0/2", "dist-sw1", "Cisco IOS-XE 16.12.4", 0x14, mgmt_ip=SW1_V10)
    sw2.lldp_rem(5, 2, MAC_PHONE, MAC_PHONE, "", "SEP" + MAC_PHONE.replace(":", "").upper(), "Cisco IP Phone 8845", 0x04, mgmt_ip=PHONE_IP)
    sw2.bridge_ports({1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 24: 24, 289: 289})  # LAG members are not bridge ports; Trk1 is
    sw2.fdb_d(MAC_A, 3), sw2.fdb_d(MAC_B, 4), sw2.fdb_d(MAC_PHONE, 5)
    for i in range(12):  # uplink learns many MACs
        sw2.fdb_d(f"00:11:22:33:66:{i:02x}", 24)
    sw2.fdb_d(MAC_SW1, 24), sw2.fdb_d(MAC_C, 24)
    sw2.stp(MAC_SW1, priority=24576, root_port=24, own_mac=MAC_SW2)
    # Q-BRIDGE: 3/4 are VLAN 10 access; 24 carries 10 and 20 tagged (trunk, native 1); port 2 has
    # one tagged voice VLAN on top of VLAN 1, which is still an access port; Trk1 is VLAN 20 access
    sw2.pvids({1: 1, 2: 1, 3: 10, 4: 10, 24: 1, 289: 20})
    sw2.vlan_ports(1, egress=[1, 2, 24], untagged=[1, 2, 24])
    sw2.vlan_ports(10, egress=[3, 4, 24], untagged=[3, 4])
    sw2.vlan_ports(20, egress=[2, 24, 289], untagged=[289])
    sw2.lag({1: 0, 2: 0, 3: 0, 4: 0, 21: 289, 22: 289, 24: 24})  # 0 or itself = not aggregated

    return {R1_IP: r1, SW1_IP: sw1, SW2_IP: sw2}


EXPECT = dict(devices=3, subnets_in_scope=3)
