"""Collect everything useful from one SNMP-speaking device."""
from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from typing import Optional

from . import oids as O
from .model import ArpEntry, Component, Device, FdbEntry, Interface, Neighbor, Route
from .snmp import SnmpError, SnmpSession
from .util import (
    enterprise_from_sysobjectid,
    ip_from_ints,
    is_usable_ip,
    mac_from_bytes,
    mac_from_ints,
    mask_to_prefix,
    oid_suffix,
    parse_os_version,
    plausible_mac,
    portlist_ports,
    to_text,
)

log = logging.getLogger("netmap.collect")

MAX_COMPONENTS = 500  # a fully loaded modular chassis reports thousands of entities
_ENT_ALWAYS = {"chassis", "module", "powerSupply", "fan", "stack", "cpu"}
_ENT_NEVER = {"backplane", "container", "sensor"}


def _int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


class CollectOptions:
    def __init__(self, fdb: bool = True, cisco_vlan_fdb: bool = False, routes: bool = True, arp: bool = True, topology: bool = True, health: bool = True, max_vlans: int = 64):
        self.fdb = fdb
        self.cisco_vlan_fdb = cisco_vlan_fdb
        self.routes = routes
        self.arp = arp
        self.topology = topology  # FHRP (HSRP/VRRP), OSPF/BGP neighbours, spanning-tree root
        self.health = health  # interface counters/errors/duplex and PoE
        self.max_vlans = max_vlans


async def _safe(dev: Device, label: str, coro):
    try:
        return await coro
    except SnmpError as e:
        dev.errors.append(f"{label}: {e}")
        log.debug("%s: %s failed: %s", dev.id, label, e)
        return None
    except Exception as e:  # noqa: BLE001 - never let one table kill the device
        dev.errors.append(f"{label}: {type(e).__name__}: {e}")
        log.debug("%s: %s crashed", dev.id, label, exc_info=True)
        return None


def classify_role(dev: Device) -> str:
    d = dev.sysdescr.lower()
    l2 = bool(dev.services & 2)
    l3 = bool(dev.services & 4)
    if re.search(r"fortigate|palo alto|pan-os|checkpoint|check point|\basa\b|adaptive security|sonicwall|pfsense|opnsense|firewall|\bsrx\d", d):
        return "firewall"
    if re.search(r"wireless|access point|aironet|unifi|aruba (ap|instant)|meraki mr|lightweight ap|\bwlc\b", d):
        return "wireless"
    if re.search(r"printer|laserjet|jetdirect|officejet|xerox|ricoh|kyocera|konica|lexmark", d):
        return "printer"
    is_router = re.search(r"\brouter\b|\bisr\d|\basr\d|\bc\d{3,4}\b.*router|mikrotik|routeros|junos.*\bmx\d|edgerouter|vyos|\bccr\d", d)
    is_switch = re.search(r"switch|catalyst|nexus|\bex\d{4}|\bqfx|procurve|comware|aruba \d{4}|\bws-c|\bc9[235]00", d)
    if is_router and not is_switch:
        return "router"
    if is_switch or dev.fdb:
        # sysServices says "routing" on nearly every managed switch, even an access switch whose
        # only address is its management SVI. Call it L3 only with evidence that it routes:
        # addresses on two or more interfaces, or routes other than connected and default.
        addressed = sum(1 for i in dev.interfaces if i.ips)
        learned = any(r.dest != "0.0.0.0/0" and r.type != 3 and r.nexthop not in ("", "0.0.0.0") for r in dev.routes)
        return "l3switch" if l3 and (addressed >= 2 or learned) else "switch"
    if re.search(r"vmware esx|esxi|\bwindows\b|\blinux\b|freebsd|ubuntu|debian|centos|red hat|net-snmp", d):
        return "server"
    if l3:
        return "router"
    if l2 or any(n.proto in ("lldp", "cdp") for n in dev.neighbors):
        return "switch"
    return "unknown"


def _vendor(sysobjectid: str, sysdescr: str) -> str:
    ent = enterprise_from_sysobjectid(sysobjectid)
    if ent and ent in O.ENTERPRISES:
        return O.ENTERPRISES[ent]
    d = sysdescr.lower()
    for kw, v in (("cisco", "Cisco"), ("juniper", "Juniper"), ("arista", "Arista"), ("fortinet", "Fortinet"), ("mikrotik", "MikroTik"), ("hp ", "HP"), ("aruba", "Aruba"), ("ubiquiti", "Ubiquiti"), ("linux", "Linux"), ("windows", "Microsoft")):
        if kw in d:
            return v
    return f"enterprise-{ent}" if ent else ""


async def collect_system(sess: SnmpSession, dev: Device, sysinfo: Optional[dict] = None) -> None:
    r = await sess.get(O.SYS_DESCR, O.SYS_OBJECTID, O.SYS_UPTIME, O.SYS_CONTACT, O.SYS_NAME, O.SYS_LOCATION, O.SYS_SERVICES)
    dev.sysdescr = to_text(r.get(O.SYS_DESCR))
    dev.sysobjectid = to_text(r.get(O.SYS_OBJECTID))
    dev.uptime_s = int(r.get(O.SYS_UPTIME) or 0) // 100
    dev.contact = to_text(r.get(O.SYS_CONTACT))
    dev.name = to_text(r.get(O.SYS_NAME))
    dev.location = to_text(r.get(O.SYS_LOCATION))
    dev.services = int(r.get(O.SYS_SERVICES) or 0)
    dev.vendor = _vendor(dev.sysobjectid, dev.sysdescr)
    dev.os_version = parse_os_version(dev.sysdescr, dev.vendor)
    oid = O.OS_VERSION_OIDS.get(dev.vendor)
    if oid and not dev.os_version:
        # FortiGate, PAN-OS and RouterOS put only the model in sysDescr; one GET to their own MIB
        raw = to_text((await _safe(dev, "os version", sess.get(oid)) or {}).get(oid))
        dev.os_version = parse_os_version(raw, dev.vendor) or raw[:40]


async def collect_entity(sess: SnmpSession, dev: Device) -> None:
    """ENTITY-MIB: the primary chassis' model/serial for the device, plus the parts an asset
    register tracks - stack members, modules, supplies, fans, CPUs and transceivers.

    Containers, sensors, backplanes and bare ports are dropped: a 48-port stack reports
    hundreds of slots and probes nobody inventories. A port entity is kept only when it has
    a model or serial, which is what a pluggable optic looks like. `parent` skips dropped
    entities, so a supply points at its chassis rather than at the empty slot it sits in.
    """
    classes = await sess.walk_map(O.ENT_CLASS)
    if not classes:
        return
    col = {}
    for key, label, oid in (
        ("descr", "entPhysicalDescr", O.ENT_DESCR), ("parent", "entPhysicalContainedIn", O.ENT_CONTAINED_IN),
        ("name", "entPhysicalName", O.ENT_NAME), ("hw", "entPhysicalHardwareRev", O.ENT_HW_REV),
        ("fw", "entPhysicalFirmwareRev", O.ENT_FW_REV), ("sw", "entPhysicalSoftwareRev", O.ENT_SW_REV),
        ("serial", "entPhysicalSerialNum", O.ENT_SERIAL), ("model", "entPhysicalModelName", O.ENT_MODEL),
        ("fru", "entPhysicalIsFRU", O.ENT_IS_FRU),
    ):
        col[key] = await _safe(dev, label, sess.walk_map(oid)) or {}
    model, serial = col["model"], col["serial"]
    chassis = [k for k, v in classes.items() if _int(v) == 3] or list(classes)[:1]
    idx = chassis[0]
    dev.model, dev.serial = to_text(model.get(idx)), to_text(serial.get(idx))
    if not dev.serial:
        k = next((k for k, v in serial.items() if to_text(v)), None)
        if k is not None:
            dev.serial = to_text(serial[k])
            dev.model = dev.model or to_text(model.get(k))

    comps = []
    for k, v in classes.items():
        cls = O.ENT_CLASSES.get(_int(v), "other")
        if cls in _ENT_NEVER or not k.isdigit():
            continue
        c = Component(
            index=int(k), cls=cls, name=to_text(col["name"].get(k)), descr=to_text(col["descr"].get(k)),
            model=to_text(model.get(k)), serial=to_text(serial.get(k)), hw_rev=to_text(col["hw"].get(k)),
            fw_rev=to_text(col["fw"].get(k)), sw_rev=to_text(col["sw"].get(k)), fru=_int(col["fru"].get(k)) == 1,
        )
        identified = c.model or c.serial or (cls in _ENT_ALWAYS and (c.name or c.descr))
        if identified:
            comps.append(c)
    if len(comps) > MAX_COMPONENTS:
        log.debug("%s: %d components, keeping %d", dev.id, len(comps), MAX_COMPONENTS)
        keep = {id(c) for c in sorted(comps, key=lambda c: c.cls == "port")[:MAX_COMPONENTS]}  # optics go first
        comps = [c for c in comps if id(c) in keep]
    kept = {c.index for c in comps}
    for c in comps:
        p, seen = _int(col["parent"].get(str(c.index))), {c.index}
        while p and p not in kept and p not in seen:
            seen.add(p)
            p = _int(col["parent"].get(str(p)))
        c.parent = p if p in kept and p != c.index else 0
    dev.components = comps


async def collect_interfaces(sess: SnmpSession, dev: Device) -> None:
    descr = await sess.walk_map(O.IF_DESCR)
    if not descr:
        return
    types = await sess.walk_map(O.IF_TYPE)
    speed = await sess.walk_map(O.IF_SPEED)
    phys = await sess.walk_map(O.IF_PHYS)
    admin = await sess.walk_map(O.IF_ADMIN)
    oper = await sess.walk_map(O.IF_OPER)
    names = await _safe(dev, "ifName", sess.walk_map(O.IF_NAME)) or {}
    hispeed = await _safe(dev, "ifHighSpeed", sess.walk_map(O.IF_HIGHSPEED)) or {}
    alias = await _safe(dev, "ifAlias", sess.walk_map(O.IF_ALIAS)) or {}
    last = await _safe(dev, "ifLastChange", sess.walk_map(O.IF_LAST_CHANGE)) or {}
    for k, d in descr.items():
        idx = int(k)
        mbps = int(hispeed.get(k) or 0) or int(speed.get(k) or 0) // 1_000_000
        mac = mac_from_bytes(phys.get(k)) if isinstance(phys.get(k), bytes) else None
        i = Interface(
            index=idx,
            name=to_text(names.get(k)),
            descr=to_text(d),
            alias=to_text(alias.get(k)),
            mac=mac,
            type=int(types.get(k) or 0),
            speed_mbps=mbps,
            admin_up=int(admin.get(k) or 0) == 1,
            oper_up=int(oper.get(k) or 0) == 1,
            last_change_s=_int(last.get(k)) // 100,
        )
        dev.interfaces.append(i)
        if mac and mac != "00:00:00:00:00:00" and mac not in dev.macs:
            dev.macs.append(mac)


async def collect_ip_addrs(sess: SnmpSession, dev: Device) -> None:
    ifidx = await sess.walk_map(O.IP_AD_IFINDEX)
    masks = await sess.walk_map(O.IP_AD_NETMASK)
    for ip, idx in ifidx.items():
        if not is_usable_ip(ip):
            continue
        mask = masks.get(ip)
        try:
            prefix = mask_to_prefix(str(mask)) if mask else 32
        except ValueError:
            prefix = 32
        cidr = f"{ip}/{prefix}"
        iface = dev.iface(int(idx)) if idx is not None else None
        if iface is None:
            iface = Interface(index=int(idx or 0), name=f"if{idx}")
            dev.interfaces.append(iface)
        if cidr not in iface.ips:
            iface.ips.append(cidr)
        if ip not in dev.ips:
            dev.ips.append(ip)


async def collect_arp(sess: SnmpSession, dev: Device) -> None:
    phys = await sess.walk(O.ARP_PHYS)
    for oid, val in phys:
        parts = oid_suffix(oid, O.ARP_PHYS)
        if len(parts) != 5:
            continue
        ip = ip_from_ints(parts[1:])
        mac = mac_from_bytes(val) if isinstance(val, bytes) else None
        if ip and mac and is_usable_ip(ip) and plausible_mac(mac):
            dev.arp.append(ArpEntry(if_index=parts[0], ip=ip, mac=mac))


async def collect_routes(sess: SnmpSession, dev: Device) -> None:
    cidr = await sess.walk(O.CIDR_ROUTE_IFINDEX)
    seen = set()
    if cidr:
        types = dict(await sess.walk(O.CIDR_ROUTE_TYPE))
        protos = dict(await sess.walk(O.CIDR_ROUTE_PROTO))
        for oid, ifidx in cidr:
            p = oid_suffix(oid, O.CIDR_ROUTE_IFINDEX)
            if len(p) != 13:
                continue
            dest, mask, nh = ip_from_ints(p[0:4]), ip_from_ints(p[4:8]), ip_from_ints(p[9:13])
            if not dest or not mask or not nh:
                continue
            key = (dest, mask, nh)
            if key in seen:
                continue
            seen.add(key)
            suffix = oid[len(O.CIDR_ROUTE_IFINDEX) :]
            dev.routes.append(
                Route(
                    dest=f"{dest}/{mask_to_prefix(mask)}",
                    nexthop=nh,
                    if_index=int(ifidx) if ifidx else None,
                    type=int(types.get(O.CIDR_ROUTE_TYPE + suffix) or 0),
                    proto=int(protos.get(O.CIDR_ROUTE_PROTO + suffix) or 0),
                )
            )
        return
    # RFC1213 fallback
    nexthops = await sess.walk_map(O.ROUTE_NEXTHOP)
    if not nexthops:
        return
    masks = await sess.walk_map(O.ROUTE_MASK)
    ifs = await sess.walk_map(O.ROUTE_IFINDEX)
    types = await sess.walk_map(O.ROUTE_TYPE)
    protos = await sess.walk_map(O.ROUTE_PROTO)
    for dest, nh in nexthops.items():
        mask = masks.get(dest) or "255.255.255.255"
        try:
            prefix = mask_to_prefix(str(mask))
        except ValueError:
            continue
        dev.routes.append(
            Route(dest=f"{dest}/{prefix}", nexthop=str(nh), if_index=int(ifs.get(dest) or 0) or None, type=int(types.get(dest) or 0), proto=int(protos.get(dest) or 0))
        )


def _lldp_id(subtype, raw, kind: str = "chassis") -> str:
    """Decode lldp{Loc,Rem}{Chassis,Port}Id according to its subtype.

    chassis: 1 component 2 ifAlias 3 portComponent 4 macAddress 5 networkAddress 6 ifName 7 local
    port:    1 ifAlias 2 portComponent 3 macAddress 4 networkAddress 5 ifName 6 agentCircuitId 7 local
    """
    if raw is None:
        return ""
    if not isinstance(raw, bytes):
        return str(raw)
    mac_st, net_st = (4, 5) if kind == "chassis" else (3, 4)
    subtype = int(subtype or 0)
    if subtype == mac_st and len(raw) == 6:
        return mac_from_bytes(raw) or ""
    if subtype == net_st and raw:
        if raw[0] == 1 and len(raw) == 5:
            return ".".join(str(b) for b in raw[1:])
        return raw.hex()
    txt = raw.decode("utf-8", "replace").strip("\x00").strip()
    if txt and txt.isprintable():
        return txt
    if len(raw) == 6:
        return mac_from_bytes(raw) or raw.hex()
    return raw.hex()


def _lldp_caps(raw) -> str:
    if not isinstance(raw, bytes) or not raw:
        return ""
    bits = raw[0]
    names = ["other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station"]
    return ",".join(n for i, n in enumerate(names) if bits & (0x80 >> i))


def _find_if_by_port(dev: Device, *candidates: str) -> Optional[int]:
    for c in candidates:
        if not c:
            continue
        cl = c.lower()
        for i in dev.interfaces:
            if cl in (i.name.lower(), i.descr.lower()) or (i.mac and cl == i.mac):
                return i.index
    return None


async def collect_lldp(sess: SnmpSession, dev: Device) -> None:
    loc = await sess.get(O.LLDP_LOC_CHASSIS_SUBTYPE, O.LLDP_LOC_CHASSIS_ID)
    dev.lldp_chassis_id = _lldp_id(loc.get(O.LLDP_LOC_CHASSIS_SUBTYPE), loc.get(O.LLDP_LOC_CHASSIS_ID), "chassis")
    rem_sys = await sess.walk(O.LLDP_REM_SYSNAME)
    if not rem_sys:
        return
    loc_port_id = await _safe(dev, "lldpLocPortId", sess.walk_map(O.LLDP_LOC_PORT_ID)) or {}
    loc_port_desc = await _safe(dev, "lldpLocPortDesc", sess.walk_map(O.LLDP_LOC_PORT_DESC)) or {}
    chassis_st = await sess.walk_map(O.LLDP_REM_CHASSIS_SUBTYPE)
    chassis_id = await sess.walk_map(O.LLDP_REM_CHASSIS_ID)
    port_st = await sess.walk_map(O.LLDP_REM_PORT_SUBTYPE)
    port_id = await sess.walk_map(O.LLDP_REM_PORT_ID)
    port_desc = await sess.walk_map(O.LLDP_REM_PORT_DESC)
    sysdesc = await _safe(dev, "lldpRemSysDesc", sess.walk_map(O.LLDP_REM_SYSDESC)) or {}
    caps = await _safe(dev, "lldpRemSysCapEnabled", sess.walk_map(O.LLDP_REM_CAPS_ENABLED)) or {}
    man = await _safe(dev, "lldpRemManAddr", sess.walk(O.LLDP_REM_MAN_ADDR_IFSUBTYPE)) or []
    mgmt: dict[str, list[str]] = {}
    for oid, _ in man:
        p = oid_suffix(oid, O.LLDP_REM_MAN_ADDR_IFSUBTYPE)
        # timeMark.localPortNum.remIndex.addrSubtype.addrLen.addr...
        if len(p) >= 9 and p[3] == 1 and p[4] == 4:
            ip = ip_from_ints(p[5:9])
            if ip and is_usable_ip(ip):
                mgmt.setdefault(".".join(map(str, p[:3])), []).append(ip)
    for oid, name in rem_sys:
        idx = oid[len(O.LLDP_REM_SYSNAME) + 1 :]
        parts = idx.split(".")
        if len(parts) != 3:
            continue
        local_port_num = parts[1]
        lp_name = to_text(loc_port_desc.get(local_port_num)) or to_text(loc_port_id.get(local_port_num))
        lif = _find_if_by_port(dev, to_text(loc_port_id.get(local_port_num)), to_text(loc_port_desc.get(local_port_num)))
        if lif is None and dev.iface(int(local_port_num)):
            lif = int(local_port_num)
        n = Neighbor(
            proto="lldp",
            local_if_index=lif,
            local_port=dev.iface_label(lif) if lif is not None else lp_name,
            remote_name=to_text(name),
            remote_port=_lldp_id(port_st.get(idx), port_id.get(idx), "port") or to_text(port_desc.get(idx)),
            remote_chassis_id=_lldp_id(chassis_st.get(idx), chassis_id.get(idx), "chassis"),
            remote_mgmt_ips=mgmt.get(idx, []),
            remote_platform=to_text(sysdesc.get(idx))[:120],
            remote_caps=_lldp_caps(caps.get(idx)),
        )
        dev.neighbors.append(n)


def _cdp_caps(raw) -> str:
    if not isinstance(raw, bytes) or not raw:
        return ""
    bits = int.from_bytes(raw[-1:], "big")
    names = ["router", "bridge", "srcbridge", "switch", "host", "igmp", "repeater", "phone"]
    return ",".join(n for i, n in enumerate(names) if bits & (1 << i))


async def collect_cdp(sess: SnmpSession, dev: Device) -> None:
    ids = await sess.walk(O.CDP_DEVICE_ID)
    if not ids:
        return
    addr_t = await sess.walk_map(O.CDP_ADDR_TYPE)
    addr = await sess.walk_map(O.CDP_ADDR)
    port = await sess.walk_map(O.CDP_DEVICE_PORT)
    plat = await sess.walk_map(O.CDP_PLATFORM)
    caps = await _safe(dev, "cdpCacheCapabilities", sess.walk_map(O.CDP_CAPS)) or {}
    for oid, did in ids:
        idx = oid[len(O.CDP_DEVICE_ID) + 1 :]
        parts = idx.split(".")
        if len(parts) != 2:
            continue
        lif = int(parts[0])
        ips = []
        a = addr.get(idx)
        if int(addr_t.get(idx) or 0) == 1 and isinstance(a, bytes) and len(a) == 4:
            ip = ".".join(str(b) for b in a)
            if is_usable_ip(ip):
                ips.append(ip)
        dev.neighbors.append(
            Neighbor(
                proto="cdp",
                local_if_index=lif,
                local_port=dev.iface_label(lif),
                remote_name=to_text(did),
                remote_port=to_text(port.get(idx)),
                remote_mgmt_ips=ips,
                remote_platform=to_text(plat.get(idx)),
                remote_caps=_cdp_caps(caps.get(idx)),
            )
        )


async def _fdb_dot1d(sess: SnmpSession, dev: Device, vlan: Optional[int], bp: Optional[dict] = None) -> int:
    ports = await sess.walk(O.DOT1D_FDB_PORT)
    if not ports:
        return 0
    if bp is None:  # a per-VLAN context has its own bridge-port table
        bp = await sess.walk_map(O.DOT1D_BASE_PORT_IFINDEX)
    status = dict(await _safe(dev, "dot1dTpFdbStatus", sess.walk(O.DOT1D_FDB_STATUS)) or [])
    n = 0
    for oid, port in ports:
        p = oid_suffix(oid, O.DOT1D_FDB_PORT)
        mac = mac_from_ints(p)
        if not mac or not port:
            continue
        st = status.get(O.DOT1D_FDB_STATUS + oid[len(O.DOT1D_FDB_PORT) :])
        if st is not None and int(st) != 3:  # 3 = learned
            continue
        ifidx = bp.get(str(port))
        dev.fdb.append(FdbEntry(mac=mac, if_index=int(ifidx) if ifidx else None, vlan=vlan))
        n += 1
    return n


async def collect_fdb(sess: SnmpSession, dev: Device, opts: CollectOptions, bp: Optional[dict] = None) -> None:
    """Bridge forwarding table. `bp` is dot1dBasePortIfIndex if the caller already walked it."""
    # Q-BRIDGE first: includes VLAN in the index
    q = await _safe(dev, "dot1qTpFdbPort", sess.walk(O.DOT1Q_FDB_PORT)) or []
    if q:
        if bp is None:
            bp = await sess.walk_map(O.DOT1D_BASE_PORT_IFINDEX)
        status = dict(await _safe(dev, "dot1qTpFdbStatus", sess.walk(O.DOT1Q_FDB_STATUS)) or [])
        for oid, port in q:
            p = oid_suffix(oid, O.DOT1Q_FDB_PORT)
            if len(p) != 7 or not port:
                continue
            st = status.get(O.DOT1Q_FDB_STATUS + oid[len(O.DOT1Q_FDB_PORT) :])
            if st is not None and int(st) != 3:
                continue
            mac = mac_from_ints(p[1:])
            ifidx = bp.get(str(port))
            dev.fdb.append(FdbEntry(mac=mac, if_index=int(ifidx) if ifidx else None, vlan=p[0]))
        if dev.fdb:
            return
    n = await _safe(dev, "dot1dTpFdb", _fdb_dot1d(sess, dev, None, bp))
    if opts.cisco_vlan_fdb and dev.vendor == "Cisco" and dev.vlans:
        # Cisco IOS keeps a separate bridge per VLAN; walk each with community@vlan / vlan-N context
        vlans = [v for v in sorted(dev.vlans) if v not in range(1002, 1006)][: opts.max_vlans]
        for v in vlans:
            await _safe(dev, f"fdb vlan {v}", _fdb_dot1d(sess.with_vlan(v), dev, v))
        # drop the context-less entries if per-vlan gave us anything with vlan set
        if any(f.vlan is not None for f in dev.fdb):
            dev.fdb = [f for f in dev.fdb if f.vlan is not None]


async def collect_vlans(sess: SnmpSession, dev: Device) -> None:
    q = await _safe(dev, "dot1qVlanStaticName", sess.walk_map(O.DOT1Q_VLAN_NAME)) or {}
    for k, v in q.items():
        try:
            dev.vlans[int(k)] = to_text(v)
        except ValueError:
            pass
    if dev.vlans:
        return
    vtp = await _safe(dev, "vtpVlanName", sess.walk(O.VTP_VLAN_NAME)) or []
    for oid, v in vtp:
        p = oid_suffix(oid, O.VTP_VLAN_NAME)
        if len(p) == 2:
            dev.vlans[p[1]] = to_text(v)


async def _cisco_port_vlans(sess: SnmpSession, dev: Device, ports: dict[int, Interface]) -> bool:
    """Cisco IOS keeps per-port VLANs in its own MIBs keyed by ifIndex. True if it answered."""
    status = await _safe(dev, "vlanTrunkPortDynamicStatus", sess.walk_map(O.CISCO_TRUNK_STATUS)) or {}
    access = await _safe(dev, "vmVlan", sess.walk_map(O.CISCO_VM_VLAN)) or {}
    trunks = {k for k, v in status.items() if _int(v) == 1}
    native = (await _safe(dev, "vlanTrunkPortNativeVlan", sess.walk_map(O.CISCO_TRUNK_NATIVE)) or {}) if trunks else {}
    for k in trunks:
        if i := ports.get(_int(k)):
            i.mode, i.vlan = "trunk", _int(native.get(k)) or None
    for k, v in access.items():
        if (i := ports.get(_int(k))) and k not in trunks and _int(v):
            i.mode, i.vlan = "access", _int(v)
    return bool(trunks or access)


async def _qbridge_port_vlans(sess: SnmpSession, dev: Device, ports: dict[int, Interface], bp: dict) -> None:
    """Q-BRIDGE: PVID per bridge port. A port sending tagged frames for more than one VLAN is
    a trunk; exactly one tagged VLAN on top of an untagged one is an access port with a voice
    VLAN, which is how most phone ports look."""
    pvid = await _safe(dev, "dot1qPvid", sess.walk_map(O.DOT1Q_PVID)) or {}
    if not pvid:
        return
    egress = await _safe(dev, "dot1qVlanCurrentEgressPorts", sess.walk_map(O.DOT1Q_VLAN_CUR_EGRESS)) or {}
    untagged = await _safe(dev, "dot1qVlanCurrentUntaggedPorts", sess.walk_map(O.DOT1Q_VLAN_CUR_UNTAGGED)) or {}
    tagged: dict[int, set[int]] = defaultdict(set)
    for k, ports_out in egress.items():  # index TimeMark.VlanIndex
        vid = _int(k.rsplit(".", 1)[-1])
        for p in portlist_ports(ports_out) - portlist_ports(untagged.get(k)):
            tagged[p].add(vid)
    for k, v in pvid.items():
        if i := ports.get(_int(bp.get(k))):
            i.vlan = _int(v) or None
            i.mode = "trunk" if len(tagged[_int(k)]) > 1 else "access"


async def collect_port_vlans(sess: SnmpSession, dev: Device, bp: dict) -> None:
    """Access/native VLAN and access-vs-trunk mode per switch port.

    Asked only of devices that look like a switch - a bridge-port table, VLANs or learned
    MACs - so routers and servers do not pay for the walks. Cisco IOS answers its own MIBs
    and not Q-BRIDGE's port table; everyone else (Cisco's small-business line included)
    answers dot1qPvid, keyed by bridge port rather than ifIndex.
    """
    if not (bp or dev.vlans or dev.fdb):
        return
    ports = {i.index: i for i in dev.interfaces}
    if dev.vendor == "Cisco" and await _cisco_port_vlans(sess, dev, ports):
        return
    if bp:
        await _qbridge_port_vlans(sess, dev, ports, bp)


async def collect_lag(sess: SnmpSession, dev: Device) -> None:
    """LAG membership from IEEE8023-LAG-MIB: each member names its aggregator's ifIndex.

    Walked on every device, not just switches: firewalls, routers and hypervisor uplinks
    bundle links too. A port that is not aggregated reports 0 or its own ifIndex.
    """
    agg = await sess.walk_map(O.LAG_ATTACHED_AGG)
    ports = {i.index: i for i in dev.interfaces}
    for k, v in agg.items():
        member, a = _int(k), _int(v)
        if (i := ports.get(member)) and a and a != member:
            i.lag = dev.iface_label(a)


DUPLEX = {1: "", 2: "half", 3: "full"}
PETH_STATUS = {1: "disabled", 2: "searching", 3: "delivering", 4: "fault", 5: "test", 6: "fault"}


async def collect_counters(sess: SnmpSession, dev: Device) -> None:
    """Per-interface traffic counters and error/discard counters, and duplex. Utilisation and
    error rates are derived later by comparing two scans (a single read is only a snapshot)."""
    ports = {i.index: i for i in dev.interfaces}
    if not ports:
        return
    hc_in = await _safe(dev, "ifHCInOctets", sess.walk_map(O.IF_HC_IN_OCTETS)) or {}
    hc_out = await _safe(dev, "ifHCOutOctets", sess.walk_map(O.IF_HC_OUT_OCTETS)) or {}
    in_oct = hc_in or (await _safe(dev, "ifInOctets", sess.walk_map(O.IF_IN_OCTETS)) or {})
    out_oct = hc_out or (await _safe(dev, "ifOutOctets", sess.walk_map(O.IF_OUT_OCTETS)) or {})
    ie = await _safe(dev, "ifInErrors", sess.walk_map(O.IF_IN_ERRORS)) or {}
    oe = await _safe(dev, "ifOutErrors", sess.walk_map(O.IF_OUT_ERRORS)) or {}
    idis = await _safe(dev, "ifInDiscards", sess.walk_map(O.IF_IN_DISCARDS)) or {}
    odis = await _safe(dev, "ifOutDiscards", sess.walk_map(O.IF_OUT_DISCARDS)) or {}
    dup = await _safe(dev, "dot3Duplex", sess.walk_map(O.DOT3_DUPLEX)) or {}
    now = time.time()
    for k, i in ((str(idx), iface) for idx, iface in ports.items()):
        i.in_octets = _int(in_oct.get(k))
        i.out_octets = _int(out_oct.get(k))
        i.in_errors = _int(ie.get(k))
        i.out_errors = _int(oe.get(k))
        i.in_discards = _int(idis.get(k))
        i.out_discards = _int(odis.get(k))
        i.counters_at = now
        i.duplex = DUPLEX.get(_int(dup.get(k)), "")


async def collect_poe(sess: SnmpSession, dev: Device) -> None:
    """Power over Ethernet: the switch's total budget and draw, and per-port status/class/watts.

    The device totals (pethMainPse*) are standard and reliable. Per-port entries are keyed by
    a PoE group.port index, which this maps to an interface by port number - best effort, since
    there is no standard PoE-port-to-ifIndex OID."""
    budget = await _safe(dev, "pethMainPsePower", sess.walk(O.PETH_MAIN_POWER)) or []
    used = await _safe(dev, "pethMainPseConsumptionPower", sess.walk(O.PETH_MAIN_CONSUMPTION)) or []
    dev.poe_budget_w = float(sum(_int(v) for _o, v in budget))
    dev.poe_used_w = float(sum(_int(v) for _o, v in used))
    status = await _safe(dev, "pethPsePortStatus", sess.walk_map(O.PETH_PORT_STATUS)) or {}
    if not status and not budget:
        return
    cls = await _safe(dev, "pethPsePortClass", sess.walk_map(O.PETH_PORT_CLASS)) or {}
    power = await _safe(dev, "cpeExtPsePortPwrConsumption", sess.walk_map(O.CISCO_PETH_PORT_POWER)) or {}
    by_index = {i.index: i for i in dev.interfaces}
    by_portnum = {}
    for i in dev.interfaces:  # last number in the name, e.g. Gi1/0/24 -> 24
        m = re.search(r"(\d+)\s*$", i.name or i.descr or "")
        if m:
            by_portnum.setdefault(int(m.group(1)), i)
    for key, st in status.items():
        port = int(key.split(".")[-1])
        iface = by_index.get(port) or by_portnum.get(port)
        if iface is None:
            continue
        iface.poe_status = PETH_STATUS.get(_int(st), "")
        c = _int(cls.get(key))
        iface.poe_class = str(c - 1) if c else ""  # 1..5 -> class 0..4
        iface.poe_watts = round(_int(power.get(key)) / 1000.0, 1)


def apply_counter_deltas(old: Device, new: Device) -> None:
    """Turn two counter snapshots into utilisation % and error rate on the new interfaces.

    Called on a rescan, when we have the previous scan's counters. Handles 64-bit wrap by
    ignoring a negative delta."""
    prev = {i.index: i for i in old.interfaces}
    for i in new.interfaces:
        o = prev.get(i.index)
        if o is None or not o.counters_at or not i.counters_at:
            continue
        dt = i.counters_at - o.counters_at
        if dt < 1:
            continue
        speed_bps = (i.speed_mbps or 0) * 1_000_000
        for cur, was, attr in ((i.in_octets, o.in_octets, "in_util_pct"), (i.out_octets, o.out_octets, "out_util_pct")):
            d = cur - was
            if d >= 0 and speed_bps:
                setattr(i, attr, round(min(100.0, d * 8.0 / dt / speed_bps * 100.0), 1))
        derr = (i.in_errors + i.out_errors) - (o.in_errors + o.out_errors)
        if derr >= 0:
            i.err_rate = round(derr / dt, 3)


HSRP_STATES = {1: "initial", 2: "learn", 3: "listen", 4: "speak", 5: "standby", 6: "active"}
VRRP_STATES = {1: "initialize", 2: "backup", 3: "master"}
OSPF_STATES = {1: "down", 2: "attempt", 3: "init", 4: "two-way", 5: "exchange-start", 6: "exchange", 7: "loading", 8: "full"}
BGP_STATES = {1: "idle", 2: "connect", 3: "active", 4: "opensent", 5: "openconfirm", 6: "established"}


async def collect_redundancy(sess: SnmpSession, dev: Device) -> None:
    """First-hop redundancy groups (HSRP, VRRP): the virtual IP that hosts really use as
    their gateway, and whether this router is active/master or standby/backup for it. This
    is what makes a subnet's true default gateway visible."""
    # HSRP (Cisco), indexed by ifIndex.group
    state = await _safe(dev, "cHsrpGrpStandbyState", sess.walk_map(O.HSRP_STATE)) or {}
    if state:
        vip = await _safe(dev, "cHsrpGrpVirtualIpAddr", sess.walk_map(O.HSRP_VIP)) or {}
        prio = await _safe(dev, "cHsrpGrpPriority", sess.walk_map(O.HSRP_PRIORITY)) or {}
        for idx, st in state.items():
            ifidx = _int(idx.split(".")[0])
            grp = idx.split(".")[-1]
            dev.redundancy.append({"proto": "hsrp", "group": grp, "vip": to_text(vip.get(idx)),
                                   "state": HSRP_STATES.get(_int(st), str(st)), "priority": _int(prio.get(idx)),
                                   "if_index": ifidx, "interface": dev.iface_label(ifidx)})
    # VRRP (standard), indexed by ifIndex.vrId; the VIP is the tail of the vrrpAssoIpAddr index
    vstate = await _safe(dev, "vrrpOperState", sess.walk_map(O.VRRP_STATE)) or {}
    if vstate:
        vprio = await _safe(dev, "vrrpOperPriority", sess.walk_map(O.VRRP_PRIORITY)) or {}
        vips: dict[str, str] = {}
        for oid, _v in await _safe(dev, "vrrpAssoIpAddr", sess.walk(O.VRRP_ASSOIP)) or []:
            p = oid_suffix(oid, O.VRRP_ASSOIP)
            if len(p) >= 3:
                vips.setdefault(f"{p[0]}.{p[1]}", ip_from_ints(p[-4:]) or "")
        for idx, st in vstate.items():
            ifidx = _int(idx.split(".")[0])
            dev.redundancy.append({"proto": "vrrp", "group": idx.split(".")[-1], "vip": vips.get(idx, ""),
                                   "state": VRRP_STATES.get(_int(st), str(st)), "priority": _int(vprio.get(idx)),
                                   "if_index": ifidx, "interface": dev.iface_label(ifidx)})


async def collect_routing_peers(sess: SnmpSession, dev: Device) -> None:
    """OSPF and BGP adjacencies - the shape of the routed core, and which peers are up."""
    ospf = await _safe(dev, "ospfNbrState", sess.walk(O.OSPF_NBR_STATE)) or []
    for oid, st in ospf:
        p = oid_suffix(oid, O.OSPF_NBR_STATE)
        addr = ip_from_ints(p[:4]) if len(p) >= 4 else None
        if addr:
            dev.peers.append({"proto": "ospf", "addr": addr, "state": OSPF_STATES.get(_int(st), str(st)), "extra": ""})
    state = await _safe(dev, "bgpPeerState", sess.walk_map(O.BGP_PEER_STATE)) or {}
    if state:
        raddr = await _safe(dev, "bgpPeerRemoteAddr", sess.walk_map(O.BGP_PEER_REMADDR)) or {}
        ras = await _safe(dev, "bgpPeerRemoteAs", sess.walk_map(O.BGP_PEER_REMAS)) or {}
        for idx, st in state.items():
            addr = to_text(raddr.get(idx)) or idx
            dev.peers.append({"proto": "bgp", "addr": addr, "state": BGP_STATES.get(_int(st), str(st)),
                              "extra": f"AS{_int(ras.get(idx))}" if ras.get(idx) else ""})


async def collect_stp(sess: SnmpSession, dev: Device) -> None:
    """Spanning-tree root: who the root bridge is, and whether this switch is it. Shows the
    active L2 forwarding shape, which can differ from the physical cabling."""
    r = await sess.get(O.STP_DESIGNATED_ROOT, O.STP_ROOT_PORT, O.STP_PRIORITY, O.BRIDGE_ADDRESS)
    root = r.get(O.STP_DESIGNATED_ROOT)
    if not isinstance(root, bytes) or len(root) != 8:
        return
    root_prio = int.from_bytes(root[:2], "big")
    root_mac = mac_from_bytes(root[2:])
    own = mac_from_bytes(r.get(O.BRIDGE_ADDRESS)) if isinstance(r.get(O.BRIDGE_ADDRESS), bytes) else None
    rp = _int(r.get(O.STP_ROOT_PORT))
    dev.stp = {"root": root_mac or "", "root_priority": root_prio, "priority": _int(r.get(O.STP_PRIORITY)),
               "is_root": bool(own and root_mac and own == root_mac), "root_port": dev.iface_label(rp) if rp else ""}


async def collect_device(sess: SnmpSession, ip: str, opts: CollectOptions, sysinfo: Optional[dict] = None) -> Device:
    t0 = time.time()
    dev = Device(id=ip, credential=sess.cred.label)
    await collect_system(sess, dev)
    await _safe(dev, "entity", collect_entity(sess, dev))
    await _safe(dev, "interfaces", collect_interfaces(sess, dev))
    await _safe(dev, "ipAddrTable", collect_ip_addrs(sess, dev))
    if ip not in dev.ips:
        dev.ips.append(ip)
    await _safe(dev, "lldp", collect_lldp(sess, dev))
    await _safe(dev, "cdp", collect_cdp(sess, dev))
    if opts.arp:
        await _safe(dev, "arp", collect_arp(sess, dev))
    if opts.routes:
        await _safe(dev, "routes", collect_routes(sess, dev))
    await _safe(dev, "vlans", collect_vlans(sess, dev))
    # walked once here: the FDB and the per-port VLANs are both keyed by bridge port
    bp = await _safe(dev, "dot1dBasePortIfIndex", sess.walk_map(O.DOT1D_BASE_PORT_IFINDEX)) or {}
    if opts.fdb:
        await _safe(dev, "fdb", collect_fdb(sess, dev, opts, bp))
    await _safe(dev, "port vlans", collect_port_vlans(sess, dev, bp))
    await _safe(dev, "lag", collect_lag(sess, dev))
    is_l3 = bool(dev.services & 4) or bool(dev.routes) or sum(1 for i in dev.interfaces if i.ips) > 1
    if opts.topology and is_l3:
        await _safe(dev, "fhrp", collect_redundancy(sess, dev))
        await _safe(dev, "routing peers", collect_routing_peers(sess, dev))
    if opts.topology and (bp or dev.fdb):
        await _safe(dev, "stp", collect_stp(sess, dev))
    if opts.health:
        await _safe(dev, "counters", collect_counters(sess, dev))
        if bp or dev.fdb:
            await _safe(dev, "poe", collect_poe(sess, dev))
    dev.role = classify_role(dev)
    dev.collected_at = time.time()
    dev.collect_seconds = round(dev.collected_at - t0, 2)
    return dev
