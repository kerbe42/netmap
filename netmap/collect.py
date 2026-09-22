"""Collect everything useful from one SNMP-speaking device."""
from __future__ import annotations

import logging
import re
import time
from typing import Optional

from . import oids as O
from .model import ArpEntry, Device, FdbEntry, Interface, Neighbor, Route
from .snmp import SnmpError, SnmpSession
from .util import (
    enterprise_from_sysobjectid,
    ip_from_ints,
    is_usable_ip,
    mac_from_bytes,
    mac_from_ints,
    mask_to_prefix,
    oid_suffix,
    to_text,
)

log = logging.getLogger("netmap.collect")


class CollectOptions:
    def __init__(self, fdb: bool = True, cisco_vlan_fdb: bool = False, routes: bool = True, arp: bool = True, max_vlans: int = 64):
        self.fdb = fdb
        self.cisco_vlan_fdb = cisco_vlan_fdb
        self.routes = routes
        self.arp = arp
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
        return "l3switch" if l3 else "switch"
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


async def collect_entity(sess: SnmpSession, dev: Device) -> None:
    classes = await sess.walk_map(O.ENT_CLASS)
    if not classes:
        return
    chassis = [k for k, v in classes.items() if v == 3] or list(classes)[:1]
    idx = chassis[0]
    r = await sess.get(f"{O.ENT_MODEL}.{idx}", f"{O.ENT_SERIAL}.{idx}")
    dev.model = to_text(r.get(f"{O.ENT_MODEL}.{idx}"))
    dev.serial = to_text(r.get(f"{O.ENT_SERIAL}.{idx}"))
    if not dev.serial:
        serials = await sess.walk_map(O.ENT_SERIAL)
        for k, v in serials.items():
            if to_text(v):
                dev.serial = to_text(v)
                if not dev.model:
                    m = await sess.get(f"{O.ENT_MODEL}.{k}")
                    dev.model = to_text(m.get(f"{O.ENT_MODEL}.{k}"))
                break


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
        if ip and mac and is_usable_ip(ip) and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
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


async def _fdb_dot1d(sess: SnmpSession, dev: Device, vlan: Optional[int]) -> int:
    ports = await sess.walk(O.DOT1D_FDB_PORT)
    if not ports:
        return 0
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


async def collect_fdb(sess: SnmpSession, dev: Device, opts: CollectOptions) -> None:
    # Q-BRIDGE first: includes VLAN in the index
    q = await _safe(dev, "dot1qTpFdbPort", sess.walk(O.DOT1Q_FDB_PORT)) or []
    if q:
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
    n = await _safe(dev, "dot1dTpFdb", _fdb_dot1d(sess, dev, None))
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
    if opts.fdb:
        await _safe(dev, "fdb", collect_fdb(sess, dev, opts))
    dev.role = classify_role(dev)
    dev.collected_at = time.time()
    dev.collect_seconds = round(dev.collected_at - t0, 2)
    return dev
