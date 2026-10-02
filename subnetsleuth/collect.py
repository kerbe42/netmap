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

log = logging.getLogger("subnetsleuth.collect")

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


# physical ethernet-ish interface types (ethernetCsmacd, fastEther(FX), gigabitEthernet)
_PHYS_IFTYPES = {6, 62, 69, 117}
# a device with at least this many physical ports and no routing is treated as a switch, not
# a router, however it describes itself — routers do not have 24 access ports.
_SWITCH_PORT_MIN = 8


# CDP and LLDP name the same capabilities differently; map everything onto the LLDP vocabulary
# so a device seen over either protocol classifies the same way.
_CAP_ALIASES = {"switch": "bridge", "srcbridge": "bridge", "phone": "telephone", "host": "station"}


def _caps_set(s: str) -> set:
    return {_CAP_ALIASES.get(c.strip(), c.strip()) for c in (s or "").split(",") if c.strip()}


def _phys_port_count(dev: Device) -> int:
    return sum(1 for i in dev.interfaces if i.type in _PHYS_IFTYPES and not i.lag
               and not re.match(r"^(vlan|vl\d|lo|loopback|po\d|port-?channel|bundle|null|tunnel|mgmt|management|irb|bvi)",
                                (i.name or i.descr or "").strip(), re.I))


def _routes_for_real(dev: Device) -> bool:
    """True if the device holds routes beyond connected/default — evidence it actually routes."""
    return any(r.dest not in ("0.0.0.0/0", "") and r.type != 3 and r.nexthop not in ("", "0.0.0.0")
               for r in dev.routes)


def _bridges(dev: Device) -> bool:
    """True if the device forwards at layer 2: it has a bridge forwarding table, LLDP/CDP
    neighbours on physical ports, or many physical ports."""
    return bool(dev.fdb) or _phys_port_count(dev) >= _SWITCH_PORT_MIN


def classify_role(dev: Device, caps: Optional[str] = None) -> str:
    """Decide what a polled device is, from the strongest evidence available.

    Order of trust: an explicit firewall string; the capabilities the device (or, via
    ``caps``, its neighbours) advertise over LLDP/CDP — a vendor-neutral statement of
    bridge / router / WLAN-AP; the bridge forwarding table and physical-port count; and
    only then the sysDescr text. Crucially it never falls back to "router" just because the
    SNMP routing service bit is set — that bit is on nearly every managed switch — so a
    switch or access point whose model string we don't recognise is no longer mislabelled.
    """
    d = dev.sysdescr.lower()
    l2 = bool(dev.services & 2)
    l3 = bool(dev.services & 4)
    cap = _caps_set(caps if caps is not None else dev.lldp_caps)
    routes = _routes_for_real(dev)
    addressed = sum(1 for i in dev.interfaces if i.ips)
    # a bridge is an L3 switch when it also has layer-3 presence: the routing service bit AND
    # either addresses on two or more interfaces (SVIs) or a real route. The bit alone is not
    # enough — it is set on nearly every managed switch.
    l3switch = l3 and (addressed >= 2 or routes)

    # a firewall usually says so, and that wins over a generic bridge/router capability
    if re.search(r"fortigate|palo alto|pan-os|checkpoint|check point|\basa\b|adaptive security|sonicwall|pfsense|opnsense|firewall|\bsrx\d", d):
        return "firewall"

    # what the device advertises it is (its own LLDP caps, or neighbours' view passed in).
    # A device that both bridges and routes is an L3 switch — decide that before the wlan-ap
    # bit, so one noisy or integrated-AP capability can't mislabel a core switch as wireless.
    if cap:
        bridge, router, wlan = "bridge" in cap, "router" in cap, "wlan-ap" in cap
        if bridge and router:
            return "l3switch"
        if wlan and not router:  # an access point (it bridges too), not a router
            return "wireless"
        if router:
            return "router"
        if bridge:
            return "switch"

    if re.search(r"wireless|access point|aironet|unifi|aruba (ap|instant)|meraki mr|lightweight ap|\bwlc\b", d):
        return "wireless"
    if re.search(r"printer|laserjet|jetdirect|officejet|xerox|ricoh|kyocera|konica|lexmark", d):
        return "printer"

    is_router = re.search(r"\brouter\b|\bisr\d|\basr\d|\bc\d{3,4}\b.*router|mikrotik|routeros|junos.*\bmx\d|edgerouter|vyos|\bccr\d", d)
    is_switch = re.search(r"switch|catalyst|nexus|\bex\d{4}|\bqfx|procurve|comware|aruba \d{4}|\bws-c|\bc9[235]00", d)
    if is_switch:
        return "l3switch" if l3switch else "switch"
    if is_router and not _bridges(dev):
        return "router"

    # bridge/port evidence: a device that forwards at L2 is a switch (L3 switch if it also
    # has the layer-3 presence above), whatever its model string — this rescues unrecognised kit.
    if _bridges(dev):
        return "l3switch" if l3switch else "switch"

    if re.search(r"vmware esx|esxi|\bwindows\b|\blinux\b|freebsd|ubuntu|debian|centos|red hat|net-snmp", d):
        return "server"

    # a device with a real routing table and few ports is a router; otherwise fall back to the
    # weak datalink/neighbour signals before giving up — never to "router" on the L3 bit alone.
    if routes:
        return "router"
    if l2 or any(n.proto in ("lldp", "cdp") for n in dev.neighbors):
        return "switch"
    return "unknown"


def _neighbor_device_id(inv, nb) -> Optional[str]:
    """The id of the polled device a neighbour entry points at, or None."""
    for ip in nb.remote_mgmt_ips:
        if ip in inv.ip_to_device:
            return inv.ip_to_device[ip]
    for cid in (nb.remote_chassis_id, (nb.remote_chassis_id or "").lower()):
        if cid and cid in inv.mac_to_device:
            return inv.mac_to_device[cid]
    d = inv.device_for_name(nb.remote_name)
    return d.id if d else None


def reclassify_from_neighbor_caps(inv) -> int:
    """Second pass, only for devices we could not type at all (role ``unknown``): a device
    whose own data was too thin — unrecognised model, no bridge table, no LLDP capabilities —
    may still be described by its neighbours, since CDP and LLDP both carry the capability
    bits. Pool what every neighbour says about each such device and classify from that.

    Deliberately conservative: it never revisits a device that classified from its own
    evidence (a model string, a bridge table, its own advertised capabilities), so a router
    that a neighbour happens to advertise with the CDP ``switch`` bit is never downgraded.
    Returns how many devices were newly typed."""
    caps_about: dict[str, set] = defaultdict(set)
    for d in inv.devices.values():
        for nb in d.neighbors:
            if not nb.remote_caps:
                continue
            tid = _neighbor_device_id(inv, nb)
            if tid and tid in inv.devices:
                caps_about[tid] |= _caps_set(nb.remote_caps)
    changed = 0
    for d in inv.devices.values():
        if d.role != "unknown":
            continue
        cap = caps_about.get(d.id)
        if not cap:
            continue
        new = classify_role(d, caps=",".join(sorted(cap)))
        if new and new != "unknown":
            d.role = new
            changed += 1
    return changed


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
    # probe() already fetched descr/objectid/name/services - seed from it first so a
    # transient failure on the fuller GET below can't lose data the device already gave.
    if sysinfo:
        dev.sysdescr = to_text(sysinfo.get(O.SYS_DESCR))
        dev.sysobjectid = to_text(sysinfo.get(O.SYS_OBJECTID))
        dev.name = to_text(sysinfo.get(O.SYS_NAME))
        dev.services = int(sysinfo.get(O.SYS_SERVICES) or 0)
    try:
        r = await sess.get(O.SYS_DESCR, O.SYS_OBJECTID, O.SYS_UPTIME, O.SYS_CONTACT, O.SYS_NAME, O.SYS_LOCATION, O.SYS_SERVICES)
    except Exception as e:  # noqa: BLE001 - keep the seeded sysinfo; don't drop the device
        dev.errors.append(f"system: {type(e).__name__}: {e}")
        if sysinfo:
            dev.vendor = _vendor(dev.sysobjectid, dev.sysdescr)
            dev.os_version = parse_os_version(dev.sysdescr, dev.vendor)
        return
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
    if not phys:
        return
    # ipNetToMediaType: 1 other, 2 invalid, 3 dynamic, 4 static. Only learned and configured
    # entries describe a neighbour that is really there; invalid/other rows are stale.
    types = dict(await _safe(dev, "ipNetToMediaType", sess.walk(O.ARP_TYPE)) or [])
    for oid, val in phys:
        parts = oid_suffix(oid, O.ARP_PHYS)
        if len(parts) != 5:
            continue
        t = types.get(O.ARP_TYPE + oid[len(O.ARP_PHYS) :])
        if t is not None and _int(t) not in (3, 4):
            continue
        ip = ip_from_ints(parts[1:])
        mac = mac_from_bytes(val) if isinstance(val, bytes) else None
        if ip and mac and is_usable_ip(ip) and plausible_mac(mac):
            dev.arp.append(ArpEntry(if_index=parts[0], ip=ip, mac=mac))


def decode_inet_cidr_index(parts: list[int]) -> Optional[tuple[str, int, str]]:
    """inetCidrRouteTable index -> (dest, prefix length, next hop) for an IPv4 row, else None.

    Layout: DestType, Dest (length + octets), PfxLen, Policy (OID length + sub-ids),
    NextHopType, NextHop (length + octets). A next hop of type unknown(0) or an empty one
    is a connected route and reads as 0.0.0.0."""
    try:
        i = 0
        dtype, dlen = parts[i], parts[i + 1]
        i += 2
        dest_parts = parts[i : i + dlen]
        i += dlen
        pfx = parts[i]
        i += 1
        plen = parts[i]
        i += 1 + plen
        nhtype, nhlen = parts[i], parts[i + 1]
        i += 2
        nh_parts = parts[i : i + nhlen]
        if i + nhlen != len(parts):
            return None
    except IndexError:
        return None
    if dtype != 1 or dlen != 4 or not 0 <= pfx <= 32:
        return None  # IPv6 and other address families are not inventoried here
    dest = ip_from_ints(dest_parts)
    if not dest:
        return None
    if nhtype == 1 and nhlen == 4:
        nh = ip_from_ints(nh_parts) or "0.0.0.0"
    elif nhtype in (0, 1) and nhlen == 0:
        nh = "0.0.0.0"
    else:
        return None
    return dest, pfx, nh


async def _routes_inet_cidr(sess: SnmpSession, dev: Device) -> bool:
    """RFC 4292 inetCidrRouteTable, the table current agents fill (IPv4 rows only). True if it had any."""
    rows = await _safe(dev, "inetCidrRouteIfIndex", sess.walk(O.INET_CIDR_ROUTE_IFINDEX)) or []
    if not rows:
        return False
    types = dict(await _safe(dev, "inetCidrRouteType", sess.walk(O.INET_CIDR_ROUTE_TYPE)) or [])
    protos = dict(await _safe(dev, "inetCidrRouteProto", sess.walk(O.INET_CIDR_ROUTE_PROTO)) or [])
    seen = set()
    n = 0
    for oid, ifidx in rows:
        dec = decode_inet_cidr_index(oid_suffix(oid, O.INET_CIDR_ROUTE_IFINDEX))
        if dec is None:
            continue
        dest, pfx, nh = dec
        if (dest, pfx, nh) in seen:
            continue
        seen.add((dest, pfx, nh))
        suffix = oid[len(O.INET_CIDR_ROUTE_IFINDEX) :]
        dev.routes.append(
            Route(
                dest=f"{dest}/{pfx}",
                nexthop=nh,
                if_index=int(ifidx) if ifidx else None,
                type=_int(types.get(O.INET_CIDR_ROUTE_TYPE + suffix)),
                proto=_int(protos.get(O.INET_CIDR_ROUTE_PROTO + suffix)),
            )
        )
        n += 1
    return n > 0


async def collect_routes(sess: SnmpSession, dev: Device) -> None:
    if await _routes_inet_cidr(sess, dev):
        return
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
            try:
                prefix = mask_to_prefix(mask)
            except ValueError:
                continue  # a non-contiguous mask on one row must not lose the rest of the table
            suffix = oid[len(O.CIDR_ROUTE_IFINDEX) :]
            dev.routes.append(
                Route(
                    dest=f"{dest}/{prefix}",
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


async def collect_lldp(sess: SnmpSession, dev: Device, bp: Optional[dict] = None) -> None:
    """LLDP neighbours. `bp` is dot1dBasePortIfIndex when already walked: on many switches
    lldpLocPortNum is the bridge port, not the ifIndex, and this maps between them."""
    loc = await sess.get(O.LLDP_LOC_CHASSIS_SUBTYPE, O.LLDP_LOC_CHASSIS_ID, O.LLDP_LOC_SYS_CAP_ENABLED)
    dev.lldp_chassis_id = _lldp_id(loc.get(O.LLDP_LOC_CHASSIS_SUBTYPE), loc.get(O.LLDP_LOC_CHASSIS_ID), "chassis")
    # the device's own advertised capabilities (bridge/router/wlan-ap…) — a vendor-neutral
    # statement of what it is, kept even when it reports no neighbours.
    dev.lldp_caps = _lldp_caps(loc.get(O.LLDP_LOC_SYS_CAP_ENABLED)) or dev.lldp_caps
    rem_sys = await sess.walk(O.LLDP_REM_SYSNAME)
    if not rem_sys:
        return
    loc_port_st = await _safe(dev, "lldpLocPortIdSubtype", sess.walk_map(O.LLDP_LOC_PORT_ID_SUBTYPE)) or {}
    loc_port_raw = await _safe(dev, "lldpLocPortId", sess.walk_map(O.LLDP_LOC_PORT_ID)) or {}
    # decoded by subtype: a MAC-address port id becomes "aa:bb:..." (matched against ifPhysAddress)
    # rather than six unprintable bytes
    loc_port_id = {k: _lldp_id(loc_port_st.get(k), v, "port") for k, v in loc_port_raw.items()}
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
        lp_name = to_text(loc_port_desc.get(local_port_num)) or loc_port_id.get(local_port_num, "")
        lif = _find_if_by_port(dev, loc_port_id.get(local_port_num, ""), to_text(loc_port_desc.get(local_port_num)))
        if lif is None and bp and bp.get(local_port_num) and dev.iface(_int(bp.get(local_port_num))):
            lif = _int(bp.get(local_port_num))  # lldpLocPortNum is a bridge port on this platform
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


def fdb_id_to_vlan(rows) -> dict[int, int]:
    """dot1qVlanFdbId rows [(oid, fdbId)] with index TimeMark.VlanIndex -> {fdbId: vlan}."""
    out: dict[int, int] = {}
    for oid, fid in rows:
        p = oid_suffix(oid, O.DOT1Q_VLAN_FDB_ID)
        if len(p) == 2 and fid is not None:
            out.setdefault(_int(fid), p[1])
    return out


async def collect_fdb(sess: SnmpSession, dev: Device, opts: CollectOptions, bp: Optional[dict] = None) -> None:
    """Bridge forwarding table. `bp` is dot1dBasePortIfIndex if the caller already walked it."""
    # Q-BRIDGE first: includes VLAN in the index
    q = await _safe(dev, "dot1qTpFdbPort", sess.walk(O.DOT1Q_FDB_PORT)) or []
    if q:
        if bp is None:
            bp = await sess.walk_map(O.DOT1D_BASE_PORT_IFINDEX)
        status = dict(await _safe(dev, "dot1qTpFdbStatus", sess.walk(O.DOT1Q_FDB_STATUS)) or [])
        # The first index of dot1qTpFdbTable is an FDB id, which is the VLAN id only on
        # switches with one FDB per VLAN. dot1qVlanFdbId says which FDB each VLAN uses.
        fdb_vlan = fdb_id_to_vlan(await _safe(dev, "dot1qVlanFdbId", sess.walk(O.DOT1Q_VLAN_FDB_ID)) or [])
        for oid, port in q:
            p = oid_suffix(oid, O.DOT1Q_FDB_PORT)
            if len(p) != 7 or not port:
                continue
            st = status.get(O.DOT1Q_FDB_STATUS + oid[len(O.DOT1Q_FDB_PORT) :])
            if st is not None and int(st) != 3:
                continue
            mac = mac_from_ints(p[1:])
            ifidx = bp.get(str(port))
            dev.fdb.append(FdbEntry(mac=mac, if_index=int(ifidx) if ifidx else None, vlan=fdb_vlan.get(p[0], p[0])))
        if dev.fdb:
            return
    n = await _safe(dev, "dot1dTpFdb", _fdb_dot1d(sess, dev, None, bp))
    if opts.cisco_vlan_fdb and dev.vendor == "Cisco" and dev.vlans:
        # Cisco IOS keeps a separate bridge per VLAN; walk each with community@vlan / vlan-N context.
        # Only operational VLANs (vtpVlanState 1) have a bridge; suspended ones just time out.
        state = await _safe(dev, "vtpVlanState", sess.walk(O.VTP_VLAN_STATE)) or []
        operational = {p[1] for oid, st in state if len(p := oid_suffix(oid, O.VTP_VLAN_STATE)) == 2 and _int(st) == 1}
        candidates = [v for v in sorted(dev.vlans) if v not in range(1002, 1006) and (not operational or v in operational)]
        vlans = candidates[: opts.max_vlans]
        if len(candidates) > opts.max_vlans:
            dev.errors.append(f"fdb: per-VLAN bridge tables read for {opts.max_vlans} of {len(candidates)} VLANs (max_vlans); "
                              f"MACs in VLANs {candidates[opts.max_vlans]}.. are missing")
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
    # Which counters are 64-bit decides how a negative delta is read on the next scan (wrap vs
    # reset). Kept on the object for this process only; it is not part of the saved record.
    dev._hc_counters = {("in", _int(k)) for k in hc_in} | {("out", _int(k)) for k in hc_out}  # type: ignore[attr-defined]
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
    by_portnum: dict[int, Interface] = {}
    by_group_port: dict[tuple[int, int], Interface] = {}
    for i in dev.interfaces:
        label = i.name or i.descr or ""
        m = re.search(r"(\d+)\s*$", label)  # last number in the name, e.g. Gi1/0/24 -> 24
        if m:
            by_portnum.setdefault(int(m.group(1)), i)
        # "Gi2/0/24" / "2/24": the leading number is the stack member or slot, which is the
        # PoE group; matching on both is what keeps a stack's members apart
        m = re.search(r"(?<!\d)(\d+)/(?:\d+/)?(\d+)\s*$", label)
        if m:
            by_group_port.setdefault((int(m.group(1)), int(m.group(2))), i)
    for key, st in status.items():
        parts = key.split(".")
        port = _int(parts[-1])
        group = _int(parts[0]) if len(parts) > 1 else 0
        iface = by_group_port.get((group, port))
        if iface is None and not any(g == group for g, _p in by_group_port):
            # no interface names this group at all: fall back to the plain port number,
            # and to ifIndex only as a last resort (it rarely equals the port number)
            iface = by_portnum.get(port) or by_index.get(port)
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
        hc = getattr(new, "_hc_counters", None)
        for cur, was, attr, direction in ((i.in_octets, o.in_octets, "in_util_pct", "in"), (i.out_octets, o.out_octets, "out_util_pct", "out")):
            d = cur - was
            if d < 0:
                # a 32-bit ifInOctets counter wraps every ~34s on a gigabit link; recover
                # the delta if adding one 32-bit turn gives a rate within the link speed.
                # A larger negative delta is a counter reset (reboot), which we skip - and
                # so is any negative delta on a 64-bit counter, which does not wrap in practice.
                is_64 = (direction, i.index) in hc if hc is not None else max(cur, was) >= (1 << 32)
                wrapped = d + (1 << 32)
                d = wrapped if not is_64 and speed_bps and wrapped * 8.0 / dt <= speed_bps else -1
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


_OID_NAMES = {v: k for k, v in vars(O).items() if isinstance(v, str) and v[:1].isdigit() and k.isupper()}


def _table_name(note: str) -> str:
    """'1.3.6.1.2.1.17.7.1.2.2.1.2: truncated ...' -> 'DOT1Q_FDB_PORT: truncated ...'."""
    oid, sep, rest = note.partition(":")
    return f"{_OID_NAMES.get(oid, oid)}{sep}{rest}"


def record_truncations(sess, dev: Device) -> None:
    """Move the session's truncated-walk notes onto the device, so an incomplete table is
    visible in the record rather than looking like the whole table."""
    notes = getattr(sess, "truncations", None)
    if not notes:
        return
    for n in notes:
        msg = _table_name(n)
        if msg not in dev.errors:
            dev.errors.append(msg)
    notes.clear()


async def collect_device(sess: SnmpSession, ip: str, opts: CollectOptions, sysinfo: Optional[dict] = None) -> Device:
    t0 = time.time()
    dev = Device(id=ip, credential=sess.cred.label, snmp_version=getattr(sess.cred, "kind", "") or "")
    await _safe(dev, "system", collect_system(sess, dev, sysinfo))
    await _safe(dev, "entity", collect_entity(sess, dev))
    await _safe(dev, "interfaces", collect_interfaces(sess, dev))
    await _safe(dev, "ipAddrTable", collect_ip_addrs(sess, dev))
    if ip not in dev.ips:
        dev.ips.append(ip)
    # walked once here: LLDP local ports, the FDB and the per-port VLANs are all keyed by bridge port
    bp = await _safe(dev, "dot1dBasePortIfIndex", sess.walk_map(O.DOT1D_BASE_PORT_IFINDEX)) or {}
    await _safe(dev, "lldp", collect_lldp(sess, dev, bp))
    await _safe(dev, "cdp", collect_cdp(sess, dev))
    if opts.arp:
        await _safe(dev, "arp", collect_arp(sess, dev))
    if opts.routes:
        await _safe(dev, "routes", collect_routes(sess, dev))
    await _safe(dev, "vlans", collect_vlans(sess, dev))
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
    record_truncations(sess, dev)
    dev.role = classify_role(dev)
    dev.collected_at = time.time()
    dev.collect_seconds = round(dev.collected_at - t0, 2)
    return dev
