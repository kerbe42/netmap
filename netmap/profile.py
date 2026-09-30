"""Work out what a host is by combining every signal a scan gathered - many weak clues
weighed together, with the evidence kept, the way endpoint-profiling systems do.

`profile_host` reads a `Host` (its MAC/OUI vendor, open ports and service banners, and the
results of the active probes in `host.probes` - NetBIOS, mDNS, SSDP, HTTP/TLS - plus any
name it goes by) and returns a role, an OS family, a vendor and model where known, a
confidence, the best hostname, and an ordered list of evidence explaining the verdict.

Nothing here does network I/O; it is pure and deterministic, so a re-profile after new
probe data just runs again.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .util import oui_vendor

# role -> the OS family it usually implies, when nothing more specific is known
ROLE_OS = {"printer": "printer", "camera": "embedded", "phone": "embedded", "ups": "embedded", "nas": "embedded", "wireless": "network", "plc": "embedded", "bms": "embedded", "ot": "embedded", "bmc": "embedded"}

# service/port -> what it suggests. (port, role, weight, note)
PORT_HINTS = [
    (9100, "printer", 6, "raw print port 9100 (JetDirect)"),
    (515, "printer", 4, "LPD print port 515"),
    (631, "printer", 4, "IPP print port 631"),
    (161, "network", 1, "SNMP agent"),
    (554, "camera", 5, "RTSP video port 554"),
    (37777, "camera", 6, "Dahua camera port"),
    (5060, "phone", 5, "SIP port 5060"),
    (5061, "phone", 4, "SIP-TLS port 5061"),
    (2000, "phone", 3, "Cisco SCCP port 2000"),
    (3389, "windows", 5, "RDP port 3389"),
    (445, "windows", 3, "SMB port 445"),
    (139, "windows", 2, "NetBIOS session 139"),
    (135, "windows", 3, "MSRPC port 135"),
    (5985, "windows", 3, "WinRM port 5985"),
    (22, "server", 1, "SSH port 22"),
    (3306, "database", 5, "MySQL port 3306"),
    (5432, "database", 5, "PostgreSQL port 5432"),
    (1433, "database", 5, "MSSQL port 1433"),
    (1521, "database", 5, "Oracle port 1521"),
    (27017, "database", 5, "MongoDB port 27017"),
    (6379, "database", 4, "Redis port 6379"),
    (5000, "nas", 2, "port 5000 (Synology/UPnP)"),
    (5001, "nas", 2, "port 5001 (Synology TLS)"),
    (2049, "nas", 3, "NFS port 2049"),
    (548, "nas", 3, "AFP port 548"),
    (32400, "server", 4, "Plex media server"),
    (8006, "server", 3, "Proxmox web UI"),
    (443, "server", 1, "HTTPS"),
    (80, "server", 1, "HTTP"),
]

# mDNS service type -> (role, weight, os_family hint, note)
MDNS_HINTS = {
    "_ipp": ("printer", 7, "printer", "advertises IPP printing over mDNS"),
    "_ipps": ("printer", 7, "printer", "advertises IPPS printing"),
    "_printer": ("printer", 7, "printer", "advertises LPR printing"),
    "_pdl-datastream": ("printer", 6, "printer", "advertises raw printing"),
    "_scanner": ("printer", 5, "printer", "advertises scanning"),
    "_airplay": ("server", 6, "embedded", "advertises AirPlay (Apple TV / speaker)"),
    "_raop": ("server", 5, "embedded", "advertises AirPlay audio"),
    "_googlecast": ("server", 6, "android", "advertises Chromecast"),
    "_hap": ("host", 5, "embedded", "advertises HomeKit (HAP)"),
    "_homekit": ("host", 5, "embedded", "advertises HomeKit"),
    "_afpovertcp": ("nas", 5, "embedded", "advertises AFP file sharing"),
    "_smb": ("nas", 3, "", "advertises SMB file sharing"),
    "_adisk": ("nas", 5, "embedded", "advertises Time Machine backup"),
    "_ssh": ("server", 2, "", "advertises SSH"),
    "_sftp-ssh": ("server", 2, "", "advertises SFTP"),
    "_device-info": ("host", 1, "", "advertises device info"),
}

# substrings in an HTTP Server header / TLS cert / SSDP server -> (vendor, role, os_family, weight)
BANNER_HINTS = [
    ("fortigate", "Fortinet", "firewall", "fortios", 8),
    ("fortinet", "Fortinet", "firewall", "fortios", 7),
    ("pan-os", "Palo Alto", "firewall", "network", 8),
    ("cisco", "Cisco", "network", "network", 4),
    ("ios-xe", "Cisco", "l3switch", "ios", 6),
    ("mikrotik", "MikroTik", "router", "network", 7),
    ("routeros", "MikroTik", "router", "network", 7),
    ("ubiquiti", "Ubiquiti", "wireless", "network", 6),
    ("unifi", "Ubiquiti", "wireless", "network", 6),
    ("synology", "Synology", "nas", "embedded", 8),
    ("diskstation", "Synology", "nas", "embedded", 8),
    ("qnap", "QNAP", "nas", "embedded", 8),
    ("truenas", "iXsystems", "nas", "embedded", 7),
    ("proxmox", "Proxmox", "server", "linux", 7),
    ("vmware", "VMware", "server", "linux", 6),
    ("esxi", "VMware", "server", "linux", 7),
    ("idrac", "Dell", "server", "embedded", 7),
    ("ilo", "HPE", "server", "embedded", 7),
    ("hp ", "HP", "printer", "printer", 3),
    ("laserjet", "HP", "printer", "printer", 8),
    ("jetdirect", "HP", "printer", "printer", 8),
    ("brother", "Brother", "printer", "printer", 6),
    ("axis", "Axis", "camera", "embedded", 8),
    ("hikvision", "Hikvision", "camera", "embedded", 8),
    ("dahua", "Dahua", "camera", "embedded", 8),
    ("apc", "APC", "ups", "embedded", 7),
    ("eaton", "Eaton", "ups", "embedded", 6),
    ("iis", "Microsoft", "server", "windows", 5),
    ("microsoft-httpapi", "Microsoft", "server", "windows", 4),
    ("windows", "Microsoft", "windows", "windows", 3),
    ("apache", "", "server", "linux", 2),
    ("nginx", "", "server", "linux", 2),
    ("openssh", "", "server", "linux", 2),
    ("boa", "", "camera", "embedded", 3),
    ("lighttpd", "", "embedded", "embedded", 2),
]

# hostname patterns -> (role, os_family, note, weight)
NAME_HINTS = [
    (re.compile(r"^SEP[0-9A-F]{12}$", re.I), "phone", "embedded", "Cisco IP phone naming (SEP<mac>)", 8),
    (re.compile(r"^SIP[0-9A-F]{12}$", re.I), "phone", "embedded", "SIP phone naming", 6),
    (re.compile(r"^android[-_]", re.I), "host", "android", "Android device hostname", 6),
    (re.compile(r"iphone|ipad|-mbp|macbook|-mac\b", re.I), "workstation", "macos", "Apple device hostname", 5),
    (re.compile(r"^(printer|prn|mfp|hpm?|kyocera|ricoh)[-_0-9]", re.I), "printer", "printer", "printer-style hostname", 4),
    (re.compile(r"^(cam|ipc|nvr|dvr)[-_0-9]", re.I), "camera", "embedded", "camera-style hostname", 4),
    (re.compile(r"^(esx|esxi|vmhost)", re.I), "server", "linux", "hypervisor hostname", 4),
    (re.compile(r"(^dc\d|domaincontroller|-dc-|^ad\d)", re.I), "windows", "windows", "domain-controller hostname", 4),
    (re.compile(r"(nas|synology|diskstation|qnap|truenas|freenas)", re.I), "nas", "embedded", "NAS-style hostname", 4),
    (re.compile(r"(switch|^sw[-_0-9]|-sw\d|catalyst|nexus)", re.I), "switch", "network", "switch-style hostname", 3),
    (re.compile(r"(router|^rtr|-rtr|gateway|^gw[-_0-9])", re.I), "router", "network", "router-style hostname", 3),
    (re.compile(r"(^ap[-_0-9]|-ap\d|accesspoint|wifi|wlan)", re.I), "wireless", "network", "access-point hostname", 3),
    (re.compile(r"(firewall|^fw[-_0-9]|-fw\d|fortigate|palo)", re.I), "firewall", "network", "firewall-style hostname", 3),
]

# order names are trusted in when choosing the one to display
NAME_PRIORITY = ["user", "dns", "netbios", "mdns", "ssdp", "lldp", "cdp", "sweep"]


@dataclass
class Profile:
    role: str = "host"
    os: str = ""
    os_family: str = ""
    vendor: str = ""
    model: str = ""
    confidence: str = "low"
    hostname: str = ""
    evidence: list[dict] = field(default_factory=list)


def _vote(scores: dict, role: str, weight: float):
    scores[role] = scores.get(role, 0.0) + weight


def profile_host(host, snmp_role_fn=None) -> Profile:
    """Identify a host from all of its signals. `snmp_role_fn` is unused here but reserved
    for callers that want to fold in an SNMP-derived role."""
    ev: list[dict] = []
    scores: dict[str, float] = {}
    os_family = host.os_family or ""
    os_text = host.os or ""
    vendor = host.vendor or (oui_vendor(host.mac) if host.mac else "")
    model = host.model or ""
    probes = host.probes or {}

    def add(source, observed, implies, role=None, weight=0.0, of=None, os_=None, ven=None, mdl=None):
        nonlocal os_family, os_text, vendor, model
        ev.append({"source": source, "observed": observed, "implies": implies})
        if role and weight:
            _vote(scores, role, weight)
        if of and not os_family:
            os_family = of
        if os_ and not os_text:
            os_text = os_
        if ven and not vendor:
            vendor = ven
        if mdl and not model:
            model = mdl

    # ---- MAC / OUI ---------------------------------------------------------
    if host.mac and vendor:
        add("MAC OUI", f"{host.mac} -> {vendor}", f"made by {vendor}", ven=vendor)

    # ---- open ports -------------------------------------------------------
    ports = {p.get("port") for p in host.ports if p.get("port")}
    products = " ".join(f"{p.get('service', '')} {p.get('product', '')}" for p in host.ports).lower()
    for port, role, weight, note in PORT_HINTS:
        if port in ports:
            add("open port", note, role, role, weight)
    if products:
        for needle, ven, role, of, weight in BANNER_HINTS:
            if needle in products:
                add("service banner", f"nmap saw '{needle}'", role, role, weight, of=of, ven=ven or None)

    # ---- NetBIOS ----------------------------------------------------------
    nb = probes.get("netbios") or {}
    if nb:
        add("NetBIOS", "answered UDP 137", "Windows / SMB host", "windows", 6, of="windows")
        if nb.get("is_dc"):
            add("NetBIOS", "advertises the domain-controller role (0x1C)", "Active Directory domain controller", "windows", 6, of="windows", os_="Windows Server")
        if nb.get("domain"):
            add("NetBIOS", f"domain/workgroup {nb['domain']}", f"member of {nb['domain']}")
        if nb.get("mac") and vendor == "":
            vendor = oui_vendor(nb["mac"])

    # ---- mDNS -------------------------------------------------------------
    md = probes.get("mdns") or {}
    for svc in md.get("services", []):
        base = svc.split(".")[0].lower()
        hint = MDNS_HINTS.get(base)
        if hint:
            role, weight, of, note = hint
            add("mDNS", note, role, role, weight, of=of or None)
    if md.get("model"):
        add("mDNS", f"model={md['model']}", md["model"], mdl=md["model"])
    if md.get("hostname") and ("apple" in (vendor or "").lower() or any("_airplay" in s or "_raop" in s for s in md.get("services", []))):
        add("mDNS", "Bonjour/AirPlay", "Apple device", "workstation", 3, of="macos")

    # ---- SSDP / UPnP ------------------------------------------------------
    sd = probes.get("ssdp") or {}
    text = " ".join(str(sd.get(k, "")) for k in ("server", "friendly_name", "manufacturer", "model", "device_type")).lower()
    if sd:
        if sd.get("manufacturer"):
            add("UPnP", f"manufacturer {sd['manufacturer']}", f"made by {sd['manufacturer']}", ven=sd["manufacturer"])
        if sd.get("model"):
            add("UPnP", f"model {sd['model']}", sd["model"], mdl=sd["model"])
        dt = (sd.get("device_type") or "").lower()
        if "mediaserver" in dt or "mediarenderer" in dt:
            add("UPnP", "advertises a media device", "media/AV device", "server", 4, of="embedded")
        if "internetgateway" in dt:
            add("UPnP", "advertises an internet gateway", "router / gateway", "router", 5, of="network")
        for needle, ven, role, of, weight in BANNER_HINTS:
            if needle in text:
                add("UPnP", f"'{needle}' in device description", role, role, weight, of=of, ven=ven or None)

    # ---- HTTP / TLS -------------------------------------------------------
    http = probes.get("http") or {}
    entries = http.values() if isinstance(http, dict) else (http if isinstance(http, list) else [])
    for e in entries:
        if not isinstance(e, dict):
            continue
        blob = " ".join(str(e.get(k, "")) for k in ("server", "title", "realm", "cert_cn", "cert_issuer")).lower()
        san = " ".join(e.get("cert_san", [])).lower()
        blob = f"{blob} {san}"
        if e.get("server"):
            add("HTTP", f"Server: {e['server']}", "has a web UI")
        if e.get("cert_cn"):
            add("TLS", f"certificate CN {e['cert_cn']}", "identifies itself in its certificate")
        for needle, ven, role, of, weight in BANNER_HINTS:
            if needle in blob:
                add("HTTP/TLS", f"'{needle}' in banner/cert", role, role, weight, of=of, ven=ven or None)

    # ---- nmap service/OS scan --------------------------------------------
    nm = probes.get("nmap") or {}
    if nm.get("os"):
        fam = _NMAP_FAMILY.get((nm.get("os_family") or "").lower(), "")
        add("nmap OS scan", f"OS fingerprint: {nm['os']}" + (f" ({nm.get('os_accuracy')}%)" if nm.get("os_accuracy") else ""),
            nm["os"], of=fam or None, os_=nm["os"])
        if nm.get("os_vendor") and not vendor:
            vendor = nm["os_vendor"]
    # ---- OT / ICS and other unauthenticated protocol probes (definitive) --
    mb = probes.get("modbus") or {}
    if mb.get("modbus"):
        add("Modbus", "answered Modbus/TCP (502)", "industrial controller (PLC)", "plc", 9, of="embedded",
            ven=mb.get("vendor") or None, mdl=mb.get("product") or None)
    en = probes.get("enip") or {}
    if en.get("enip"):
        add("EtherNet/IP", f"answered EtherNet/IP List Identity: {en.get('product', '')}".strip(), "industrial controller (PLC)", "plc", 9,
            of="embedded", mdl=en.get("product") or None)
    bac = probes.get("bacnet") or {}
    if bac.get("bacnet"):
        add("BACnet", f"answered BACnet I-Am (device {bac.get('device_id', '?')})", "building-automation controller", "bms", 9, of="embedded")
    ipmi = probes.get("ipmi") or {}
    if ipmi.get("ipmi"):
        add("IPMI", f"answered IPMI {ipmi.get('version', '')} (623)".strip(), "server lights-out controller (BMC)", "bmc", 8, of="embedded")
    wsd = probes.get("wsd") or {}
    if wsd.get("kind"):
        role = {"camera": "camera", "printer": "printer", "windows": "windows"}.get(wsd["kind"], "host")
        add("WS-Discovery", f"advertises WS-Discovery ({', '.join(wsd.get('types', [])[:2])})", role, role, 6,
            of="windows" if role == "windows" else ("embedded" if role in ("camera",) else "printer" if role == "printer" else None))

    # ---- deep inspection (SSH/WinRM), the most authoritative -------------
    sysd = getattr(host, "system", {}) or {}
    if sysd.get("os"):
        os_text = sysd["os"]  # exact OS caption from the host itself overrides guesses
        ev.append({"source": "agent-less inspection", "observed": f"reported OS: {sysd['os']}", "implies": sysd["os"]})

    # ---- names ------------------------------------------------------------
    for src in NAME_PRIORITY:
        nm = host.names.get(src) if host.names else None
        if not nm:
            continue
        for rx, role, of, note, weight in NAME_HINTS:
            if rx.search(nm):
                add(f"{src} name", f"'{nm}' - {note}", role, role, weight, of=of or None)

    # ---- decide -----------------------------------------------------------
    hostname = _best_name(host)
    if not scores:
        # nothing decisive: keep whatever role it already had, or fall back by OS family
        role = host.role if host.role not in ("", "host", None) else ROLE_FROM_FAMILY.get(os_family, "host")
        conf = "medium" if (vendor or hostname) else "low"
        return Profile(role=role, os=os_text, os_family=os_family, vendor=vendor, model=model, confidence=conf, hostname=hostname, evidence=ev)

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    role, top = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0.0
    distinct_sources = len({e["source"].split()[0] for e in ev if e.get("implies")})
    if top >= 6 and (top - second) >= 3:
        conf = "high"
    elif top >= 4 or distinct_sources >= 3:
        conf = "medium"
    else:
        conf = "low"
    if not os_family:
        os_family = ROLE_OS.get(role, "")
    return Profile(role=role, os=os_text, os_family=os_family, vendor=vendor, model=model, confidence=conf, hostname=hostname, evidence=ev)


ROLE_FROM_FAMILY = {"windows": "windows", "macos": "workstation", "android": "host", "printer": "printer", "network": "switch", "linux": "server"}

# nmap osclass osfamily -> our os_family
_NMAP_FAMILY = {"windows": "windows", "linux": "linux", "mac os x": "macos", "macos": "macos", "ios": "ios",
                "embedded": "embedded", "ios-xe": "ios", "junos": "junos", "freebsd": "linux", "vmware esxi": "esxi"}


def _best_name(host) -> str:
    names = host.names or {}
    for src in NAME_PRIORITY:
        if names.get(src):
            return names[src]
    return host.hostname or ""


def device_os_family(dev) -> str:
    """OS family for a polled device, from its vendor and sysDescr."""
    d = (dev.sysdescr or "").lower()
    v = (dev.vendor or "").lower()
    if "nx-os" in d or "nexus" in d:
        return "nx-os"
    if "ios-xe" in d or "ios xe" in d:
        return "ios-xe"
    if re.search(r"\bios\b", d) and "cisco" in d:
        return "ios"
    if "junos" in d or "juniper" in v:
        return "junos"
    if "fortios" in d or "fortigate" in d or "fortinet" in v:
        return "fortios"
    if "pan-os" in d or "palo alto" in v:
        return "pan-os"
    if "arubaos" in d or "aruba" in v:
        return "arubaos"
    if "procurve" in d or "provision" in d:
        return "hp-provision"
    if "routeros" in d or "mikrotik" in v:
        return "routeros"
    if "esxi" in d or "vmware" in d:
        return "esxi"
    if "windows" in d:
        return "windows"
    if "linux" in d or "net-snmp" in d:
        return "linux"
    return "network" if dev.role in ("router", "switch", "l3switch", "firewall", "wireless") else ""


def profile_inventory(inv) -> None:
    """Re-profile every non-SNMP host and set OS family on polled devices. Idempotent."""
    for dev in inv.devices.values():
        if not dev.os_family:
            dev.os_family = device_os_family(dev)
    for ip, h in inv.hosts.items():
        if ip in inv.ip_to_device:
            continue
        note = inv.note(ip) if hasattr(inv, "note") else {}
        p = profile_host(h)
        # a role the user set by hand always wins
        if not note.get("role"):
            h.role = p.role
        h.os = p.os or h.os
        h.os_family = p.os_family or h.os_family
        if p.vendor and not h.vendor:
            h.vendor = p.vendor
        if p.model and not h.model:
            h.model = p.model
        h.confidence = p.confidence
        h.evidence = p.evidence
        if p.hostname and not h.hostname:
            h.hostname = p.hostname
