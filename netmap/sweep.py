"""Host discovery on subnets: nmap ping sweep (ARP when root), optional service fingerprint; ping fallback."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil
import sys
import xml.etree.ElementTree as ET
from typing import Optional

from .model import Inventory
from .util import in_scope, norm_mac, plausible_mac

log = logging.getLogger("netmap.sweep")

# Root: ARP on-link plus ICMP/TCP/UDP probes. Unprivileged: nmap can only do TCP connect pings.
NMAP_PING_OPTS_ROOT = ["-sn", "-PE", "-PP", "-PS22,80,443,445,3389", "-PA80,443", "-PU53,161", "--max-retries", "2"]
NMAP_PING_OPTS_USER = ["-sn", "-PS22,80,443,445,3389,161,8080", "-PA80,443", "--max-retries", "2"]


def is_admin() -> bool:
    """root on POSIX, elevated Administrator on Windows (needed for raw-socket scans)."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


def nmap_ping_opts() -> list[str]:
    return NMAP_PING_OPTS_ROOT if is_admin() else NMAP_PING_OPTS_USER


def find_nmap() -> Optional[str]:
    """nmap on PATH, or where the Windows installer puts it (it does not always add itself to PATH)."""
    found = shutil.which("nmap")
    if found or sys.platform != "win32":
        return found
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), r"C:\Program Files (x86)", r"C:\Program Files"):
        if base:
            cand = os.path.join(base, "Nmap", "nmap.exe")
            if os.path.isfile(cand):
                return cand
    return None


def no_window() -> dict:
    """subprocess kwargs that stop a console window flashing up for every ping/nmap when
    netmap runs as a windowed desktop app on Windows. No-op elsewhere."""
    if sys.platform == "win32":
        import subprocess

        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


def ping_args(ip: str) -> list[str]:
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", "1000", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


# Device families worth separating in an asset inventory, matched on the MAC's OUI
# organization. Open ports win where they are decisive; the OUI is often all a host gives us.
VENDOR_ROLES = [
    ("printer", ("hp inc", "hewlett", "xerox", "ricoh", "kyocera", "brother", "canon", "lexmark", "zebra", "sato corp", "epson", "oki electric", "sharp corp", "konica", "toshiba tec")),
    ("phone", ("polycom", "yealink", "grandstream", "snom", "avaya", "mitel", "audiocodes", "unify")),
    ("camera", ("axis communication", "hikvision", "dahua", "hanwha", "mobotix", "vivotek", "bosch security", "uniview", "verkada")),
    ("ups", ("american power conversion", "apc by", "eaton", "tripp lite", "vertiv", "schneider electric", "riello", "socomec")),
    ("nas", ("synology", "qnap", "netapp", "buffalo.inc", "western digital", "drobo", "terra master")),
    ("wireless", ("aerohive", "ruckus", "extreme networks wireless")),
    ("vm", ("vmware", "xensource", "microsoft corp", "nutanix", "proxmox", "qemu", "parallels", "oracle virtual")),
    ("workstation", ("apple", "samsung", "intel", "dell", "lenovo", "asus", "raspberry", "micro-star", "gigabyte", "hon hai", "wistron", "compal")),
]


def classify_host(ports: list[dict], vendor: str, hostname: str) -> str:
    ps = {p["port"] for p in ports}
    v = (vendor or "").lower()

    def vendor_role() -> str:
        if v in ("hp", "hp inc", "hewlett packard"):
            return "printer"  # HP's own OUIs are mostly on printers; its PCs use Intel/Realtek NICs
        for role, keys in VENDOR_ROLES:
            if any(k in v for k in keys):
                if role == "printer" and "enterprise" in v:
                    continue  # Hewlett Packard Enterprise: servers and Aruba kit, not printers
                return role
        return ""

    vr = vendor_role()
    if {9100, 631, 515} & ps or vr == "printer":
        return "printer"
    if 5060 in ps or vr == "phone":
        return "phone"
    if {554, 8554} & ps or vr == "camera":
        return "camera"
    if vr in ("ups", "nas", "wireless", "vm"):
        return vr
    if {5000, 5001, 2049} & ps and {445, 139} & ps:
        return "nas"
    if {3389, 445, 135} & ps and not (22 in ps):
        return "windows"
    if {3306, 5432, 1433, 1521, 27017, 6379} & ps:
        return "database"
    if {80, 443, 8080, 8443} & ps and 22 in ps:
        return "server"
    if 22 in ps:
        return "server"
    if vr:
        return vr
    return "host"


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log.warning("could not parse nmap output: %s", e)
        return hosts
    for h in root.iter("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        rec = {"ip": None, "mac": None, "vendor": "", "hostname": "", "ports": []}
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                rec["ip"] = a.get("addr")
            elif a.get("addrtype") == "mac":
                m = norm_mac(a.get("addr"))
                if m and plausible_mac(m):
                    rec["mac"] = m
                    rec["vendor"] = a.get("vendor", "") or ""
        hn = h.find("hostnames/hostname")
        if hn is not None:
            rec["hostname"] = hn.get("name", "")
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            rec["ports"].append(
                {
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol"),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": " ".join(filter(None, [svc.get("product"), svc.get("version"), svc.get("extrainfo")])).strip() if svc is not None else "",
                }
            )
        # OS detection (nmap -O): the best osmatch, with family/vendor from its first osclass
        best = None
        for om in h.findall("os/osmatch"):
            acc = int(om.get("accuracy") or 0)
            if best is None or acc > best[0]:
                oc = om.find("osclass")
                best = (acc, om.get("name", ""), (oc.get("osfamily") if oc is not None else "") or "", (oc.get("vendor") if oc is not None else "") or "")
        if best:
            rec["os"], rec["os_accuracy"] = best[1], best[0]
            rec["os_family_raw"], rec["os_vendor"] = best[2], best[3]
        if rec["ip"]:
            hosts.append(rec)
    return hosts


async def _reap(proc) -> None:
    """Await a killed subprocess so it doesn't linger as a zombie / ResourceWarning."""
    try:
        await proc.wait()
    except Exception:  # noqa: BLE001
        pass


async def _run_nmap(args: list[str], timeout: float) -> Optional[str]:
    cmd = [find_nmap() or "nmap", "-oX", "-", *args]
    log.debug("running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **no_window())
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await _reap(proc)
        log.warning("nmap timed out: %s", " ".join(args))
        return None
    except asyncio.CancelledError:
        # the scan was stopped: don't leave nmap running behind the app
        proc.kill()
        await _reap(proc)
        raise
    if proc.returncode != 0:
        log.warning("nmap exited %s: %s", proc.returncode, err.decode(errors="replace").strip()[:300])
        return None
    return out.decode(errors="replace")


async def _ping(ip: str, sem: asyncio.Semaphore) -> Optional[str]:
    async with sem:
        proc = await asyncio.create_subprocess_exec(*ping_args(ip), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, **no_window())
        try:
            out, _ = await proc.communicate()
        except asyncio.CancelledError:
            proc.kill()
            await _reap(proc)
            raise
        # Windows ping exits 0 even for "Destination host unreachable"; require a TTL in the reply.
        ok = proc.returncode == 0 and (sys.platform != "win32" or b"TTL=" in out)
        return ip if ok else None


async def sweep_subnet(cidr: str, fingerprint: bool = False, nmap_timeout: float = 900.0, top_ports: int = 25) -> list[dict]:
    net = ipaddress.ip_network(cidr)
    if find_nmap():
        if not is_admin():
            log.warning("not elevated: nmap will use TCP pings only (no ARP/ICMP); run with sudo / as Administrator for full host discovery")
        xml = await _run_nmap([*nmap_ping_opts(), str(net)], nmap_timeout)
        hosts = _parse_nmap_xml(xml) if xml else []
        if fingerprint and hosts:
            targets = [h["ip"] for h in hosts]
            scan_type = "-sS" if is_admin() else "-sT"
            xml2 = await _run_nmap([scan_type, "-sV", "--version-light", "--top-ports", str(top_ports), "-T4", "--open", "-Pn", "-n", *targets], nmap_timeout * 2)
            if xml2:
                by_ip = {h["ip"]: h for h in _parse_nmap_xml(xml2)}
                for h in hosts:
                    if h["ip"] in by_ip:
                        h["ports"] = by_ip[h["ip"]]["ports"]
        return hosts
    log.warning("nmap not found; falling back to ICMP ping only (no MAC/vendor data)")
    sem = asyncio.Semaphore(128)
    results = await asyncio.gather(*[_ping(str(ip), sem) for ip in net.hosts()])
    return [{"ip": ip, "mac": None, "vendor": "", "hostname": "", "ports": []} for ip in results if ip]


async def nmap_inspect(ips: list[str], fingerprint: bool = True, os_detect: bool = False,
                       top_ports: int = 200, batch: int = 24, nmap_timeout: float = 600.0) -> dict[str, dict]:
    """Scan specific addresses (the devices and hosts already found) for open ports, service
    versions and - with -O, which needs privilege - the OS. Returns {ip: parsed record}.

    This is what fills in ports and a real OS guess, whether a host came from SNMP, ARP or a
    sweep; it is not limited to a subnet sweep."""
    if not find_nmap() or not ips:
        if not find_nmap():
            log.warning("nmap not found; install it for port, service and OS detection")
        return {}
    admin = is_admin()
    if os_detect and not admin:
        log.warning("OS detection (-O) needs raw sockets; run as root/Administrator. Doing service detection only")
    out: dict[str, dict] = {}
    sem = asyncio.Semaphore(4)
    ips = list(dict.fromkeys(ips))

    async def one(chunk: list[str]):
        args = []
        if fingerprint:
            args += ["-sV", "--version-light"]
        if os_detect and admin:
            args += ["-O", "--osscan-limit"]
        args += ["--top-ports", str(top_ports), "-T4", "--open", "-Pn", "-n"]
        if not args or (not fingerprint and not (os_detect and admin)):
            args = ["--top-ports", str(top_ports), "-T4", "--open", "-Pn", "-n"]
        async with sem:
            xml = await _run_nmap(args + chunk, nmap_timeout)
        for rec in (_parse_nmap_xml(xml) if xml else []):
            if rec.get("ip"):
                out[rec["ip"]] = rec

    await asyncio.gather(*[one(ips[i:i + batch]) for i in range(0, len(ips), batch)])
    log.info("nmap inspected %d/%d addresses (ports%s)", len(out), len(ips), ", OS" if (os_detect and admin) else "")
    return out


async def discover_targets(
    inv: Inventory,
    targets: list,
    scope: list,
    exclude: list,
    fingerprint: bool = False,
    probe_all: bool = False,
    max_prefix: int = 22,
    parallel: int = 4,
) -> list[str]:
    """Find candidate addresses inside the subnets the operator asked for.

    Returns the addresses worth trying SNMP against. With `probe_all` every usable
    address in each target is returned without pinging first, for networks that drop
    ICMP but permit SNMP; otherwise a ping sweep decides, and whatever answers is also
    recorded as a host (MAC, vendor, open ports) so non-SNMP kit still shows up.
    """
    nets = []
    for t in targets:
        net = ipaddress.ip_network(str(t), strict=False)
        if not in_scope(str(net.network_address + 1), scope, exclude) and net.prefixlen < 32:
            log.warning("target %s is outside the scope/exclude rules; skipping", net)
            continue
        nets.append(net)
        inv.add_subnet(str(net), "target")
    if not nets:
        return []

    if probe_all:
        ips = []
        for net in nets:
            # /31 (RFC 3021) has two usable p2p addresses - net.hosts() yields both;
            # only a /32 is the single address.
            hosts = [net.network_address] if net.prefixlen == 32 else list(net.hosts())
            if net.prefixlen < max_prefix:
                log.warning("target %s is larger than /%d; --probe-all would send %d probes, skipping", net, max_prefix, len(hosts))
                continue
            ips += [str(ip) for ip in hosts if in_scope(str(ip), scope, exclude)]
        log.info("targets: %d addresses queued for SNMP (no ping first)", len(ips))
        return ips

    log.info("discovering live addresses in %d target subnet(s)%s", len(nets), " with fingerprinting" if fingerprint else "")
    sem = asyncio.Semaphore(parallel)
    live: list[str] = []

    async def one(net):
        if net.prefixlen < max_prefix:
            log.info("skipping target %s: larger than /%d (raise --sweep-max-size to include)", net, max_prefix)
            return
        async with sem:
            hosts = await sweep_subnet(str(net), fingerprint=fingerprint)
        for rec in hosts:
            if not in_scope(rec["ip"], scope, exclude):
                continue
            h = inv.touch_host(rec["ip"], "sweep", rec["mac"])
            if rec["hostname"] and not h.hostname:
                h.hostname = rec["hostname"]
            if rec["vendor"] and not h.vendor:
                h.vendor = rec["vendor"]
            if rec["ports"]:
                h.ports = rec["ports"]
            h.role = classify_host(h.ports, h.vendor, h.hostname)
            live.append(rec["ip"])
        inv.subnets[str(net)].swept = True
        log.info("target %s: %d addresses responded", net, len(hosts))

    await asyncio.gather(*[one(n) for n in nets])
    log.info("targets: %d live addresses queued for SNMP", len(live))
    return live


async def sweep(inv: Inventory, subnets: list[str], scope: list, exclude: list, fingerprint: bool = False, max_prefix: int = 22, parallel: int = 4, resweep: bool = False) -> int:
    todo = []
    for cidr in subnets:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen < max_prefix:
            log.info("skipping %s: larger than /%d (raise --sweep-max-size to include)", cidr, max_prefix)
            continue
        if not in_scope(str(net.network_address + 1), scope, exclude):
            log.info("skipping %s: out of scope", cidr)
            continue
        s = inv.add_subnet(str(net), "sweep")
        if s.swept and not resweep:
            continue
        todo.append(str(net))
    if not todo:
        return 0
    log.info("sweeping %d subnets%s", len(todo), " with fingerprinting" if fingerprint else "")
    sem = asyncio.Semaphore(parallel)
    found = 0

    async def one(cidr: str):
        nonlocal found
        async with sem:
            hosts = await sweep_subnet(cidr, fingerprint=fingerprint)
        for rec in hosts:
            if not in_scope(rec["ip"], scope, exclude):
                continue
            h = inv.touch_host(rec["ip"], "sweep", rec["mac"])
            if rec["hostname"] and not h.hostname:
                h.hostname = rec["hostname"]
            if rec["vendor"] and not h.vendor:
                h.vendor = rec["vendor"]
            if rec["ports"]:
                h.ports = rec["ports"]
            h.role = classify_host(h.ports, h.vendor, h.hostname)
            found += 1
        inv.subnets[cidr].swept = True
        log.info("%s: %d hosts up", cidr, len(hosts))

    await asyncio.gather(*[one(c) for c in todo])
    return found
