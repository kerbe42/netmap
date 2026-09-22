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
from .util import in_scope, norm_mac

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


def ping_args(ip: str) -> list[str]:
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", "1000", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


def classify_host(ports: list[dict], vendor: str, hostname: str) -> str:
    ps = {p["port"] for p in ports}
    v = (vendor or "").lower()
    if {9100, 631} & ps or any(k in v for k in ("hp inc", "hewlett", "xerox", "ricoh", "kyocera", "brother", "canon", "lexmark")):
        return "printer"
    if 5060 in ps or any(k in v for k in ("polycom", "yealink", "grandstream", "snom", "avaya")):
        return "phone"
    if {554, 8554} & ps or any(k in v for k in ("axis", "hikvision", "dahua", "hanwha")):
        return "camera"
    if any(k in v for k in ("vmware", "xensource", "microsoft corp", "nutanix", "proxmox", "qemu")):
        return "vm"
    if {3389, 445, 135} & ps and not (22 in ps):
        return "windows"
    if {3306, 5432, 1433, 1521, 27017, 6379} & ps:
        return "database"
    if {80, 443, 8080, 8443} & ps and 22 in ps:
        return "server"
    if 22 in ps:
        return "server"
    if any(k in v for k in ("apple", "samsung", "intel", "dell", "lenovo", "asus", "raspberry")):
        return "workstation"
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
                rec["mac"] = norm_mac(a.get("addr"))
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
                    "product": " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else "",
                }
            )
        if rec["ip"]:
            hosts.append(rec)
    return hosts


async def _run_nmap(args: list[str], timeout: float) -> Optional[str]:
    cmd = ["nmap", "-oX", "-", *args]
    log.debug("running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        log.warning("nmap timed out: %s", " ".join(args))
        return None
    if proc.returncode != 0:
        log.warning("nmap exited %s: %s", proc.returncode, err.decode(errors="replace").strip()[:300])
        return None
    return out.decode(errors="replace")


async def _ping(ip: str, sem: asyncio.Semaphore) -> Optional[str]:
    async with sem:
        proc = await asyncio.create_subprocess_exec(*ping_args(ip), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        # Windows ping exits 0 even for "Destination host unreachable"; require a TTL in the reply.
        ok = proc.returncode == 0 and (sys.platform != "win32" or b"TTL=" in out)
        return ip if ok else None


async def sweep_subnet(cidr: str, fingerprint: bool = False, nmap_timeout: float = 900.0, top_ports: int = 25) -> list[dict]:
    net = ipaddress.ip_network(cidr)
    if shutil.which("nmap"):
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
