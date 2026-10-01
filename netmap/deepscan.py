"""Deep scan: one address looked at as thoroughly as nmap can, read-only.

Every TCP port, the full set of service-version probes, OS detection and a traceroute (both
need Administrator/root), the common UDP services on request, and nmap's scripts that are in
both its "default" and "safe" categories: certificates, page titles, SSH host keys, SMB/RDP
names and similar inventory facts, nothing intrusive. The result is kept per address in the
project (`inv.deep_scans`) and folded onto the device or host (open ports, OS guess).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from . import activity
from .sweep import _HOST_RE, _run_nmap, find_nmap, fmt_limit, is_admin
from .util import in_scope

log = logging.getLogger("netmap.deepscan")

# UDP services worth knowing about on an inventory (DNS, DHCP, TFTP, NTP, NetBIOS, SNMP and
# traps, IKE, syslog, RIP, IPMI, SQL browser, SSDP, NAT-T, mDNS, BACnet)
COMMON_UDP = "53,67,69,123,137,138,161,162,500,514,520,623,1434,1900,4500,5353,47808"
SCRIPTS = "default and safe"


@dataclass
class DeepScanOptions:
    udp: bool = False  # the common UDP services as well (needs Administrator/root; slow)
    scripts: bool = True  # nmap's "default and safe" scripts
    os_detect: bool = True  # -O --osscan-guess (needs Administrator/root)
    traceroute: bool = True  # --traceroute (needs Administrator/root)
    timeout: Optional[float] = None  # seconds for the whole run; None = no limit

    def describe(self, admin: bool) -> str:
        bits = ["all TCP ports", "full version detection"]
        if self.udp and admin:
            bits.append("common UDP")
        if self.os_detect and admin:
            bits.append("OS")
        if self.traceroute and admin:
            bits.append("traceroute")
        if self.scripts:
            bits.append("safe scripts")
        return ", ".join(bits)


def deep_args(opts: DeepScanOptions, admin: bool) -> list[str]:
    """nmap arguments for a deep scan. -v makes nmap report each stage as it starts, which
    is what the app shows while the scan runs; -Pn because the address was chosen by hand."""
    args = ["-v", "-Pn", "-T4", "-sV", "--version-all", "-sS" if admin else "-sT"]
    if opts.udp and admin:
        args += ["-sU", "-p", f"T:1-65535,U:{COMMON_UDP}"]
    else:
        args += ["-p-"]
    if opts.os_detect and admin:
        args += ["-O", "--osscan-guess"]
    if opts.traceroute and admin:
        args += ["--traceroute"]
    if opts.scripts:
        args += ["--script", SCRIPTS]
    return args


def _scripts(elem) -> dict:
    return {s.get("id", ""): (s.get("output") or "").strip() for s in elem.findall("script") if s.get("id")}


def parse_deep_xml(text: str, ip: str) -> Optional[dict]:
    """The host record for `ip` from nmap's XML (whole, or cut short at a time limit)."""
    try:
        hosts = list(ET.fromstring(text).iter("host"))
    except ET.ParseError:
        hosts = []
        for block in _HOST_RE.findall(text or ""):
            try:
                hosts.append(ET.fromstring(block))
            except ET.ParseError:
                pass
    for h in hosts:
        addrs = {a.get("addrtype"): a for a in h.findall("address")}
        if addrs.get("ipv4") is None or addrs["ipv4"].get("addr") != ip:
            continue
        rec: dict = {"hostname": "", "mac": "", "vendor": "", "ports": [], "not_shown": [], "os": [],
                     "host_scripts": {}, "uptime": {}, "distance": None, "trace": []}
        if "mac" in addrs:
            rec["mac"] = addrs["mac"].get("addr", "")
            rec["vendor"] = addrs["mac"].get("vendor", "") or ""
        hn = h.find("hostnames/hostname")
        if hn is not None:
            rec["hostname"] = hn.get("name", "")
        for ep in h.findall("ports/extraports"):
            rec["not_shown"].append(f"{int(ep.get('count', 0)):,} {ep.get('state', '')}")
        for p in h.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            sv = svc.attrib if svc is not None else {}
            rec["ports"].append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol", ""),
                "state": st.get("state", "") if st is not None else "",
                "reason": st.get("reason", "") if st is not None else "",
                "service": sv.get("name", ""),
                "product": sv.get("product", ""),
                "version": sv.get("version", ""),
                "extrainfo": sv.get("extrainfo", ""),
                "tunnel": sv.get("tunnel", ""),
                "devicetype": sv.get("devicetype", ""),
                "ostype": sv.get("ostype", ""),
                "cpe": [c.text for c in (svc.findall("cpe") if svc is not None else []) if c.text],
                "scripts": _scripts(p),
            })
        for om in h.findall("os/osmatch")[:5]:
            oc = om.find("osclass")
            rec["os"].append({
                "name": om.get("name", ""),
                "accuracy": int(om.get("accuracy") or 0),
                "family": oc.get("osfamily", "") if oc is not None else "",
                "vendor": oc.get("vendor", "") if oc is not None else "",
                "gen": oc.get("osgen", "") if oc is not None else "",
                "type": oc.get("type", "") if oc is not None else "",
            })
        hs = h.find("hostscript")
        if hs is not None:
            rec["host_scripts"] = _scripts(hs)
        up = h.find("uptime")
        if up is not None:
            rec["uptime"] = {"seconds": int(up.get("seconds") or 0), "lastboot": up.get("lastboot", "")}
        d = h.find("distance")
        if d is not None and d.get("value"):
            rec["distance"] = int(d.get("value"))
        for hop in h.findall("trace/hop"):
            rec["trace"].append({"ttl": int(hop.get("ttl") or 0), "ip": hop.get("ipaddr", ""),
                                 "rtt": hop.get("rtt", ""), "host": hop.get("host", "")})
        return rec
    return None


def standard_ports(rec: dict) -> list[dict]:
    """The open ports in the shape the rest of the inventory uses."""
    out = []
    for p in rec.get("ports") or []:
        if p.get("state") != "open":
            continue
        product = " ".join(x for x in (p.get("product"), p.get("version"), p.get("extrainfo")) if x).strip()
        out.append({"port": p["port"], "proto": p.get("proto", ""), "service": p.get("service", ""), "product": product})
    return out


async def deep_scan(ip: str, opts: Optional[DeepScanOptions] = None) -> dict:
    """Deep-scan one address. Returns the record kept in the project: when, how long, the
    options and nmap arguments, a status ("ok", "timeout", "error" or "no-nmap") and, when
    nmap reported the host, everything parse_deep_xml read."""
    opts = opts or DeepScanOptions()
    started = time.time()
    base = {"ip": ip, "when": started, "seconds": 0.0, "options": asdict(opts), "args": "", "status": "no-nmap", "admin": False}
    if not find_nmap():
        log.warning("nmap not found; install it from nmap.org for deep scans")
        return base
    admin = is_admin()
    skipped = [name for name, on in (("OS detection", opts.os_detect), ("traceroute", opts.traceroute), ("UDP", opts.udp)) if on]
    if not admin and skipped:
        log.warning("%s: %s need%s Administrator/root; skipped", ip, ", ".join(skipped), "s" if len(skipped) == 1 else "")
    args = deep_args(opts, admin)
    log.info("deep scan of %s: %s", ip, opts.describe(admin))
    run = await _run_nmap([*args, ip], opts.timeout, "deep scan", ip)
    rec = parse_deep_xml(run.xml, ip)
    out = {**base, "seconds": round(time.time() - started, 1), "args": " ".join(args), "status": run.status, "admin": admin}
    if rec is not None:
        out.update(rec)
    if run.status == "timeout":
        log.warning("deep scan of %s stopped at its time limit (%s) before nmap finished; raise the limit and scan it again", ip, fmt_limit(opts.timeout))
    elif rec is not None:
        n_open = sum(1 for p in rec["ports"] if p["state"] == "open")
        best = rec["os"][0]["name"] if rec["os"] else ""
        log.info("deep scan of %s: %d open port(s)%s in %s", ip, n_open, f", OS {best}" if best else "",
                 activity.fmt_secs(out["seconds"]))
    return out


def apply_deep_scan(inv, rec: dict) -> None:
    """Keep the record and fold its findings onto the device or host. An address that was
    not in the inventory becomes a host: someone asked about it by name."""
    from .scan import _apply_nmap

    ip = rec["ip"]
    prev = inv.deep_scans.get(ip) or {}
    if not (rec.get("status") == "ok" and "ports" in rec) and prev.get("status") == "ok" and "ports" in prev:
        return  # a failed or unfinished rescan does not replace a finished deep scan
    inv.deep_scans[ip] = rec
    if "ports" not in rec:
        return
    best = rec["os"][0] if rec.get("os") else {}
    _apply_nmap(inv, ip, {"ports": standard_ports(rec), "os": best.get("name", ""), "os_accuracy": best.get("accuracy", 0),
                          "os_family_raw": best.get("family", ""), "os_vendor": best.get("vendor", ""),
                          "hostname": rec.get("hostname", ""), "mac": rec.get("mac", "")})
    if ip not in inv.devices and ip not in inv.ip_to_device and ip not in inv.hosts:
        inv.touch_host(ip, "nmap", rec.get("mac") or None)


async def deep_scan_into(inv, ips: list[str], opts: Optional[DeepScanOptions] = None, scope: Optional[list] = None,
                         exclude: Optional[list] = None, parallel: int = 2, on_done: Optional[Callable[[dict], None]] = None,
                         act: Optional[activity.Activity] = None) -> dict:
    """Deep-scan several addresses (two at a time) into `inv`. Addresses outside `scope` or
    inside `exclude` are refused, never scanned. Returns {"scanned", "refused", "results"}."""
    from .graph import enrich_inventory

    activity.use(act or activity.Activity())  # what is in flight, for the caller to show
    allow = scope if scope is not None else [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]
    todo, refused = [], []
    for ip in dict.fromkeys(ips):
        if in_scope(ip, allow, exclude or []):  # also refuses loopback, multicast and the like
            todo.append(ip)
        else:
            refused.append(ip)
            log.warning("%s is outside the scope or inside an exclusion; not deep-scanned", ip)
    sem = asyncio.Semaphore(parallel)
    results = []

    async def one(ip):
        async with sem:
            rec = await deep_scan(ip, opts)
        apply_deep_scan(inv, rec)
        results.append(rec)
        if on_done:
            on_done(rec)

    try:
        await asyncio.gather(*[one(ip) for ip in todo])
    finally:
        enrich_inventory(inv)
    return {"scanned": len(results), "refused": refused, "results": results}
