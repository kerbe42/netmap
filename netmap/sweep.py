"""Host discovery on subnets: nmap ping sweep (ARP when root), optional service fingerprint; ping fallback.

Every nmap run here is bounded: a sweep runs one nmap per /24 block, a port scan one per small
batch of addresses, and each run has a time limit. A run stopped at its limit keeps every host
nmap had finished (it writes them out a group at a time), and what it had not finished is tried
once more with twice the time, so a slow corner of a large network costs that corner, not the
whole subnet.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from typing import NamedTuple, Optional

from .model import Inventory
from .util import in_scope, norm_mac, plausible_mac, scoped_networks

log = logging.getLogger("netmap.sweep")

# Root: ARP on-link plus ICMP/TCP/UDP probes. Unprivileged: nmap can only do TCP connect pings.
NMAP_PING_OPTS_ROOT = ["-sn", "-PE", "-PP", "-PS22,80,443,445,3389", "-PA80,443", "-PU53,161", "--max-retries", "2"]
NMAP_PING_OPTS_USER = ["-sn", "-PS22,80,443,445,3389,161,8080", "-PA80,443", "--max-retries", "2"]

DEFAULT_NMAP_TIMEOUT = 30 * 60.0  # seconds one nmap run may take before it is stopped
SWEEP_BLOCK = 24  # a sweep runs one nmap per block of this prefix length
NMAP_PARALLEL = 8  # nmap sweep runs at once, across every subnet of a sweep
PING_PARALLEL = 256  # ping processes at once when nmap is not installed


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


_HOST_RE = re.compile(r"<host[\s>].*?</host>", re.S)


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    try:
        elems = list(ET.fromstring(xml_text).iter("host"))
    except ET.ParseError as e:
        # A run stopped at its time limit ends mid-document; every <host> it had finished is whole.
        elems = []
        for block in _HOST_RE.findall(xml_text or ""):
            try:
                elems.append(ET.fromstring(block))
            except ET.ParseError:
                pass
        if not elems and "</nmaprun>" in (xml_text or ""):
            log.warning("could not parse nmap output: %s", e)
    hosts = []
    for h in elems:
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


class NmapRun(NamedTuple):
    xml: str  # what nmap wrote: the whole document, or up to where it was stopped
    status: str  # "ok", "timeout" (stopped at its limit) or "error"


def fmt_limit(seconds: Optional[float]) -> str:
    if not seconds:
        return "no limit"
    m = seconds / 60
    return f"{m:g} min" if m >= 1 else f"{seconds:g} s"


async def _run_nmap(args: list[str], timeout: Optional[float]) -> NmapRun:
    """Run nmap with XML on stdout, for at most `timeout` seconds (None or 0: no limit).

    Output is read as it comes, so a run stopped at its limit still returns every host nmap
    had finished; the caller decides what to try again."""
    cmd = [find_nmap() or "nmap", "-oX", "-", *args]
    log.debug("running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **no_window())
    chunks: list[bytes] = []

    async def drain() -> bytes:
        async def out():
            while True:
                b = await proc.stdout.read(65536)
                if not b:
                    return
                chunks.append(b)

        _, err = await asyncio.gather(out(), proc.stderr.read())
        await proc.wait()
        return err

    try:
        err = await asyncio.wait_for(drain(), timeout=timeout or None)
    except asyncio.TimeoutError:
        proc.kill()
        await _reap(proc)
        try:  # whatever was still in the pipe when it was stopped
            chunks.append(await asyncio.wait_for(proc.stdout.read(), 5))
        except Exception:  # noqa: BLE001
            pass
        return NmapRun(b"".join(chunks).decode(errors="replace"), "timeout")
    except asyncio.CancelledError:
        # the scan was stopped: don't leave nmap running behind the app
        proc.kill()
        await _reap(proc)
        raise
    out = b"".join(chunks).decode(errors="replace")
    if proc.returncode != 0:
        log.warning("nmap exited %s: %s", proc.returncode, err.decode(errors="replace").strip()[:300])
        return NmapRun(out, "error")
    return NmapRun(out, "ok")


class _Progress:
    """Logs "<what>: done/total <unit>" at each quarter, for jobs big enough to take a while."""

    def __init__(self, what: str, total: int, unit: str, min_total: int = 16):
        self.what, self.total, self.unit = what, total, unit
        self.done, self.next = 0, (total // 4 if total >= min_total else total + 1)

    def step(self, n: int = 1, extra: str = "") -> None:
        self.done += n
        if self.done >= self.next and self.done < self.total:
            log.info("%s: %d/%d %s done%s", self.what, self.done, self.total, self.unit, extra)
            self.next = self.done + max(1, self.total // 4)


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


def sweep_addresses(net) -> list:
    """Every address a sweep may try in `net`: the usable hosts of a normal subnet, both
    addresses of a /31 and the single address of a /32 (the network address itself)."""
    net = ipaddress.ip_network(str(net), strict=False)
    if net.prefixlen >= net.max_prefixlen - 1:
        return list(net)
    return list(net.hosts())


def sweep_blocks(pieces: list) -> list:
    """The in-scope pieces of a subnet cut into /24 (or smaller) blocks, one nmap run each."""
    out = []
    for p in pieces:
        if p.version == 4 and p.prefixlen < SWEEP_BLOCK:
            out.extend(p.subnets(new_prefix=SWEEP_BLOCK))
        else:
            out.append(p)
    return out


async def _ping_targets(targets: list[str], label: str, timeout: Optional[float], sem: asyncio.Semaphore) -> tuple[list[dict], str]:
    """nmap host discovery on `targets`. Returns (live host records, status of the last run).

    A sweep lists only the hosts that answered, so a run stopped at its limit cannot say which
    addresses it had finished: the whole set is tried again with twice the time, and what both
    runs found is kept."""
    args = [*nmap_ping_opts(), *targets]
    async with sem:
        run = await _run_nmap(args, timeout)
    hosts = {h["ip"]: h for h in _parse_nmap_xml(run.xml)}
    if run.status != "timeout":
        return list(hosts.values()), run.status
    log.warning("nmap reached its %s limit pinging %s; kept the %d live address(es) it had reported, trying again with %s",
                fmt_limit(timeout), label, len(hosts), fmt_limit(timeout * 2))
    async with sem:
        run = await _run_nmap(args, timeout * 2)
    for h in _parse_nmap_xml(run.xml):
        hosts.setdefault(h["ip"], h)
    if run.status == "timeout":
        log.warning("nmap could not finish pinging %s even with %s (%d live so far); raise the nmap time limit and sweep it again",
                    label, fmt_limit(timeout * 2), len(hosts))
    return list(hosts.values()), run.status


async def sweep_subnet(cidr: str, nmap_timeout: Optional[float] = DEFAULT_NMAP_TIMEOUT, scope: Optional[list] = None,
                       exclude: Optional[list] = None, nmap_sem: Optional[asyncio.Semaphore] = None,
                       ping_sem: Optional[asyncio.Semaphore] = None) -> tuple[list[dict], bool]:
    """Find live addresses in `cidr`. Returns (host records, whether every part was finished).

    With `scope`/`exclude` given, only the part of the subnet inside the scope and outside
    every excluded range is ever probed: nmap gets exactly those ranges, cut into /24 blocks
    that run side by side (up to the shared `nmap_sem`), and the ping fallback skips
    everything else."""
    net = ipaddress.ip_network(cidr, strict=False)
    if scope is None:
        pieces = [net]
    else:
        pieces = scoped_networks(net, scope, exclude or [])
        if not pieces:
            log.warning("%s lies entirely outside the scope/exclude rules; not swept", net)
            return [], True
        if pieces != [net]:
            log.info("%s: sweeping only the in-scope part: %s", net, ", ".join(str(p) for p in pieces))
    if find_nmap():
        if not is_admin():
            log.warning("not elevated: nmap will use TCP pings only (no ARP/ICMP); run with sudo / as Administrator for full host discovery")
        blocks = sweep_blocks(pieces)
        sem = nmap_sem or asyncio.Semaphore(NMAP_PARALLEL)
        progress = _Progress(str(net), len(blocks), "blocks")
        found: list[dict] = []

        async def block(b):
            hosts, status = await _ping_targets([str(b)], str(b), nmap_timeout, sem)
            found.extend(hosts)
            progress.step(extra=f", {len(found)} live so far")
            return status != "timeout"

        finished = await asyncio.gather(*[block(b) for b in blocks])
        return found, all(finished)
    log.warning("nmap not found; falling back to ICMP ping only (no MAC/vendor data)")
    sem = ping_sem or asyncio.Semaphore(PING_PARALLEL)
    addrs = [str(ip) for ip in sweep_addresses(net) if any(ip in p for p in pieces)]
    results = await asyncio.gather(*[_ping(ip, sem) for ip in addrs])
    return [{"ip": ip, "mac": None, "vendor": "", "hostname": "", "ports": []} for ip in results if ip], True


async def live_addresses(ips: list[str], nmap_timeout: Optional[float] = DEFAULT_NMAP_TIMEOUT,
                         parallel: int = NMAP_PARALLEL, batch: int = 256) -> Optional[set[str]]:
    """Which of `ips` answer nmap's host discovery (the same probes as a sweep).

    Addresses in a batch nmap could not finish even on its retry, or in a run that failed,
    count as up: an unknown is scanned rather than left out. None when nmap is not installed."""
    if not find_nmap():
        return None
    ips = list(dict.fromkeys(ips))
    sem = asyncio.Semaphore(parallel)
    progress = _Progress("ping check", len(ips), "addresses", min_total=batch * 4)
    up: set[str] = set()

    async def one(chunk: list[str]):
        hosts, status = await _ping_targets(chunk, f"{len(chunk)} address(es) from {chunk[0]}", nmap_timeout, sem)
        up.update(h["ip"] for h in hosts)
        if status != "ok":
            up.update(chunk)
        progress.step(len(chunk))

    await asyncio.gather(*[one(ips[i:i + batch]) for i in range(0, len(ips), batch)])
    return up


async def nmap_inspect(ips: list[str], fingerprint: bool = True, os_detect: bool = False,
                       top_ports: int = 200, batch: int = 24, nmap_timeout: Optional[float] = DEFAULT_NMAP_TIMEOUT,
                       parallel: int = 4) -> dict[str, dict]:
    """Scan specific addresses (the devices and hosts already found) for open ports, service
    versions and - with -O, which needs privilege - the OS. Returns {ip: parsed record} for
    the addresses with an open port or an OS guess.

    This is what fills in ports and a real OS guess, whether a host came from SNMP, ARP or a
    sweep; it is not limited to a subnet sweep. Addresses go to nmap in batches; the ones a
    batch had not finished when it reached its time limit are scanned again in smaller
    batches with twice the time, and any still unfinished are named in a warning."""
    if not find_nmap() or not ips:
        if not find_nmap():
            log.warning("nmap not found; install it for port, service and OS detection")
        return {}
    admin = is_admin()
    if os_detect and not admin:
        log.warning("OS detection (-O) needs raw sockets; run as root/Administrator. Doing service detection only")
    args = []
    if fingerprint:
        args += ["-sV", "--version-light"]
    if os_detect and admin:
        args += ["-O", "--osscan-limit"]
    # No --open: every address nmap finishes is then in its output, which is how a run stopped
    # at its limit tells the finished addresses from the ones still to do.
    args += ["--top-ports", str(top_ports), "-T4", "-Pn", "-n"]
    out: dict[str, dict] = {}
    done: set[str] = set()
    sem = asyncio.Semaphore(parallel)
    ips = list(dict.fromkeys(ips))
    progress = _Progress("port scan", len(ips), "addresses", min_total=batch * parallel * 2)

    async def one(chunk: list[str], limit) -> list[str]:
        async with sem:
            run = await _run_nmap(args + chunk, limit)
        for rec in _parse_nmap_xml(run.xml):
            ip = rec.get("ip")
            if ip:
                done.add(ip)
                if rec["ports"] or rec.get("os"):
                    out[ip] = rec
        left = [ip for ip in chunk if ip not in done] if run.status == "timeout" else []
        progress.step(len(chunk) - len(left))
        return left

    async def pass_(items: list[str], size: int, limit) -> list[str]:
        lefts = await asyncio.gather(*[one(items[i:i + size], limit) for i in range(0, len(items), size)])
        return [ip for left in lefts for ip in left]

    left = await pass_(ips, batch, nmap_timeout)
    if left:
        log.warning("nmap reached its %s limit before finishing %d address(es); scanning those again in smaller batches with %s",
                    fmt_limit(nmap_timeout), len(left), fmt_limit(nmap_timeout * 2))
        left = await pass_(left, max(1, batch // 4), nmap_timeout * 2)
        if left:
            log.warning("nmap could not finish %d address(es) even with %s: %s. Raise the nmap time limit and scan them again",
                        len(left), fmt_limit(nmap_timeout * 2), ", ".join(left[:10]) + (" ..." if len(left) > 10 else ""))
    log.info("nmap inspected %d/%d addresses (ports%s)", len(out), len(ips), ", OS" if (os_detect and admin) else "")
    return out


def _record_host(inv: Inventory, rec: dict) -> None:
    h = inv.touch_host(rec["ip"], "sweep", rec["mac"])
    if rec["hostname"] and not h.hostname:
        h.hostname = rec["hostname"]
    if rec["vendor"] and not h.vendor:
        h.vendor = rec["vendor"]
    if rec["ports"]:
        h.ports = rec["ports"]
    h.role = classify_host(h.ports, h.vendor, h.hostname)


async def _fingerprint(inv: Inventory, ips: list[str], nmap_timeout: Optional[float]) -> None:
    """Light service scan of the addresses a sweep found, once every subnet has been pinged."""
    recs = await nmap_inspect(ips, fingerprint=True, top_ports=25, nmap_timeout=nmap_timeout)
    for ip, rec in recs.items():
        h = inv.hosts.get(ip)
        if h is not None and rec["ports"]:
            h.ports = rec["ports"]
            h.role = classify_host(h.ports, h.vendor, h.hostname)


async def discover_targets(
    inv: Inventory,
    targets: list,
    scope: list,
    exclude: list,
    fingerprint: bool = False,
    probe_all: bool = False,
    max_prefix: int = 22,
    parallel: int = NMAP_PARALLEL,
    nmap_timeout: Optional[float] = DEFAULT_NMAP_TIMEOUT,
    live: Optional[set] = None,
) -> list[str]:
    """Find candidate addresses inside the subnets the operator asked for.

    Returns the addresses worth trying SNMP against. With `probe_all` every usable
    address in each target is returned without pinging first, for networks that drop
    ICMP but permit SNMP; otherwise a ping sweep decides, and whatever answers is also
    recorded as a host (MAC, vendor, open ports) so non-SNMP kit still shows up, and
    added to `live` when given. Every target is pinged before any is fingerprinted.
    """
    nets = []
    for t in targets:
        net = ipaddress.ip_network(str(t), strict=False)
        if not scoped_networks(net, scope, exclude):
            # nothing in it may be touched: an excluded /32, or a range outside the scope
            log.warning("target %s is outside the scope/exclude rules; skipping", net)
            continue
        nets.append(net)
        inv.add_subnet(str(net), "target")
    if not nets:
        return []

    if probe_all:
        ips = []
        for net in nets:
            # /31 (RFC 3021) has two usable p2p addresses; a /32 is the single address.
            hosts = sweep_addresses(net)
            if net.prefixlen < max_prefix:
                log.warning("target %s is larger than /%d; --probe-all would send %d probes, skipping", net, max_prefix, len(hosts))
                continue
            ips += [str(ip) for ip in hosts if in_scope(str(ip), scope, exclude)]
        log.info("targets: %d addresses queued for SNMP (no ping first)", len(ips))
        return ips

    log.info("discovering live addresses in %d target subnet(s)%s", len(nets), " with fingerprinting" if fingerprint else "")
    nmap_sem, ping_sem = asyncio.Semaphore(parallel), asyncio.Semaphore(PING_PARALLEL)
    found: list[str] = []

    async def one(net):
        if net.prefixlen < max_prefix:
            log.warning("skipping target %s: larger than /%d (raise the largest subnet to sweep, --sweep-max-size, to include it)", net, max_prefix)
            return
        hosts, complete = await sweep_subnet(str(net), nmap_timeout=nmap_timeout, scope=scope, exclude=exclude, nmap_sem=nmap_sem, ping_sem=ping_sem)
        n = 0
        for rec in hosts:
            if not in_scope(rec["ip"], scope, exclude):
                continue
            _record_host(inv, rec)
            found.append(rec["ip"])
            n += 1
        inv.subnets[str(net)].swept = complete
        log.info("target %s: %d addresses responded%s", net, n, "" if complete else " (sweep not finished; see above)")

    await asyncio.gather(*[one(n) for n in nets])
    if live is not None:
        live.update(found)
    if fingerprint and found:
        await _fingerprint(inv, found, nmap_timeout)
    log.info("targets: %d live addresses queued for SNMP", len(found))
    return found


async def sweep(inv: Inventory, subnets: list[str], scope: list, exclude: list, fingerprint: bool = False, max_prefix: int = 22,
                parallel: int = NMAP_PARALLEL, resweep: bool = False, nmap_timeout: Optional[float] = DEFAULT_NMAP_TIMEOUT,
                live: Optional[set] = None) -> int:
    """Ping-sweep `subnets` (those not swept yet, unless `resweep`) and add what answers as
    hosts; with `fingerprint`, then service-scan them. A subnet is marked swept only when
    every block of it finished, so the next sweep picks up one that ran out of time."""
    todo = []
    for cidr in subnets:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen < max_prefix:
            log.info("skipping %s: larger than /%d (raise --sweep-max-size to include)", cidr, max_prefix)
            continue
        if not scoped_networks(net, scope, exclude):
            log.info("skipping %s: out of scope", cidr)
            continue
        s = inv.add_subnet(str(net), "sweep")
        if s.swept and not resweep:
            continue
        todo.append(str(net))
    if not todo:
        return 0
    log.info("sweeping %d subnets%s", len(todo), " with fingerprinting" if fingerprint else "")
    nmap_sem, ping_sem = asyncio.Semaphore(parallel), asyncio.Semaphore(PING_PARALLEL)
    found: list[str] = []

    async def one(cidr: str):
        hosts, complete = await sweep_subnet(cidr, nmap_timeout=nmap_timeout, scope=scope, exclude=exclude, nmap_sem=nmap_sem, ping_sem=ping_sem)
        n = 0
        for rec in hosts:
            if not in_scope(rec["ip"], scope, exclude):
                continue
            _record_host(inv, rec)
            found.append(rec["ip"])
            n += 1
        inv.subnets[cidr].swept = complete
        log.info("%s: %d hosts up%s", cidr, n, "" if complete else " (sweep not finished; see above)")

    await asyncio.gather(*[one(c) for c in todo])
    if live is not None:
        live.update(found)
    if fingerprint and found:
        await _fingerprint(inv, found, nmap_timeout)
    return len(found)
