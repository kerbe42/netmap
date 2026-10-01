"""One scan from start to finish: the same code behind `netmap crawl` and the desktop app.

A scan is: work out the scope, find live addresses in the named target subnets, spider
SNMP devices outwards from those and from any seeds, optionally sweep the subnets the
devices revealed, optionally name everything from reverse DNS, identify hosts and
port-scan the ones that answer a ping, and record what happened in the inventory's
history. Callers get progress through a `ScanEvents` object and can stop a scan by
cancelling the task running it; whatever was found up to then is kept.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from . import activity
from .collect import CollectOptions
from .crawl import CrawlConfig, Crawler
from .dns import resolve_names
from .graph import enrich_inventory
from .model import Inventory
from .snmp import Credential
from .sweep import discover_targets, sweep
from .util import RFC1918, in_scope, scope_devices, scope_hosts

log = logging.getLogger("netmap.scan")

NOW_LOG_EVERY = 60.0  # seconds between "working on: ..." log lines


def nets(items) -> list:
    return [ipaddress.ip_network(str(x).strip(), strict=False) for x in items or [] if str(x).strip()]


def resolve_scope(targets: list, scope: list, exclude: list) -> tuple[list, list]:
    """The address ranges a scan may touch, and those it must never touch.

    Named targets are always inside the scope: with no explicit scope they *are* the
    scope, so listing the ranges you were given is enough to stay inside them. With
    neither, the scan is limited to RFC1918 space.
    """
    scope = nets(scope)
    exclude = nets(exclude)
    targets = nets(targets)
    if targets:
        if not scope:
            scope = list(targets)
            log.info("scope taken from the %d target subnet(s) given", len(targets))
        else:
            scope = scope + [t for t in targets if not any(t.subnet_of(s) for s in scope if t.version == s.version)]
    if not scope:
        scope = list(RFC1918)
        log.warning("no scope or targets given; limiting the scan to RFC1918 space (10/8, 172.16/12, 192.168/16)")
    return scope, exclude


@dataclass
class ScanRequest:
    seeds: list[str] = field(default_factory=list)  # devices to spider outwards from
    targets: list[str] = field(default_factory=list)  # subnets to inventory address by address
    scope: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    probe_all: bool = False  # SNMP every address in the targets without pinging first
    sweep: bool = False  # ping-sweep every subnet the devices revealed
    fingerprint: bool = False  # nmap service detection on live hosts
    probe_hosts: bool = False  # try SNMP on every ARP-learned address
    resolve_names: bool = False  # reverse DNS for devices and hosts
    identify: bool = False  # active host identification (NetBIOS, mDNS, SSDP, HTTP/TLS)
    port_scan: bool = False  # nmap service detection on every device and host found
    os_detect: bool = False  # nmap OS detection (-O; needs admin/root)
    top_ports: int = 200  # how many ports nmap checks per address
    ping_first: bool = True  # port-scan only addresses that answer a ping (or SNMP) in this scan
    nmap_timeout: float = 30.0  # minutes one nmap run may take before it is stopped; 0 = no limit
    follow_routes: bool = True
    follow_gateways: bool = True
    arp: bool = True
    fdb: bool = True
    routes: bool = True
    cisco_vlan_fdb: bool = False
    refresh: bool = False  # re-poll devices already in the inventory
    refresh_ids: Optional[list[str]] = None
    retry_unreachable: bool = False
    resweep: bool = False
    max_depth: int = 6
    workers: int = 12
    timeout: float = 2.0
    retries: int = 1
    port: int = 161
    max_devices: int = 5000
    sweep_max_prefix: int = 22  # largest *discovered* subnet the sweep step covers; entered ranges have no cap
    save_path: Optional[str] = None

    def describe(self) -> dict:
        """What was asked for, for the scan history. Credential labels only, never secrets."""
        d = {k: v for k, v in self.__dict__.items() if k not in ("credentials", "save_path")}
        d["credentials"] = [c.label for c in self.credentials]
        return d


class ScanEvents:
    """Progress hooks. Every method runs on the scan's event loop thread and must be quick."""

    def phase(self, name: str, detail: str = "") -> None:
        pass

    def tick(self, inv: Inventory, stats: dict) -> None:
        """About once a second while a scan runs; `inv` is safe to read (or copy) here.
        stats["now"] is a one-line summary of what is in flight (subnets, batches, devices);
        stats["now_all"] lists every item."""

    def device(self, dev) -> None:
        pass


async def run_scan(inv: Inventory, req: ScanRequest, events: Optional[ScanEvents] = None, engine=None, prober=None) -> dict:
    """Run one scan into `inv`. Returns (and appends to inv.history) a record of it.

    Cancelling the task that awaits this stops the scan cleanly: everything collected so
    far stays in the inventory, it is saved, and the record says it was stopped.
    """
    ev = events or ScanEvents()
    started = time.time()
    scope, exclude = resolve_scope(req.targets, req.scope, req.exclude)
    targets = nets(req.targets)
    before = {"devices": set(inv.devices), "hosts": set(inv.hosts), "subnets": set(inv.subnets)}
    stats: dict = {"phase": "starting", "devices": len(inv.devices), "hosts": len(inv.hosts), "elapsed": 0.0}
    state = {"crawler": None, "cancelled": False, "error": ""}
    nmap_limit = req.nmap_timeout * 60 if req.nmap_timeout and req.nmap_timeout > 0 else None
    live: set[str] = set()  # addresses that answered a ping during this scan
    act = activity.Activity()  # what this scan has in flight; the tasks it starts report into it
    activity.use(act)

    async def ticker():
        last_log = time.time()
        while True:
            await asyncio.sleep(1.0)
            c = state["crawler"]
            if c is not None:
                stats.update(c.progress())
            items = act.now()
            stats.update(devices=len(inv.devices), hosts=len(inv.hosts), subnets=len(inv.subnets), elapsed=time.time() - started,
                         now=act.summary(), now_all=[f"{i.kind} {i.describe()}" for i in items[:200]])
            if items and time.time() - last_log >= NOW_LOG_EVERY:
                last_log = time.time()
                log.info("working on: %s", act.summary(limit=4))
            try:
                ev.tick(inv, dict(stats))
            except Exception:  # noqa: BLE001
                log.debug("tick callback failed", exc_info=True)

    def phase(name: str, detail: str = "") -> None:
        stats["phase"] = name
        log.info("== %s%s", name, f": {detail}" if detail else "")
        ev.phase(name, detail)

    tick_task = asyncio.ensure_future(ticker())
    try:
        seeds = list(dict.fromkeys(req.seeds))
        if targets:
            phase("Finding live addresses", f"{len(targets)} target subnet(s)")
            found = await discover_targets(
                inv, targets, scope, exclude,
                fingerprint=req.fingerprint, probe_all=req.probe_all, nmap_timeout=nmap_limit, live=live,
            )
            seeds += [ip for ip in found if ip not in seeds]
            if req.save_path:
                inv.save(req.save_path)
            if not seeds:
                log.warning("nothing answered a ping in the target subnets; check the ranges, or probe every address if ICMP is filtered")
        ccfg = CrawlConfig(
            seeds=seeds,
            credentials=req.credentials,
            scope=scope,
            exclude=exclude,
            max_depth=req.max_depth,
            workers=req.workers,
            timeout=req.timeout,
            retries=req.retries,
            port=req.port,
            probe_hosts=req.probe_hosts,
            follow_routes=req.follow_routes and req.routes,
            follow_gateways=req.follow_gateways,
            collect=CollectOptions(fdb=req.fdb, cisco_vlan_fdb=req.cisco_vlan_fdb, routes=req.routes, arp=req.arp),
            save_path=req.save_path,
            max_devices=req.max_devices,
            refresh=req.refresh,
            refresh_ids=set(req.refresh_ids) if req.refresh_ids is not None else None,
            retry_unreachable=req.retry_unreachable,
            on_device=ev.device,
        )
        phase("Polling devices", f"{len(seeds)} starting point(s), {len(req.credentials)} credential(s)")
        log.info("scope: %s  exclude: %s  creds: %s", [str(n) for n in scope], [str(n) for n in exclude], [c.label for c in req.credentials])
        crawler = Crawler(ccfg, inv, engine=engine, prober=prober)
        state["crawler"] = crawler
        await crawler.run()
        stats.update(crawler.progress())
        if req.sweep:
            phase("Sweeping subnets")
            n = await sweep(inv, list(inv.subnets), scope, exclude, fingerprint=req.fingerprint, max_prefix=req.sweep_max_prefix,
                            resweep=req.resweep, nmap_timeout=nmap_limit, live=live)
            log.info("sweep found %d hosts", n)
        # Everything after the crawl works from the inventory, which may hold addresses this
        # scan is not allowed to touch (a DHCP or hypervisor import, an earlier wider scan):
        # every phase below gets only the in-scope addresses.
        devices_in, hosts_in = scope_devices(inv, scope, exclude), scope_hosts(inv, scope, exclude)
        skipped = (len(inv.devices) - len(devices_in)) + (sum(1 for h in inv.hosts if h not in inv.ip_to_device) - len(hosts_in))
        if skipped and (req.resolve_names or req.identify or req.port_scan):
            log.info("%d address(es) in the inventory are outside this scan's scope and are left alone", skipped)
        if req.resolve_names:
            phase("Resolving names")
            await resolve_names(inv, hosts=devices_in + hosts_in)
        if req.identify:
            from .discover import identify_hosts

            phase("Identifying hosts", "NetBIOS, mDNS, SSDP and web probes")
            n = await identify_hosts(inv, hosts=hosts_in)
            log.info("active identification: %d host(s) answered a probe", n)
            from .discover import probe_management

            m = await probe_management(inv, device_ids=devices_in)
            log.info("management-plane check: %d device(s) expose a management port", m)
            try:
                from .probes_extra import probe_extra

                x = await probe_extra(inv, hosts=hosts_in)
                log.info("broad protocol probes: %d host(s) answered (WS-Discovery/IPMI/OT)", x)
            except ImportError:
                pass
        if req.port_scan:
            from .sweep import live_addresses, nmap_inspect

            ips = devices_in + hosts_in
            if req.ping_first and ips:
                # nmap -Pn spends its whole timeout on every port of an address nobody answers
                # at (a stale ARP entry, a powered-off PC), so only scan what is up. Devices
                # that answered SNMP and hosts this scan's sweeps found are known to be.
                live |= {d for d in devices_in if inv.devices[d].collected_at >= started}
                unknown = [ip for ip in ips if ip not in live]
                if unknown:
                    phase("Checking which addresses are up", f"{len(unknown)} address(es) not yet seen answering in this scan")
                    up = await live_addresses(unknown, nmap_timeout=nmap_limit)
                    live |= up if up is not None else set(unknown)
                silent = [ip for ip in ips if ip not in live]
                if silent:
                    log.info("%d of %d address(es) did not answer a ping and are not port-scanned (they stay in the inventory); "
                             "turn off 'ping first' (--no-ping-first) to scan them anyway", len(silent), len(ips))
                ips = [ip for ip in ips if ip in live]
            phase("Scanning ports", f"nmap service{' and OS' if req.os_detect else ''} detection on {len(ips)} address(es)")
            results = await nmap_inspect(ips, fingerprint=True, os_detect=req.os_detect, top_ports=req.top_ports, nmap_timeout=nmap_limit)
            for ip, rec in results.items():
                _apply_nmap(inv, ip, rec)
            log.info("nmap enriched %d address(es) with ports/OS", len(results))
        if targets and not inv.devices:
            log.warning(
                "no device in the target subnets answered SNMP: %d address(es) were probed and none replied. "
                "Check that the community/v3 user is right, that SNMP is permitted from this host, and that the ranges are the managed ones",
                len(inv.unreachable),
            )
    except asyncio.CancelledError:
        state["cancelled"] = True
        log.warning("scan stopped; keeping what was found so far")
    finally:
        tick_task.cancel()
        enrich_inventory(inv)
    record = {
        "started": started,
        "finished": time.time(),
        "seconds": round(time.time() - started, 1),
        "cancelled": state["cancelled"],
        "request": req.describe(),
        "scope": [str(n) for n in scope],
        "exclude": [str(n) for n in exclude],
        "found": {
            "devices": len(inv.devices),
            "hosts": len(inv.hosts),
            "subnets": len(inv.subnets),
            "new_devices": sorted(set(inv.devices) - before["devices"]),
            "new_hosts": len(set(inv.hosts) - before["hosts"]),
            "new_subnets": sorted(set(inv.subnets) - before["subnets"]),
            "refreshed": (state["crawler"].stats["refreshed"] if state["crawler"] else 0),
        },
    }
    inv.history.append(record)
    if req.save_path:
        inv.save(req.save_path)
    phase("Stopped" if state["cancelled"] else "Finished", inv.summary())
    return record


def _apply_nmap(inv, ip: str, rec: dict) -> None:
    """Fold an nmap result onto a device or host: open ports, and an OS guess where we have
    nothing better. SNMP-derived facts on a device are authoritative and kept."""
    from .util import plausible_mac

    ports = rec.get("ports") or []
    os_str = rec.get("os") or ""
    dev = inv.devices.get(ip)
    if dev is not None:
        if ports:
            dev.ports = ports
        if os_str and not dev.os_detail:
            dev.os_detail = os_str
        if not dev.os_family and rec.get("os_family_raw"):
            dev.os_family = rec["os_family_raw"].lower()
        return
    h = inv.hosts.get(ip)
    if h is None and (ports or os_str):
        h = inv.touch_host(ip, "nmap", rec.get("mac") if plausible_mac(rec.get("mac")) else None)
    if h is None:
        return
    if ports:
        h.ports = ports
    if "nmap" not in h.sources:
        h.sources.append("nmap")
    h.probes["nmap"] = {"os": os_str, "os_accuracy": rec.get("os_accuracy", 0),
                        "os_family": rec.get("os_family_raw", ""), "os_vendor": rec.get("os_vendor", "")}
    if rec.get("hostname") and not h.hostname:
        h.hostname = rec["hostname"]
        h.names.setdefault("nmap", rec["hostname"])
