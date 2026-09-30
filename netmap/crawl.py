"""Breadth-first crawler: seeds -> SNMP -> neighbors/next-hops/gateways -> repeat, inside a scope."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

from .collect import CollectOptions, collect_device
from .model import Device, Inventory
from .snmp import Credential, probe
from .util import RFC1918, in_scope, is_usable_ip

log = logging.getLogger("netmap.crawl")


@dataclass
class CrawlConfig:
    seeds: list[str]
    credentials: list[Credential]
    scope: list = field(default_factory=lambda: list(RFC1918))
    exclude: list = field(default_factory=list)
    max_depth: int = 6
    workers: int = 12
    timeout: float = 2.0
    retries: int = 1
    port: int = 161
    probe_hosts: bool = False  # also try SNMP on every ARP-learned IP (finds APs, printers, servers)
    follow_routes: bool = True
    follow_gateways: bool = True  # try the first usable address of each discovered subnet
    collect: CollectOptions = field(default_factory=CollectOptions)
    save_path: Optional[str] = None
    max_devices: int = 5000
    progress_every: int = 1
    # Rescan: re-poll devices already in the inventory instead of skipping them. `refresh_ids`
    # narrows that to particular devices (e.g. "rescan this switch"); None means all of them.
    refresh: bool = False
    refresh_ids: Optional[set] = None
    retry_unreachable: bool = False  # try again addresses that did not answer last time
    on_device: Optional[Callable] = None  # called with each Device as it is added


class Crawler:
    def __init__(self, cfg: CrawlConfig, inv: Inventory, engine: Optional[SnmpEngine] = None, collector=None, prober=None):
        self.cfg = cfg
        self.inv = inv
        self.engine = engine
        self.collector = collector or collect_device
        self.prober = prober or probe
        self.queue: asyncio.Queue = asyncio.Queue()
        self.queued: set[str] = set()
        # Devices to collect again even though we know them; everything else already in the
        # inventory is skipped, which is what makes --resume cheap.
        if cfg.refresh:
            self.refresh_pending: set[str] = set(cfg.refresh_ids if cfg.refresh_ids is not None else inv.devices) & set(inv.devices)
        else:
            self.refresh_pending = set()
        self.refreshing: set[str] = set()
        self.tried: set[str] = set(inv.devices) - self.refresh_pending
        if not cfg.retry_unreachable:
            self.tried |= set(inv.unreachable)
        self.stats = {"probed": 0, "devices": 0, "refreshed": 0, "no_snmp": 0, "skipped_scope": 0, "new_devices": []}
        self._started = time.time()

    # ---- queue management ----
    def enqueue(self, ip: str, depth: int, via: str) -> bool:
        if not is_usable_ip(ip):
            return False
        known = self.inv.ip_to_device.get(ip)
        if known is not None:
            if known not in self.refresh_pending:
                return False
            # a device due for a rescan, reached via any of its addresses: poll its usual one
            self.refresh_pending.discard(known)
            self.refreshing.add(known)
            ip = known
        if ip in self.queued or ip in self.tried:
            return False
        if not in_scope(ip, self.cfg.scope, self.cfg.exclude):
            self.stats["skipped_scope"] += 1
            log.debug("out of scope: %s (via %s)", ip, via)
            return False
        if depth > self.cfg.max_depth:
            log.debug("max depth reached at %s (via %s)", ip, via)
            return False
        self.queued.add(ip)
        self.queue.put_nowait((ip, depth, via))
        return True

    def _enqueue_from_device(self, dev: Device) -> int:
        n = 0
        d = dev.depth + 1
        for nb in dev.neighbors:
            for ip in nb.remote_mgmt_ips:
                n += self.enqueue(ip, d, f"{nb.proto}:{dev.name or dev.id}")
        if self.cfg.follow_routes:
            for r in dev.routes:
                if r.nexthop and r.nexthop not in dev.ips and r.nexthop != "0.0.0.0":
                    n += self.enqueue(r.nexthop, d, f"nexthop:{dev.name or dev.id}")
        if self.cfg.follow_gateways:
            for cidr in dev.subnets():
                net = ipaddress.ip_network(cidr)
                if net.prefixlen < 16:
                    continue
                first = str(net.network_address + 1)
                last = str(net.broadcast_address - 1)
                for cand in (first, last):
                    if cand not in dev.ips:
                        n += self.enqueue(cand, d, f"gateway:{cidr}")
        if self.cfg.probe_hosts:
            for a in dev.arp:
                n += self.enqueue(a.ip, d, f"arp:{dev.name or dev.id}")
        return n

    def _resolve_unmatched_neighbors(self) -> int:
        """LLDP neighbors that advertised no mgmt IP: find their chassis MAC in someone's ARP table."""
        mac_ip = self.inv.mac_to_ip()
        n = 0
        for dev in self.inv.devices.values():
            for nb in dev.neighbors:
                if nb.remote_mgmt_ips:
                    continue
                if nb.remote_chassis_id in self.inv.mac_to_device:
                    continue
                ip = mac_ip.get(nb.remote_chassis_id)
                if ip:
                    n += self.enqueue(ip, dev.depth + 1, f"lldp-mac:{dev.name or dev.id}")
                elif self.inv.device_for_name(nb.remote_name) is None and is_usable_ip(nb.remote_name):
                    n += self.enqueue(nb.remote_name, dev.depth + 1, f"lldp-name:{dev.name or dev.id}")
        return n

    # ---- per-IP work ----
    async def _process(self, ip: str, depth: int, via: str) -> None:
        self.tried.add(ip)
        refresh = ip in self.refreshing
        if ip in self.inv.ip_to_device and not refresh:
            return
        if len(self.inv.devices) >= self.cfg.max_devices and not refresh:
            return
        self.stats["probed"] += 1
        sess, sysinfo = await self.prober(self.engine, ip, self.cfg.credentials, self.cfg.timeout, self.cfg.retries, self.cfg.port)
        if sess is None:
            if refresh:
                # it answered before; keep what we had and say that it went quiet
                old = self.inv.devices.get(ip)
                if old is not None and "no answer on rescan" not in old.errors:
                    old.errors.append("no answer on rescan")
                return
            self.stats["no_snmp"] += 1
            self.inv.unreachable[ip] = via
            if via.startswith(("arp", "lldp", "cdp", "nexthop")):
                h = self.inv.touch_host(ip, via.split(":")[0])
                h.snmp_failed = True
            return
        self.inv.unreachable.pop(ip, None)
        dev = await self.collector(sess, ip, self.cfg.collect, sysinfo)
        if refresh:
            old = self.inv.devices.get(ip)
            dev.depth = old.depth if old is not None else depth
            dev.discovered_via = old.discovered_via if old is not None else via
            if old is not None:
                from .collect import apply_counter_deltas

                apply_counter_deltas(old, dev)  # two counter snapshots -> utilisation and error rate
            self.inv.replace_device(dev)
            self.stats["refreshed"] += 1
            self._after_device(dev)
            return
        dev.depth = depth
        dev.discovered_via = via
        # Dedupe: the same box reached via another of its addresses
        for a in dev.ips:
            if a in self.inv.ip_to_device and self.inv.ip_to_device[a] != ip:
                other = self.inv.ip_to_device[a]
                log.info("%s is the same device as %s (%s); merging", ip, other, dev.name)
                for b in dev.ips:
                    self.inv.ip_to_device.setdefault(b, other)
                return
        self.inv.add_device(dev)
        self.stats["devices"] += 1
        self.stats["new_devices"].append(dev.id)
        self._after_device(dev)

    def _after_device(self, dev: Device) -> None:
        for a in dev.arp:
            if not in_scope(a.ip, self.cfg.scope, self.cfg.exclude):
                continue
            h = self.inv.touch_host(a.ip, "arp", a.mac)
            seen = {"device": dev.id, "interface": dev.iface_label(a.if_index), "vlan": None, "via": "arp"}
            if seen not in h.seen_on:
                h.seen_on.append(seen)
        added = self._enqueue_from_device(dev)
        log.info(
            "[%d dev, %d queued] %s %s (%s %s) if=%d lldp=%d cdp=%d arp=%d routes=%d fdb=%d +%d new, %.1fs%s",
            len(self.inv.devices),
            self.queue.qsize(),
            dev.id,
            dev.name or "-",
            dev.vendor or "?",
            dev.role,
            len(dev.interfaces),
            sum(1 for n in dev.neighbors if n.proto == "lldp"),
            sum(1 for n in dev.neighbors if n.proto == "cdp"),
            len(dev.arp),
            len(dev.routes),
            len(dev.fdb),
            added,
            dev.collect_seconds,
            f" errors={len(dev.errors)}" if dev.errors else "",
        )
        if self.cfg.on_device:
            try:
                self.cfg.on_device(dev)
            except Exception:  # noqa: BLE001 - a UI callback must never stop a crawl
                log.debug("on_device callback failed", exc_info=True)
        if self.cfg.save_path:
            self.inv.save(self.cfg.save_path)

    async def _worker(self, wid: int) -> None:
        while True:
            ip, depth, via = await self.queue.get()
            try:
                await self._process(ip, depth, via)
            except Exception:  # noqa: BLE001
                log.exception("worker %d: unhandled error on %s", wid, ip)
                self.inv.unreachable[ip] = f"error:{via}"
            finally:
                self.queue.task_done()

    def progress(self) -> dict:
        return {
            "devices": len(self.inv.devices),
            "probed": self.stats["probed"],
            "queued": self.queue.qsize(),
            "no_snmp": self.stats["no_snmp"],
            "refreshed": self.stats["refreshed"],
            "hosts": len(self.inv.hosts),
            "elapsed": time.time() - self._started,
        }

    async def run(self) -> Inventory:
        own_engine = self.engine is None
        if own_engine:
            self.engine = SnmpEngine()
        try:
            return await self._run()
        finally:
            if own_engine:
                # the desktop app runs many scans in one process: release the UDP sockets
                try:
                    self.engine.close_dispatcher()
                except Exception:  # noqa: BLE001
                    log.debug("closing the SNMP engine failed", exc_info=True)

    async def _run(self) -> Inventory:
        for s in self.cfg.seeds:
            if not self.enqueue(s, 0, "seed"):
                log.log(logging.INFO if s in self.inv.ip_to_device else logging.WARNING,
                        "seed %s not enqueued (out of scope, invalid, or already known)", s)
        # On resume (or a deeper max_depth), re-walk what known devices point at.
        for dev in list(self.inv.devices.values()):
            self._enqueue_from_device(dev)
        workers = [asyncio.create_task(self._worker(i)) for i in range(self.cfg.workers)]
        try:
            while True:
                await self.queue.join()
                if self._resolve_unmatched_neighbors() == 0:
                    break
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            if self.cfg.save_path:
                self.inv.save(self.cfg.save_path)
        log.info(
            "crawl finished in %.0fs: %d probed, %d new devices, %d re-polled, %d without SNMP, %d out-of-scope refs",
            time.time() - self._started,
            self.stats["probed"],
            self.stats["devices"],
            self.stats["refreshed"],
            self.stats["no_snmp"],
            self.stats["skipped_scope"],
        )
        return self.inv
