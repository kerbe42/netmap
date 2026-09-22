"""Breadth-first crawler: seeds -> SNMP -> neighbors/next-hops/gateways -> repeat, inside a scope."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

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


class Crawler:
    def __init__(self, cfg: CrawlConfig, inv: Inventory, engine: Optional[SnmpEngine] = None, collector=None, prober=None):
        self.cfg = cfg
        self.inv = inv
        self.engine = engine
        self.collector = collector or collect_device
        self.prober = prober or probe
        self.queue: asyncio.Queue = asyncio.Queue()
        self.queued: set[str] = set()
        self.tried: set[str] = set(inv.devices) | set(inv.unreachable)
        self._save_lock = asyncio.Lock()
        self.stats = {"probed": 0, "devices": 0, "no_snmp": 0, "skipped_scope": 0}
        self._started = time.time()

    # ---- queue management ----
    def enqueue(self, ip: str, depth: int, via: str) -> bool:
        if not is_usable_ip(ip):
            return False
        if ip in self.queued or ip in self.tried or ip in self.inv.ip_to_device:
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
        if ip in self.inv.ip_to_device:
            return
        if len(self.inv.devices) >= self.cfg.max_devices:
            return
        self.stats["probed"] += 1
        sess, sysinfo = await self.prober(self.engine, ip, self.cfg.credentials, self.cfg.timeout, self.cfg.retries, self.cfg.port)
        if sess is None:
            self.stats["no_snmp"] += 1
            self.inv.unreachable[ip] = via
            if via.startswith(("arp", "lldp", "cdp", "nexthop")):
                h = self.inv.touch_host(ip, via.split(":")[0])
                h.snmp_failed = True
            return
        dev = await self.collector(sess, ip, self.cfg.collect, sysinfo)
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
        for a in dev.arp:
            if not in_scope(a.ip, self.cfg.scope, self.cfg.exclude):
                continue
            h = self.inv.touch_host(a.ip, "arp", a.mac)
            h.seen_on.append({"device": dev.id, "interface": dev.iface_label(a.if_index), "vlan": None, "via": "arp"})
        self.stats["devices"] += 1
        added = self._enqueue_from_device(dev)
        log.info(
            "[%d dev, %d queued] %s %s (%s %s) if=%d lldp=%d cdp=%d arp=%d routes=%d fdb=%d +%d new, %.1fs%s",
            len(self.inv.devices),
            self.queue.qsize(),
            ip,
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
        if self.cfg.save_path:
            async with self._save_lock:
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

    async def run(self) -> Inventory:
        if self.engine is None:
            self.engine = SnmpEngine()
        for s in self.cfg.seeds:
            if not self.enqueue(s, 0, "seed"):
                log.warning("seed %s not enqueued (out of scope, invalid, or already known)", s)
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
            "crawl finished in %.0fs: %d probed, %d devices, %d without SNMP, %d out-of-scope refs",
            time.time() - self._started,
            self.stats["probed"],
            self.stats["devices"],
            self.stats["no_snmp"],
            self.stats["skipped_scope"],
        )
        return self.inv
