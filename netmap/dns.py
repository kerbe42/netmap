"""Reverse DNS for everything a scan found.

A host known only from an ARP table is an address and a MAC; its PTR record is often
the only thing that says what it is for ("pos-till-03", "esx-b2-07"). Lookups go to the
resolver the machine is configured with, not to the hosts themselves.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .model import Inventory

log = logging.getLogger("netmap.dns")


def ptr(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    name = (name or "").rstrip(".")
    if not name or name == ip:
        return None
    return name


async def resolve_names(inv: Inventory, workers: int = 32, timeout: float = 4.0, lookup=ptr, hosts: Optional[list] = None) -> int:
    """Fill Host.hostname and Device.dns_name from PTR records where they are empty.

    The system resolver has no per-call timeout, so each lookup runs in a thread and is
    abandoned after `timeout`; a slow DNS server costs time, never correctness.
    `hosts` limits the lookups to those addresses (devices or hosts); None means every
    address in the inventory. Returns the number of names found.
    """
    allowed = None if hosts is None else set(hosts)
    todo: list[str] = [d.id for d in inv.devices.values() if not d.dns_name and (allowed is None or d.id in allowed)]
    todo += [ip for ip, h in inv.hosts.items() if not h.hostname and ip not in inv.ip_to_device and (allowed is None or ip in allowed)]
    if not todo:
        return 0
    log.info("resolving names for %d addresses", len(todo))
    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netmap-dns")
    sem = asyncio.Semaphore(workers)
    found = 0

    async def one(ip: str) -> None:
        nonlocal found
        async with sem:
            try:
                name = await asyncio.wait_for(loop.run_in_executor(pool, lookup, ip), timeout)
            except (asyncio.TimeoutError, OSError):
                return
        if not name:
            return
        found += 1
        d = inv.devices.get(ip)
        if d is not None:
            d.dns_name = name
        elif ip in inv.hosts:
            inv.hosts[ip].hostname = name

    try:
        await asyncio.gather(*(one(ip) for ip in todo))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    log.info("reverse DNS: %d of %d addresses have a name", found, len(todo))
    return found
