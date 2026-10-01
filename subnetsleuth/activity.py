"""What a scan is working on right now: the subnets, address batches and devices in flight.

Each step that sends traffic wraps the work in `working("ping sweep", "10.20.4.0/24")`; a scan
reads `now()` once a second for the app's "Now:" line and logs it now and then, so a long run
always shows what it is doing. Every scan (and deep scan) gets its own `Activity` through
`use()`, which asyncio tasks inherit, so two jobs never show each other's work.
"""
from __future__ import annotations

import contextlib
import contextvars
import itertools
import threading
import time
from dataclasses import dataclass, field


@dataclass
class Item:
    kind: str  # "ping sweep", "port scan", "SNMP", "deep scan", ...
    target: str  # "10.20.4.0/24", "10.1.0.1 - 10.1.0.24 (24)", ...
    started: float = field(default_factory=time.time)
    detail: str = ""  # live progress, e.g. nmap's "SYN Stealth Scan 45%"

    def describe(self, now: float | None = None) -> str:
        secs = (now or time.time()) - self.started
        bits = [b for b in (self.detail, fmt_secs(secs) if secs >= 60 else "") if b]
        return f"{self.target} ({', '.join(bits)})" if bits else self.target


def fmt_secs(secs: float) -> str:
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    return f"{secs // 3600}h{secs % 3600 // 60:02d}m"


class Activity:
    def __init__(self):
        self._items: dict[int, Item] = {}
        self._lock = threading.Lock()  # read from the UI thread's tick, written on the scan's loop
        self._ids = itertools.count()

    @contextlib.contextmanager
    def working(self, kind: str, target: str):
        item = Item(kind, target)
        key = next(self._ids)
        with self._lock:
            self._items[key] = item
        try:
            yield item
        finally:
            with self._lock:
                self._items.pop(key, None)

    def now(self) -> list[Item]:
        """What is in flight, oldest first."""
        with self._lock:
            items = list(self._items.values())
        return sorted(items, key=lambda i: i.started)

    def summary(self, limit: int = 6) -> str:
        """One line: each kind with up to `limit` of its targets, e.g.
        "ping sweep 10.20.4.0/24, 10.20.5.0/24 (+6 more) · SNMP 10.0.0.1"."""
        items = self.now()
        if not items:
            return ""
        t = time.time()
        by_kind: dict[str, list[Item]] = {}
        for i in items:
            by_kind.setdefault(i.kind, []).append(i)
        parts = []
        for kind, its in by_kind.items():
            shown = ", ".join(i.describe(t) for i in its[:limit])
            more = f" (+{len(its) - limit} more)" if len(its) > limit else ""
            parts.append(f"{kind} {shown}{more}")
        return " · ".join(parts)


_current: contextvars.ContextVar[Activity] = contextvars.ContextVar("subnetsleuth_activity", default=Activity())


def use(activity: Activity) -> None:
    """Make `activity` the one this task (and the tasks it starts) report into."""
    _current.set(activity)


def working(kind: str, target: str):
    return _current.get().working(kind, target)


def current() -> Activity:
    return _current.get()


def span(ips: list[str]) -> str:
    """A batch of addresses as a short label: all of them when few, else first - last (n)."""
    if len(ips) <= 3:
        return ", ".join(ips)
    return f"{ips[0]} - {ips[-1]} ({len(ips)})"
