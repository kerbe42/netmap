"""Runs a scan on its own thread and event loop, reporting back through Qt signals."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional

from PySide6.QtCore import QObject, QThread, Signal

from ..model import Inventory
from ..scan import ScanEvents, ScanRequest, run_scan
from ..views import Snapshot

log = logging.getLogger("subnetsleuth.gui")


class LogBridge(QObject):
    """A logging handler that forwards records to the UI thread as a signal."""

    record = Signal(float, str, str, str)  # time, level, logger, message

    class _Handler(logging.Handler):
        def __init__(self, bridge):
            super().__init__(logging.INFO)
            self.bridge = bridge

        def emit(self, rec):
            try:
                self.bridge.record.emit(rec.created, rec.levelname, rec.name, rec.getMessage())
            except Exception:  # noqa: BLE001
                pass

    def __init__(self, parent=None):
        super().__init__(parent)
        self.handler = self._Handler(self)

    def attach(self):
        logging.getLogger("subnetsleuth").addHandler(self.handler)
        logging.getLogger("subnetsleuth").setLevel(logging.DEBUG if logging.getLogger().level <= logging.DEBUG else logging.INFO)

    def detach(self):
        logging.getLogger("subnetsleuth").removeHandler(self.handler)


class ScanWorker(QThread):
    phase = Signal(str, str)
    progress = Signal(dict)
    snapshot = Signal(dict)  # a consistent copy of the inventory while the scan runs
    finished_ok = Signal(object, dict)  # Inventory, history record
    failed = Signal(str)

    def __init__(self, inv: Inventory, req: ScanRequest, snapshot_every: float = 3.0, parent=None):
        super().__init__(parent)
        self.inv = inv
        self.req = req
        self.snapshot_every = snapshot_every
        self._loop = None
        self._task = None
        self._stop_requested = False
        # the result is also kept here, so the window can take it synchronously after
        # wait() instead of depending on the queued signal being delivered in time
        self.outcome: Optional[tuple] = None  # ("ok", inv, record) | ("failed", message)
        self.consumed = False

    def stop(self):
        self._stop_requested = True
        loop, task = self._loop, self._task
        if loop is not None and task is not None:
            loop.call_soon_threadsafe(task.cancel)

    def run(self):
        worker = self

        class Events(ScanEvents):
            last = 0.0

            def phase(self, name, detail=""):
                worker.phase.emit(name, detail)

            def tick(self, inv, stats):
                worker.progress.emit(stats)
                now = time.time()
                if now - self.last >= worker.snapshot_every:
                    self.last = now
                    worker.snapshot.emit(inv.to_dict())

        async def main():
            self._loop = asyncio.get_running_loop()
            self._task = asyncio.ensure_future(run_scan(self.inv, self.req, Events()))
            if self._stop_requested:
                self._task.cancel()
            return await self._task

        try:
            record = asyncio.run(main())
            self.outcome = ("ok", self.inv, record)
            self.finished_ok.emit(self.inv, record)
        except asyncio.CancelledError:
            self.outcome = ("ok", self.inv, {"cancelled": True})
            self.finished_ok.emit(self.inv, {"cancelled": True})
        except Exception as e:  # noqa: BLE001
            log.exception("scan failed")
            self.outcome = ("failed", f"{type(e).__name__}: {e}")
            self.failed.emit(f"{type(e).__name__}: {e}")


class SnapshotBuilder(QThread):
    """Turns a scan's live snapshot (a plain dict) into an Inventory, a Snapshot and the
    rows of the page on screen - all pure Python, all off the UI thread. The window only
    swaps the results in, so a 14,000-host project no longer freezes it on every tick.

    Annotations are copied for the build; the window re-attaches its live dicts when it
    takes the result, so notes typed meanwhile are never lost."""

    built = Signal(object, object, str, object)  # Inventory, Snapshot, page key, rows or None

    def __init__(self, data: dict, annotations: dict, layout: dict, project: dict, page_key: str = "", rows_fn: Optional[Callable] = None, parent=None):
        super().__init__(parent)
        self.data = data
        self.annotations = {k: dict(v) for k, v in annotations.items()}
        self.layout = layout
        self.project = project
        self.page_key = page_key
        self.rows_fn = rows_fn

    def run(self):
        try:
            inv = Inventory.from_dict(self.data)
            inv.annotations = self.annotations
            inv.layout = self.layout
            inv.project = self.project
            snap = Snapshot(inv)
            rows = self.rows_fn(snap) if self.rows_fn else None
        except Exception:  # noqa: BLE001 - a bad tick is dropped, the next one comes in seconds
            log.exception("live snapshot build failed")
            return
        self.built.emit(inv, snap, self.page_key, rows)
