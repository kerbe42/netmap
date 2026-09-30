"""Runs a scan on its own thread and event loop, reporting back through Qt signals."""
from __future__ import annotations

import asyncio
import logging
import time

from PySide6.QtCore import QObject, QThread, Signal

from ..model import Inventory
from ..scan import ScanEvents, ScanRequest, run_scan

log = logging.getLogger("netmap.gui")


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
        logging.getLogger("netmap").addHandler(self.handler)
        logging.getLogger("netmap").setLevel(logging.DEBUG if logging.getLogger().level <= logging.DEBUG else logging.INFO)

    def detach(self):
        logging.getLogger("netmap").removeHandler(self.handler)


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
            self.finished_ok.emit(self.inv, record)
        except asyncio.CancelledError:
            self.finished_ok.emit(self.inv, {"cancelled": True})
        except Exception as e:  # noqa: BLE001
            log.exception("scan failed")
            self.failed.emit(f"{type(e).__name__}: {e}")
