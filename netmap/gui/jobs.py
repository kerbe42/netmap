"""Background work for the desktop app: one registry of every worker thread, and a helper
that runs a slow pure-Python step (serialising a big project, copying it, writing a
workbook) on a thread while the window keeps repainting behind a small progress dialog.

Every QThread the window starts is registered here, so one `busy()` answers "may I swap
the inventory / start another job now?", one `stop_all()` serves the Stop button and the
close request, and closing never destroys a thread that is still running.
"""
from __future__ import annotations

import logging
import time
from typing import Callable, Optional

from PySide6.QtCore import QEventLoop, QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import QApplication, QProgressDialog

log = logging.getLogger("netmap.gui")


class JobRegistry(QObject):
    """Every worker thread the window owns, with a human title for messages."""

    changed = Signal()  # a job started or finished
    idle = Signal()  # the last job finished

    def __init__(self, parent=None):
        super().__init__(parent)
        self._jobs: list[tuple[QThread, str, bool]] = []  # (thread, title, counts_as_busy)

    def add(self, thread: QThread, title: str, blocking: bool = True) -> QThread:
        """Register a thread. `blocking` jobs make `busy()` true (they touch the inventory);
        housekeeping such as the recovery autosave or an update check does not."""
        self._jobs.append((thread, title, blocking))
        thread.finished.connect(lambda t=thread: self._done(t))
        self.changed.emit()
        return thread

    def _done(self, thread: QThread):
        self._jobs = [j for j in self._jobs if j[0] is not thread]
        self.changed.emit()
        if not self._jobs:
            self.idle.emit()

    def busy(self) -> bool:
        return any(b and t.isRunning() for t, _, b in self._jobs) or any(b and not t.isFinished() for t, _, b in self._jobs)

    def running(self) -> list[QThread]:
        return [t for t, _, _ in self._jobs if t.isRunning()]

    def titles(self, blocking_only: bool = True) -> list[str]:
        return [title for t, title, b in self._jobs if (b or not blocking_only) and not t.isFinished()]

    def describe(self) -> str:
        """'the scan', 'the config capture and the server inspection' — for a message."""
        titles = self.titles() or self.titles(blocking_only=False)
        if not titles:
            return "a background job"
        if len(titles) == 1:
            return titles[0]
        return ", ".join(titles[:-1]) + " and " + titles[-1]

    def wait_message(self) -> str:
        return f"Wait for {self.describe()} to finish."

    def stop_all(self) -> None:
        for t, _, _ in list(self._jobs):
            stop = getattr(t, "stop", None)
            if callable(stop) and t.isRunning():
                try:
                    stop()
                except Exception:  # noqa: BLE001
                    log.exception("stop() failed")

    def wait_all(self, timeout_ms: int) -> bool:
        """Wait up to `timeout_ms` in total for every thread; True when all have finished."""
        end = time.time() + timeout_ms / 1000
        for t in self.running():
            left = int((end - time.time()) * 1000)
            if left <= 0 or not t.wait(left):
                return False
        return not self.running()

    def __len__(self):
        return len(self._jobs)


class _FnThread(QThread):
    def __init__(self, fn: Callable, parent=None):
        super().__init__(parent)
        self.fn = fn
        self.result = None
        self.error: Optional[BaseException] = None

    def run(self):
        try:
            self.result = self.fn()
        except BaseException as e:  # noqa: BLE001 - re-raised on the calling thread
            self.error = e


def run_blocking(parent, title: str, fn: Callable, registry: Optional[JobRegistry] = None, show_after_ms: int = 350):
    """Run `fn()` on a thread and return its result, keeping the window painting meanwhile.

    The caller's flow stays synchronous (it gets the result or the exception), the user
    sees a wait cursor and, after a moment, a small "Saving…" style dialog with no Cancel.
    Input is blocked while it runs, so the data `fn` reads is not edited under it.
    """
    th = _FnThread(fn)
    if registry is not None:
        registry.add(th, title)
    loop = QEventLoop()
    th.finished.connect(loop.quit, Qt.QueuedConnection)
    dlg = None

    def show_dialog():
        nonlocal dlg
        if th.isRunning() or not th.isFinished():
            dlg = QProgressDialog(title + "…", "", 0, 0, parent)
            dlg.setWindowTitle("NetMap")
            dlg.setCancelButton(None)
            dlg.setWindowModality(Qt.ApplicationModal)
            dlg.setMinimumDuration(0)
            dlg.setAutoClose(False)
            dlg.setAutoReset(False)
            dlg.show()

    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(show_dialog)
    QApplication.setOverrideCursor(Qt.WaitCursor)
    try:
        th.start()
        timer.start(show_after_ms)
        if not th.isFinished():
            loop.exec()
        th.wait()
    finally:
        timer.stop()
        QApplication.restoreOverrideCursor()
        if dlg is not None:
            dlg.close()
            dlg.deleteLater()
    if th.error is not None:
        raise th.error
    return th.result


def with_retry(fn: Callable, attempts: int = 4):
    """Serialising a live inventory on a thread can collide with a same-moment edit on the
    UI thread ("dictionary changed size during iteration"): try again, it is rare and short."""
    last = None
    for _ in range(attempts):
        try:
            return fn()
        except RuntimeError as e:
            last = e
            time.sleep(0.05)
    raise last  # type: ignore[misc]
