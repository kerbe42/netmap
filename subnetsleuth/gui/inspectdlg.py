"""Agentless server inspection (SSH for Linux/Unix, WinRM for Windows): credential dialog and
background worker. Read-only — it only runs read commands to collect facts."""
from __future__ import annotations

import asyncio
from typing import Optional

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)


class InspectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Inspect servers (SSH / WinRM)")
        self.linux_on = QCheckBox("Linux / Unix over SSH")
        self.linux_on.setChecked(True)
        self.lin_user = QLineEdit()
        self.lin_pw = QLineEdit()
        self.lin_pw.setEchoMode(QLineEdit.Password)
        self.lin_key = QLineEdit()
        self.lin_key.setPlaceholderText("optional private key file")
        lg = QGroupBox()
        lf = QFormLayout(lg)
        lf.addRow(self.linux_on)
        lf.addRow("Username", self.lin_user)
        lf.addRow("Password", self.lin_pw)
        lf.addRow("Private key", self.lin_key)
        self.win_on = QCheckBox("Windows over WinRM")
        self.win_on.setChecked(True)
        self.win_user = QLineEdit()
        self.win_user.setPlaceholderText("DOMAIN\\user or user")
        self.win_pw = QLineEdit()
        self.win_pw.setEchoMode(QLineEdit.Password)
        wg = QGroupBox()
        wf = QFormLayout(wg)
        wf.addRow(self.win_on)
        wf.addRow("Username", self.win_user)
        wf.addRow("Password", self.win_pw)
        note = QLabel("Read-only: collects OS, hardware, installed software, services and active connections "
                      "(which feed the dependency map). Credentials are used for this run only. WinRM must be enabled "
                      "on the Windows hosts (usual in a domain); SSH for Linux/Unix.")
        note.setWordWrap(True)
        note.setObjectName("muted")
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("Inspect")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(lg)
        lay.addWidget(wg)
        lay.addWidget(note)
        lay.addWidget(bb)
        self.resize(430, 0)

    def creds(self) -> dict:
        c = {}
        if self.linux_on.isChecked() and (self.lin_user.text() or self.lin_key.text()):
            c["linux"] = {"username": self.lin_user.text().strip(), "password": self.lin_pw.text(),
                          "key_filename": self.lin_key.text().strip() or None}
        if self.win_on.isChecked() and self.win_user.text():
            c["windows"] = {"username": self.win_user.text().strip(), "password": self.win_pw.text(), "transport": "ntlm"}
        return c


class InspectWorker(QThread):
    progress = Signal(dict)
    done = Signal(dict)

    def __init__(self, inv, creds: dict, parent=None, scope=None, exclude=None):
        super().__init__(parent)
        self.inv = inv  # a copy of the project: results are merged on the UI thread when done
        self.creds = creds
        self.scope = scope
        self.exclude = exclude
        self._loop = None
        self._task = None
        self._stop_requested = False
        self.result: Optional[dict] = None

    def stop(self):
        """Cooperative stop: cancel the inspection task; hosts done so far are kept."""
        self._stop_requested = True
        loop, task = self._loop, self._task
        if loop is not None and task is not None:
            loop.call_soon_threadsafe(task.cancel)

    def run(self):
        import inspect as _inspect

        from ..hostinfo import inspect_hosts

        kwargs = {}
        try:  # scope/exclude are being added to the core; pass them only when accepted
            params = _inspect.signature(inspect_hosts).parameters
            if "scope" in params and self.scope is not None:
                kwargs["scope"] = self.scope
            if "exclude" in params and self.exclude is not None:
                kwargs["exclude"] = self.exclude
        except (TypeError, ValueError):
            pass

        async def main():
            self._loop = asyncio.get_running_loop()
            self._task = asyncio.ensure_future(inspect_hosts(self.inv, self.creds, **kwargs))
            if self._stop_requested:
                self._task.cancel()
            return await self._task

        try:
            result = asyncio.run(main())
        except asyncio.CancelledError:
            result = {"cancelled": True, "ok": 0}
        except Exception as e:  # noqa: BLE001
            result = {"error": f"{type(e).__name__}: {e}"}
        self.result = result
        self.done.emit(result)
