"""Agentless server inspection (SSH for Linux/Unix, WinRM for Windows): credential dialog and
background worker. Read-only — it only runs read commands to collect facts."""
from __future__ import annotations

import asyncio

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

    def __init__(self, inv, creds: dict, parent=None):
        super().__init__(parent)
        self.inv = inv
        self.creds = creds

    def run(self):
        from ..hostinfo import inspect_hosts

        try:
            result = asyncio.run(inspect_hosts(self.inv, self.creds))
        except Exception as e:  # noqa: BLE001
            result = {"error": f"{type(e).__name__}: {e}"}
        self.done.emit(result)
