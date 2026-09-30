"""Capture device running-configs over SSH: the dialog, the background worker, and the
per-device config viewer with a diff between revisions."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFontDatabase, QTextCharFormat, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ..capture import capture_config, diff_configs, store_config
from ..views import fmt_time


class CaptureDialog(QDialog):
    def __init__(self, device_count: int, one_name: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Capture device configs")
        self.user = QLineEdit()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.key = QLineEdit()
        self.key.setPlaceholderText("optional: path to a private key file")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(22)
        self.scope = QComboBox()
        if one_name:
            self.scope.addItem(f"Just {one_name}", "one")
        self.scope.addItem(f"All {device_count} polled devices", "all")
        f = QFormLayout()
        f.addRow("SSH username", self.user)
        f.addRow("Password", self.pw)
        f.addRow("Private key", self.key)
        f.addRow("SSH port", self.port)
        f.addRow("Capture", self.scope)
        note = QLabel("Read-only: NetMap logs in, disables paging and runs 'show running-config' (per vendor). "
                      "It never changes anything. Configs are stored in the project so you can diff them later. "
                      "These credentials are used for this run only, not saved.")
        note.setWordWrap(True)
        note.setObjectName("muted")
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("Capture")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(f)
        lay.addWidget(note)
        lay.addWidget(bb)
        self.resize(440, 0)

    def values(self) -> dict:
        return {"username": self.user.text().strip(), "password": self.pw.text(), "key": self.key.text().strip() or None,
                "port": self.port.value(), "scope": self.scope.currentData()}


class CaptureWorker(QThread):
    progress = Signal(str, bool, str)  # device id, ok, message
    done = Signal(int, int)  # captured ok, changed

    def __init__(self, inv, device_ids, creds: dict, parent=None):
        super().__init__(parent)
        self.inv = inv
        self.device_ids = device_ids
        self.creds = creds
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        ok = changed = 0
        for did in self.device_ids:
            if self._stop:
                break
            dev = self.inv.devices.get(did)
            if dev is None:
                continue
            cap = capture_config(did, self.creds["username"], self.creds["password"], os_family=dev.os_family,
                                 vendor=dev.vendor, port=self.creds["port"], key_filename=self.creds["key"])
            if cap.ok:
                ok += 1
                if store_config(self.inv, did, cap):
                    changed += 1
                self.progress.emit(did, True, "captured" + (" (changed)" if changed else ""))
            else:
                self.progress.emit(did, False, cap.error)
        self.done.emit(ok, changed)


class ConfigView(QWidget):
    """Shows a device's stored configs: pick a revision, or diff it against the previous one."""

    def __init__(self, revisions: list[dict], parent=None):
        super().__init__(parent)
        self.revisions = revisions  # newest last
        self.pick = QComboBox()
        for i, r in enumerate(reversed(revisions)):
            self.pick.addItem(f"{fmt_time(r.get('captured_at'))}" + (f"  ·  {r.get('version', '')[:40]}" if r.get("version") else ""), len(revisions) - 1 - i)
        self.diff = QCheckBox("Show changes since the previous capture")
        self.diff.setEnabled(len(revisions) > 1)
        top = QHBoxLayout()
        top.addWidget(QLabel("Revision"))
        top.addWidget(self.pick, 1)
        top.addWidget(self.diff)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.text.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.addLayout(top)
        lay.addWidget(self.text, 1)
        self.pick.currentIndexChanged.connect(self._render)
        self.diff.toggled.connect(self._render)
        self._render()

    def _render(self):
        idx = self.pick.currentData() or 0
        rev = self.revisions[idx]
        if self.diff.isChecked() and idx > 0:
            d = diff_configs(self.revisions[idx - 1]["text"], rev["text"],
                             fmt_time(self.revisions[idx - 1].get("captured_at")), fmt_time(rev.get("captured_at")))
            self.text.setPlainText(d or "(no differences)")
            self._colour_diff()
        else:
            self.text.setPlainText(rev["text"])

    def _colour_diff(self):
        doc = self.text.document()
        add = QTextCharFormat()
        add.setForeground(QColor("#16a34a"))
        rem = QTextCharFormat()
        rem.setForeground(QColor("#dc2626"))
        cur = self.text.textCursor()
        block = doc.begin()
        while block.isValid():
            t = block.text()
            fmt = add if t.startswith("+") and not t.startswith("+++") else rem if t.startswith("-") and not t.startswith("---") else None
            if fmt:
                cur.setPosition(block.position())
                cur.movePosition(cur.MoveOperation.EndOfBlock, cur.MoveMode.KeepAnchor)
                cur.setCharFormat(fmt)
            block = block.next()
