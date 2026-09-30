"""Read-only VMware vCenter/ESXi discovery: a small credentials dialog and a worker."""
from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QSpinBox, QVBoxLayout,
)


class VmwareDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Discover VMware (vCenter / ESXi)")
        self.host = QLineEdit()
        self.host.setPlaceholderText("vcenter.example.com or an ESXi host")
        self.user = QLineEdit()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(443)
        self.insecure = QCheckBox("Accept a self-signed / untrusted certificate")
        self.insecure.setChecked(False)  # the certificate is verified unless you say otherwise
        self.insecure.setToolTip("Tick only for a vCenter/ESXi whose certificate is not trusted by this machine")
        f = QFormLayout()
        f.addRow("vCenter / ESXi host", self.host)
        f.addRow("Username", self.user)
        f.addRow("Password", self.pw)
        f.addRow("Port", self.port)
        f.addRow(self.insecure)
        note = QLabel("Read-only: reads the vSphere inventory (ESXi hosts, VMs, guest IPs/OS, port groups/VLANs) and "
                      "folds VMs and hosts into the map. Nothing is powered on/off or reconfigured.")
        note.setWordWrap(True)
        note.setObjectName("muted")
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Ok).setText("Discover")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(f)
        lay.addWidget(note)
        lay.addWidget(bb)
        self.resize(430, 0)

    def values(self):
        return {"host": self.host.text().strip(), "username": self.user.text().strip(),
                "password": self.pw.text(), "port": self.port.value(), "insecure": self.insecure.isChecked()}


class VmwareWorker(QThread):
    done = Signal(dict)

    def __init__(self, inv, params, parent=None):
        super().__init__(parent)
        self.inv = inv  # a copy of the project: results are merged on the UI thread when done
        self.params = params
        self._stop_requested = False
        self.result = None

    def stop(self):
        """Cooperative stop. The vSphere calls themselves cannot be interrupted, but a stop
        asked before they begin skips them, and one asked during them discards the result."""
        self._stop_requested = True

    def run(self):
        from ..vmware import discover

        p = self.params
        if self._stop_requested:
            self.result = {"cancelled": True}
            self.done.emit(self.result)
            return
        try:
            result = discover(self.inv, p["host"], p["username"], p["password"], port=p["port"], insecure=p["insecure"])
        except Exception as e:  # noqa: BLE001
            result = {"error": f"{type(e).__name__}: {e}"}
        if self._stop_requested:
            result = {"cancelled": True}
        self.result = result
        self.done.emit(result)
