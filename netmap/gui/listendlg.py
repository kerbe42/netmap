"""A live view of syslog messages and SNMP traps arriving from the network."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from ..listen import EventCollector

SEV_COLOR = {"emergency": "#dc2626", "alert": "#dc2626", "critical": "#dc2626", "error": "#dc2626",
             "warning": "#d97706", "notice": "#2563eb", "info": "#64748b", "debug": "#94a3b8"}


class ListenDialog(QDialog):
    def __init__(self, snapshot=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Listen for syslog / SNMP traps")
        self.snapshot = snapshot
        self.collector: EventCollector | None = None
        self._seen = 0
        self.syslog_port = QSpinBox()
        self.syslog_port.setRange(1, 65535)
        self.syslog_port.setValue(514)
        self.trap_port = QSpinBox()
        self.trap_port.setRange(1, 65535)
        self.trap_port.setValue(162)
        self.start_btn = QPushButton("Start listening")
        self.start_btn.clicked.connect(self.toggle)
        self.status = QLabel("Point devices' logging/trap host at this machine. Ports 514/162 need admin; use high ports otherwise.")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        top = QHBoxLayout()
        top.addWidget(QLabel("Syslog UDP"))
        top.addWidget(self.syslog_port)
        top.addWidget(QLabel("Trap UDP"))
        top.addWidget(self.trap_port)
        top.addWidget(self.start_btn)
        top.addStretch(1)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Source", "Kind", "Severity", "Message"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 90)
        self.table.setColumnWidth(1, 160)
        self.table.setColumnWidth(2, 60)
        self.table.setColumnWidth(3, 80)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        clear = QPushButton("Clear")
        clear.clicked.connect(lambda: (self.table.setRowCount(0)))
        bottom = QHBoxLayout()
        self.count = QLabel("0 events")
        self.count.setObjectName("muted")
        bottom.addWidget(self.count)
        bottom.addStretch(1)
        bottom.addWidget(clear)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)
        lay.addLayout(bottom)
        self.timer = QTimer(self)
        self.timer.setInterval(700)
        self.timer.timeout.connect(self._drain)
        self.resize(900, 480)

    def toggle(self):
        if self.collector is None:
            c = EventCollector(self.syslog_port.value(), self.trap_port.value())
            listening = c.start()
            if not listening:
                self.status.setText("Could not bind either port: " + "; ".join(c.errors) + "  Try high ports (e.g. 5140 / 1620) or run as administrator.")
                c.stop()
                return
            self.collector = c
            self.start_btn.setText("Stop")
            self.syslog_port.setEnabled(False)
            self.trap_port.setEnabled(False)
            note = "Listening on " + ", ".join(listening)
            if c.errors:
                note += "  (" + "; ".join(c.errors) + ")"
            self.status.setText(note)
            self.timer.start()
        else:
            self.stop()

    def _drain(self):
        if self.collector is None:
            return
        evs = list(self.collector.events)
        for ev in evs[self._seen:]:
            self._add(ev)
        self._seen = len(evs)
        self.count.setText(f"{self._seen} events")

    def _add(self, ev):
        r = self.table.rowCount()
        self.table.insertRow(r)
        name = self.snapshot.name(ev.source) if self.snapshot and ev.source in self.snapshot.inv.devices else ev.source
        vals = [time.strftime("%H:%M:%S", time.localtime(ev.time)), name, ev.kind, ev.severity, ev.message]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(str(v))
            if c == 3 and ev.severity in SEV_COLOR:
                it.setForeground(QBrush(QColor(SEV_COLOR[ev.severity])))
            self.table.setItem(r, c, it)
        if r > 4000:
            self.table.removeRow(0)
        self.table.scrollToBottom()

    def stop(self):
        self.timer.stop()
        if self.collector is not None:
            self.collector.stop()
            self.collector = None
        self.start_btn.setText("Start listening")
        self.syslog_port.setEnabled(True)
        self.trap_port.setEnabled(True)

    def closeEvent(self, e):
        self.stop()
        super().closeEvent(e)
