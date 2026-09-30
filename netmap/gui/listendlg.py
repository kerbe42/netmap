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
    QLineEdit,
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
        self._seen = 0  # events shown so far (a running total, not an index into the buffer)
        self._last_seq = None  # Event.seq of the last shown event, when events carry one
        self._last_obj = None  # else the last shown event object itself
        self.syslog_port = QSpinBox()
        self.syslog_port.setRange(1, 65535)
        self.syslog_port.setValue(514)
        self.trap_port = QSpinBox()
        self.trap_port.setRange(1, 65535)
        self.trap_port.setValue(162)
        self.bind_addr = QLineEdit("0.0.0.0")
        self.bind_addr.setToolTip("Local address to listen on (0.0.0.0 = every interface)")
        self.bind_addr.setMaximumWidth(120)
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
        top.addWidget(QLabel("Bind"))
        top.addWidget(self.bind_addr)
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
            c = self._make_collector()
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

    def _new_events(self, evs: list) -> list:
        """The events not shown yet. The collector's buffer is a bounded deque, so an index
        into it is meaningless once it wraps: track by Event.seq when there is one, else by
        the identity of the last event shown."""
        if not evs:
            return []
        if getattr(evs[-1], "seq", None) is not None:
            if self._last_seq is None:
                return evs
            return [e for e in evs if getattr(e, "seq", None) is not None and e.seq > self._last_seq]
        if self._last_obj is None:
            return evs
        for i in range(len(evs) - 1, -1, -1):
            if evs[i] is self._last_obj:
                return evs[i + 1:]
        return evs  # everything shown before has been evicted: all of these are new

    def _make_collector(self) -> EventCollector:
        import inspect

        kwargs = {}
        addr = self.bind_addr.text().strip()
        try:
            if addr and "bind_addr" in inspect.signature(EventCollector).parameters:
                kwargs["bind_addr"] = addr
        except (TypeError, ValueError):
            pass
        return EventCollector(self.syslog_port.value(), self.trap_port.value(), **kwargs)

    def _drain(self):
        if self.collector is None:
            return
        evs = list(self.collector.events)
        new = self._new_events(evs)
        for ev in new:
            self._add(ev)
        if new:
            self._last_obj = new[-1]
            self._last_seq = getattr(new[-1], "seq", None)
            self._seen += len(new)
        self.count.setText(f"{self._seen} events")

    def _add(self, ev):
        r = self.table.rowCount()
        self.table.insertRow(r)
        name = self.snapshot.name(ev.source) if self.snapshot and ev.source in self.snapshot.inv.devices else ev.source
        vals = [time.strftime("%H:%M:%S", time.localtime(ev.time)), name, ev.kind, ev.severity, ev.message]
        details = getattr(ev, "details", None)  # decoded trap OID / varbinds, when the core provides them
        for c, v in enumerate(vals):
            it = QTableWidgetItem(str(v))
            if c == 3 and ev.severity in SEV_COLOR:
                it.setForeground(QBrush(QColor(SEV_COLOR[ev.severity])))
            if c == 4 and details:
                it.setToolTip(str(ev.message) + "\n\n" + (("\n".join(f"{k}: {v2}" for k, v2 in details.items()) if isinstance(details, dict) else str(details))))
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
