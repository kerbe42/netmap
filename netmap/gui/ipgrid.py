"""The IP map of a subnet: one cell per address, coloured by what occupies it."""
from __future__ import annotations

import ipaddress

from PySide6.QtCore import QPoint, QRect, QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPalette, QPen
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QSizePolicy, QToolTip, QVBoxLayout, QWidget

from ..views import subnet_addresses

STATE_COLORS = {
    "gateway": "#ea580c",
    "device": "#2563eb",
    "host": "#16a34a",
    "silent": "#a8a29e",
    "reserved": "#475569",
}
STATE_TITLES = {"gateway": "gateway", "device": "network device", "host": "host", "silent": "probed, no SNMP", "reserved": "network / broadcast", "free": "not seen in use"}

PAGE = 256


class _Cells(QWidget):
    nodeClicked = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cells: list[dict] = []
        self.cols = 16
        self.cell = 17
        self.gap = 2
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

    def set_cells(self, cells):
        self.cells = cells
        self.cols = 16 if len(cells) > 16 else max(len(cells), 1)
        self.updateGeometry()
        self.update()

    def sizeHint(self):
        rows = (len(self.cells) + self.cols - 1) // self.cols
        step = self.cell + self.gap
        return QSize(self.cols * step + 44, rows * step + 4)

    def minimumSizeHint(self):
        return self.sizeHint()

    def _rect(self, i) -> QRect:
        step = self.cell + self.gap
        return QRect(40 + (i % self.cols) * step, (i // self.cols) * step, self.cell, self.cell)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        pal = self.palette()
        dark = pal.color(QPalette.Window).lightness() < 128
        free = QColor("#2b313d") if dark else QColor("#f1f5f9")
        border = QColor("#3a4150") if dark else QColor("#cbd5e1")
        muted = pal.color(QPalette.PlaceholderText)
        f = p.font()
        f.setPointSizeF(7)
        p.setFont(f)
        for i, c in enumerate(self.cells):
            r = self._rect(i)
            if i % self.cols == 0:
                p.setPen(muted)
                p.drawText(QRect(0, r.top(), 36, r.height()), Qt.AlignRight | Qt.AlignVCenter, "." + c["ip"].rsplit(".", 1)[-1])
            col = QColor(STATE_COLORS.get(c["state"], free.name())) if c["state"] != "free" else free
            p.setPen(QPen(border if c["state"] == "free" else col.darker(120), 1))
            p.setBrush(col)
            p.drawRoundedRect(r, 3, 3)
        p.end()

    def _at(self, pos: QPoint):
        for i in range(len(self.cells)):
            if self._rect(i).contains(pos):
                return self.cells[i]
        return None

    def mouseMoveEvent(self, e):
        c = self._at(e.position().toPoint())
        if c:
            text = f"<b>{c['ip']}</b><br>{STATE_TITLES.get(c['state'], c['state'])}"
            if c.get("label"):
                text += f"<br>{c['label']}"
            QToolTip.showText(e.globalPosition().toPoint(), text, self)
            self.setCursor(Qt.PointingHandCursor if c.get("node") else Qt.ArrowCursor)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, e):
        c = self._at(e.position().toPoint())
        if c and c.get("node"):
            self.nodeClicked.emit(c["node"])


class IpGrid(QWidget):
    nodeClicked = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.snapshot = None
        self.cidr = ""
        self.block = QComboBox()
        self.block.currentIndexChanged.connect(self._show_block)
        self.cells = _Cells()
        self.cells.nodeClicked.connect(self.nodeClicked)
        legend = QHBoxLayout()
        legend.setSpacing(10)
        for st in ("gateway", "device", "host", "silent", "free"):
            sw = QLabel()
            sw.setFixedSize(11, 11)
            colr = STATE_COLORS.get(st, "#e2e8f0")
            sw.setStyleSheet(f"background:{colr}; border-radius:2px; border:1px solid #94a3b8;")
            legend.addWidget(sw)
            t = QLabel(STATE_TITLES[st])
            t.setObjectName("muted")
            legend.addWidget(t)
        legend.addStretch(1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.block)
        lay.addWidget(self.cells)
        lay.addLayout(legend)
        self._all: list[dict] = []

    def set_subnet(self, snapshot, cidr: str):
        self.snapshot = snapshot
        self.cidr = cidr
        net = ipaddress.ip_network(cidr)
        self._all = subnet_addresses(snapshot, cidr, limit=min(net.num_addresses, 65536))
        self.block.blockSignals(True)
        self.block.clear()
        if len(self._all) > PAGE:
            for i in range(0, len(self._all), PAGE):
                chunk = self._all[i : i + PAGE]
                used = sum(1 for c in chunk if c["state"] in ("gateway", "device", "host"))
                self.block.addItem(f"{chunk[0]['ip']} – {chunk[-1]['ip']}   ({used} in use)", i)
            self.block.show()
        else:
            self.block.hide()
        self.block.blockSignals(False)
        self._show_block()

    def _show_block(self, *_):
        start = self.block.currentData() or 0
        self.cells.set_cells(self._all[start : start + PAGE])
