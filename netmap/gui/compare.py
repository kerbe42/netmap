"""Compare this project with another scan of the same network."""
from __future__ import annotations

import csv

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout

from ..diff import Diff

COLORS = {"added": "#16a34a", "removed": "#dc2626", "changed": "#d97706", "moved": "#2563eb"}
KINDS = [("device", "Devices"), ("link", "Links"), ("subnet", "Subnets"), ("vlan", "VLANs"), ("host", "Hosts")]


class CompareDialog(QDialog):
    openNode = Signal(str)

    def __init__(self, diff: Diff, old_name: str, new_name: str, parent=None):
        super().__init__(parent)
        self.diff = diff
        self.setWindowTitle("Compare scans")
        s = diff.summary()
        head = QLabel(f"Changes from <b>{old_name}</b> (earlier) to <b>{new_name}</b> (this project)." if diff.changes else f"No differences between <b>{old_name}</b> and <b>{new_name}</b>.")
        head.setWordWrap(True)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Item", "Change", "Detail"])
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(1, 80)
        self.tree.setAlternatingRowColors(True)
        for kind, title in KINDS:
            items = diff.of(kind)
            if not items:
                continue
            counts = ", ".join(f"{n} {c}" for c, n in sorted(s.get(kind, {}).items()))
            top = QTreeWidgetItem([f"{title} ({counts})", "", ""])
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            self.tree.addTopLevelItem(top)
            for c in items:
                it = QTreeWidgetItem([c.name or c.item, c.change, c.detail])
                it.setData(0, Qt.UserRole, c.item)
                it.setForeground(1, QBrush(QColor(COLORS.get(c.change, "#64748b"))))
                it.setToolTip(2, c.detail)
                top.addChild(it)
            top.setExpanded(len(items) <= 200)
        self.tree.itemDoubleClicked.connect(lambda it, _: it.data(0, Qt.UserRole) and self.openNode.emit(it.data(0, Qt.UserRole)))
        exp = QPushButton("Export CSV…")
        exp.clicked.connect(self._export)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.reject)
        bb.accepted.connect(self.accept)
        row = QHBoxLayout()
        row.addWidget(exp)
        row.addStretch(1)
        row.addWidget(bb)
        lay = QVBoxLayout(self)
        lay.addWidget(head)
        lay.addWidget(self.tree, 1)
        lay.addLayout(row)
        self.resize(860, 560)

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export changes", "changes.csv", "CSV files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["kind", "change", "item", "name", "detail"])
            for c in self.diff.changes:
                w.writerow([c.kind, c.change, c.item, c.name, c.detail])
