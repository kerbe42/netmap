"""Check the project against an asset list (CSV or Excel)."""
from __future__ import annotations

import os

from PySide6.QtCore import QSettings, Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..reconcile import FIELDS, guess_columns, read_table, reconcile, write_csv

FIELD_TITLES = {"ip": "Address", "name": "Name", "serial": "Serial number", "mac": "MAC address", "model": "Model", "site": "Site / location"}


class ReconcileDialog(QDialog):
    openNode = Signal(str)
    applied = Signal()

    def __init__(self, inv, parent=None):
        super().__init__(parent)
        self.inv = inv
        self.setWindowTitle("Check against an asset list")
        self.headers: list[str] = []
        self.rows: list[list[str]] = []
        self.rec = None
        self.stack = QStackedWidget()

        # page 1: file and columns
        p1 = QWidget()
        l1 = QVBoxLayout(p1)
        intro = QLabel("Compare what the scans found with the list of devices you were given (CSV or Excel). "
                       "Rows are matched by address, then serial number, then name, then MAC address.")
        intro.setWordWrap(True)
        l1.addWidget(intro)
        row = QHBoxLayout()
        self.path = QLineEdit()
        self.path.setReadOnly(True)
        pick = QPushButton("Choose file…")
        pick.clicked.connect(self._pick)
        row.addWidget(self.path, 1)
        row.addWidget(pick)
        l1.addLayout(row)
        self.form = QFormLayout()
        self.combos: dict[str, QComboBox] = {}
        for f in FIELDS:
            cb = QComboBox()
            self.combos[f] = cb
            self.form.addRow(FIELD_TITLES[f], cb)
        l1.addLayout(self.form)
        self.preview = QLabel()
        self.preview.setObjectName("muted")
        self.preview.setWordWrap(True)
        l1.addWidget(self.preview)
        l1.addStretch(1)
        self.stack.addWidget(p1)

        # page 2: results
        p2 = QWidget()
        l2 = QVBoxLayout(p2)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        l2.addWidget(self.summary)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Item", "Matched", "Detail"])
        self.tree.setColumnWidth(0, 280)
        self.tree.setColumnWidth(1, 200)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemDoubleClicked.connect(lambda it, _: it.data(0, Qt.UserRole) and self.openNode.emit(it.data(0, Qt.UserRole)))
        l2.addWidget(self.tree, 1)
        self.copy_notes = QCheckBox("Copy the list's names and sites into Notes for the devices it matched (where Notes are empty)")
        l2.addWidget(self.copy_notes)
        self.stack.addWidget(p2)

        self.bb = QDialogButtonBox()
        self.run_btn = self.bb.addButton("Compare", QDialogButtonBox.AcceptRole)
        self.export_btn = self.bb.addButton("Export CSV…", QDialogButtonBox.ActionRole)
        self.back_btn = self.bb.addButton("Back", QDialogButtonBox.ActionRole)
        self.close_btn = self.bb.addButton(QDialogButtonBox.Close)
        self.run_btn.clicked.connect(self._run)
        self.export_btn.clicked.connect(self._export)
        self.back_btn.clicked.connect(lambda: self._page(0))
        self.close_btn.clicked.connect(self._close)
        lay = QVBoxLayout(self)
        lay.addWidget(self.stack, 1)
        lay.addWidget(self.bb)
        self._page(0)
        self.resize(820, 560)

    def _page(self, i):
        self.stack.setCurrentIndex(i)
        self.run_btn.setVisible(i == 0)
        self.run_btn.setEnabled(bool(self.rows))
        self.export_btn.setVisible(i == 1)
        self.back_btn.setVisible(i == 1)

    def _pick(self):
        start = QSettings().value("ui/last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(self, "Asset list", start, "Spreadsheets (*.csv *.xlsx *.txt);;All files (*)")
        if path:
            self.load(path)

    def load(self, path: str):
        try:
            self.headers, self.rows = read_table(path)
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "Could not read the list", f"{path}\n\n{e}")
            return
        self.path.setText(path)
        guess = guess_columns(self.headers)
        for f, cb in self.combos.items():
            cb.clear()
            cb.addItem("(not in the list)", -1)
            for i, h in enumerate(self.headers):
                cb.addItem(h or f"column {i + 1}", i)
            if f in guess:
                cb.setCurrentIndex(guess[f] + 1)
        self.preview.setText(f"{len(self.rows)} rows. Columns found: " + ", ".join(h for h in self.headers if h))
        self._page(0)

    def columns(self) -> dict[str, int]:
        return {f: cb.currentData() for f, cb in self.combos.items() if cb.currentData() is not None and cb.currentData() >= 0}

    def _run(self):
        cols = self.columns()
        if not cols:
            QMessageBox.information(self, "Columns", "Choose at least one column to match on (address, serial, name or MAC).")
            return
        self.rec = rec = reconcile(self.inv, self.rows, cols)
        self.tree.clear()

        def group(title, color):
            top = QTreeWidgetItem([title, "", ""])
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            top.setForeground(0, QBrush(QColor(color)))
            self.tree.addTopLevelItem(top)
            return top

        def label(m):
            return m.listed.get("name") or m.listed.get("ip") or m.listed.get("serial") or m.listed.get("mac") or f"row {m.row + 2}"

        g = group(f"Listed, but not found ({len(rec.missing)})", "#dc2626")
        for m in rec.missing:
            g.addChild(QTreeWidgetItem([label(m), "", " · ".join(f"{k} {v}" for k, v in m.listed.items())]))
        g = group(f"Found, but different from the list ({len(rec.differ)})", "#d97706")
        for m in rec.differ:
            it = QTreeWidgetItem([label(m), f"{self.inv.display_name(m.node)} (by {m.how})", "; ".join(m.differences)])
            it.setData(0, Qt.UserRole, m.node)
            g.addChild(it)
        g.setExpanded(True)
        g = group(f"On the network, not in the list ({len(rec.unlisted)})", "#2563eb")
        for did in rec.unlisted:
            d = self.inv.devices[did]
            it = QTreeWidgetItem([self.inv.display_name(did), did, " ".join(x for x in (d.vendor, d.model, d.serial) if x)])
            it.setData(0, Qt.UserRole, did)
            g.addChild(it)
        g.setExpanded(True)
        g = group(f"Listed and found ({len(rec.found)})", "#16a34a")
        for m in rec.found:
            it = QTreeWidgetItem([label(m), f"{self.inv.display_name(m.node)} (by {m.how})", ""])
            it.setData(0, Qt.UserRole, m.node)
            g.addChild(it)
        self.tree.topLevelItem(0).setExpanded(True)
        self.summary.setText(f"<b>{len(rec.matches)}</b> rows compared: <b>{len(rec.found)}</b> found as listed, "
                             f"<b>{len(rec.differ)}</b> found but different, <b>{len(rec.missing)}</b> not found; "
                             f"<b>{len(rec.unlisted)}</b> network devices are not in the list. Double-click an item to open it.")
        self.copy_notes.setVisible("name" in cols or "site" in cols)
        self._page(1)

    def _export(self):
        if not self.rec:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export comparison", "asset-list-check.csv", "CSV files (*.csv)")
        if path:
            write_csv(self.inv, self.rec, path)

    def apply_notes(self) -> int:
        """Names and sites from the list into Notes of matched items that have none yet."""
        n = 0
        for m in (self.rec.found + self.rec.differ) if self.rec else []:
            note = self.inv.note(m.node)
            fields = {}
            if m.listed.get("site") and not note.get("site"):
                fields["site"] = m.listed["site"]
            if m.listed.get("name") and not note.get("name") and m.node not in self.inv.devices:
                fields["name"] = m.listed["name"]
            if fields:
                self.inv.annotate(m.node, **fields)
                n += 1
        return n

    def _close(self):
        if self.rec and self.copy_notes.isVisible() and self.copy_notes.isChecked():
            if self.apply_notes():
                self.applied.emit()
        self.reject()
