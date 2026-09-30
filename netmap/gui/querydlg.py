"""An asset-search console: type a query, get a table. Backed by netmap.query."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from ..query import QueryError, pages, run_query
from .table import display

EXAMPLES = [
    "devices where role = switch",
    "devices where vendor ~ cisco and os_version ~ 16",
    "hosts where os ~ windows and confidence = high",
    "hosts where port = 3389",
    "interfaces where util > 80",
    "subnets where util > 75 order by util desc",
    "findings where severity = attention",
    "compliance where severity = high",
    "dependencies where service = https",
]


class QueryDialog(QDialog):
    openNode = Signal(str)

    def __init__(self, snapshot, parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self.setWindowTitle("Query")
        self.edit = QLineEdit()
        self.edit.setPlaceholderText("e.g. hosts where os ~ windows and confidence = high")
        self.edit.returnPressed.connect(self.run)
        run = QPushButton("Run")
        run.clicked.connect(self.run)
        self.examples = QComboBox()
        self.examples.addItem("Examples…", "")
        for ex in EXAMPLES:
            self.examples.addItem(ex, ex)
        self.examples.currentIndexChanged.connect(lambda _: self.examples.currentData() and (self.edit.setText(self.examples.currentData()), self.run()))
        top = QHBoxLayout()
        top.addWidget(self.edit, 1)
        top.addWidget(run)
        top.addWidget(self.examples)
        self.status = QLabel(f"Tables: {', '.join(pages())}.  Operators: = != ~ !~ > < >= <=.  Clauses: where / and / or / select / order by / limit.")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        self.table = QTableWidget(0, 0)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.doubleClicked.connect(self._open)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)
        self.resize(900, 560)
        self._rows = []

    def run(self):
        try:
            cols, rows = run_query(self.snapshot, self.edit.text())
        except QueryError as e:
            self.status.setText(f"<span style='color:#dc2626'>{e}</span>")
            return
        self._cols = cols
        self._rows = rows
        self.table.setColumnCount(len(cols))
        self.table.setHorizontalHeaderLabels([c.title for c in cols])
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, col in enumerate(cols):
                self.table.setItem(r, c, QTableWidgetItem(display(col, row.get(col.key))))
        self.table.resizeColumnsToContents()
        self.status.setText(f"{len(rows)} result(s). Double-click a row to open it.")

    def _open(self, idx):
        if 0 <= idx.row() < len(self._rows):
            nid = self._rows[idx.row()].get("_id")
            if nid:
                self.openNode.emit(nid)
