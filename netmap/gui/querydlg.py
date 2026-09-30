"""An asset-search console: type a query, get a table. Backed by netmap.query."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from ..query import QueryError, pages, run_query
from .table import ID_ROLE, FilterProxy, PlaceholderTableView, RowsModel

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

RESIZE_TO_CONTENTS_MAX = 2000  # above this many rows, columns take their declared widths


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
        # the same model/view pair as the inventory pages: 14,000 result rows cost a list of
        # dicts, not 14,000 x columns QTableWidgetItems
        self.model = RowsModel([], self)
        self.proxy = FilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.table = PlaceholderTableView()
        self.table.set_placeholder("Type a query and press Enter, or pick an example.")
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.doubleClicked.connect(self._open)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)
        self.resize(900, 560)
        self._rows = []
        self._cols = []

    def run(self):
        try:
            cols, rows = run_query(self.snapshot, self.edit.text())
        except QueryError as e:
            self.status.setText(f"<span style='color:#dc2626'>{e}</span>")
            return
        self._cols = cols
        self._rows = rows
        self.model = RowsModel(cols, self)
        self.model.set_rows(rows)
        self.proxy.setSourceModel(self.model)
        hdr = self.table.horizontalHeader()
        hdr.setSortIndicator(-1, Qt.AscendingOrder)
        if len(rows) <= RESIZE_TO_CONTENTS_MAX:
            self.table.resizeColumnsToContents()
        else:
            for i, c in enumerate(cols):
                self.table.setColumnWidth(i, c.width or 120)
        self.table.viewport().update()
        self.status.setText(f"{len(rows)} result(s). Double-click a row to open it.")

    def row_count(self) -> int:
        return self.model.rowCount()

    def _open(self, idx):
        nid = idx.data(ID_ROLE)
        if nid:
            self.openNode.emit(nid)
