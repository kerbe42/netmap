"""A table page: filter box, column chooser, CSV export, sortable view over `views` rows."""
from __future__ import annotations

import csv
import re
from typing import Callable, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QRect, QSettings, QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QAction, QBrush, QColor, QGuiApplication, QKeySequence, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..views import Column, fmt_duration, fmt_time, sort_key
from .icons import role_icon

ID_ROLE = Qt.UserRole + 1
ROW_ROLE = Qt.UserRole + 2
SORT_ROLE = Qt.UserRole + 3

SEVERITY_COLORS = {"attention": "#dc2626", "check": "#d97706", "info": "#64748b"}
ICON_COLUMNS = {"name", "cidr", "a", "device", "ip"}


def display(col: Column, v) -> str:
    if v is None or v == "":
        return ""
    if col.kind == "time":
        return fmt_time(v)
    if col.kind == "duration":
        return fmt_duration(v)
    if col.kind == "pct":
        return f"{float(v):.1f}%"
    if col.kind == "bool":
        return "yes" if v else "no"
    return str(v)


class RowsModel(QAbstractTableModel):
    def __init__(self, columns: list[Column], parent=None):
        super().__init__(parent)
        self.columns = columns
        self.rows: list[dict] = []
        self._icons: dict = {}

    def set_rows(self, rows: list[dict]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal:
            col = self.columns[section]
            if role == Qt.DisplayRole:
                return col.title
            if role == Qt.ToolTipRole and col.tip:
                return col.tip
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        col = self.columns[index.column()]
        v = row.get(col.key)
        if role == Qt.DisplayRole:
            if col.key == "ports_up" and row.get("_ports_total"):
                return f"{v} / {row['_ports_total']}"
            return display(col, v)
        if role == SORT_ROLE:
            return sort_key(col.kind, v)
        if role == ID_ROLE:
            return row.get("_id")
        if role == ROW_ROLE:
            return row
        if role == Qt.DecorationRole and index.column() == 0 and col.key in ICON_COLUMNS and (row.get("_role") or row.get("_kind") == "subnet"):
            key = (row.get("_role"), row.get("_kind"))
            if key not in self._icons:
                kind = row.get("_kind")
                self._icons[key] = role_icon(row.get("_role") or "unknown", "subnet" if kind == "subnet" else ("host" if kind == "host" else "device"))
            return self._icons[key]
        if role == Qt.ToolTipRole:
            s = display(col, v)
            return s if len(s) > 30 else None
        if role == Qt.ForegroundRole:
            if col.key == "severity":
                return QBrush(QColor(SEVERITY_COLORS.get(str(v).lower(), "#64748b")))
            if col.key == "status" and v in ("down", "disabled"):
                return QBrush(QColor("#94a3b8"))
            if (col.key == "speed" and row.get("_mismatch")) or (col.key == "names" and row.get("_conflict")):
                return QBrush(QColor("#d97706"))
        if role == Qt.FontRole and col.key == "severity":
            from PySide6.QtGui import QFont

            f = QFont()
            f.setBold(True)
            return f
        if role == Qt.TextAlignmentRole and col.kind in ("int", "pct", "duration"):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None


class FilterProxy(QSortFilterProxyModel):
    """Every word must match some visible column; `column:text` narrows a word to one column
    (by key or by the start of its title), e.g. ``role:switch vendor:cisco``."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.terms: list[tuple[Optional[int], str]] = []
        self.hidden: set[int] = set()
        self.setSortRole(SORT_ROLE)

    def set_filter(self, text: str) -> None:
        model: RowsModel = self.sourceModel()
        terms = []
        for word in re.findall(r'"[^"]+"|\S+', text.strip()):
            word = word.strip('"').lower()
            col = None
            if ":" in word and not re.match(r"^[0-9a-f:.]+$", word):
                name, _, val = word.partition(":")
                for i, c in enumerate(model.columns):
                    if c.key.lower() == name or c.title.lower().startswith(name):
                        col = i
                        break
                if col is not None:
                    word = val
            if word:
                terms.append((col, word))
        self.terms = terms
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self.terms:
            return True
        model: RowsModel = self.sourceModel()
        row = model.rows[source_row]
        texts = [display(c, row.get(c.key)).lower() for c in model.columns]
        for col, word in self.terms:
            if col is not None:
                if word not in texts[col]:
                    return False
            elif not any(word in t for i, t in enumerate(texts) if i not in self.hidden):
                return False
        return True

    def lessThan(self, left, right):
        a = left.data(SORT_ROLE)
        b = right.data(SORT_ROLE)
        try:
            return a < b
        except TypeError:
            return str(a) < str(b)


class BarDelegate(QStyledItemDelegate):
    """Utilisation as a bar behind the percentage."""

    def paint(self, painter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        style = opt.widget.style() if opt.widget else None
        text = opt.text
        opt.text = ""
        if style:
            style.drawControl(QStyle.CE_ItemViewItem, opt, painter, opt.widget)
        try:
            pct = float(str(index.data(Qt.DisplayRole)).rstrip("%") or 0)
        except ValueError:
            pct = 0.0
        r = option.rect.adjusted(4, 5, -4, -5)
        painter.save()
        painter.setPen(Qt.NoPen)
        pal = option.palette
        painter.setBrush(pal.color(QPalette.Midlight) if pct < 100 else QColor("#fecaca"))
        painter.drawRoundedRect(r, 3, 3)
        color = QColor("#16a34a") if pct < 60 else QColor("#d97706") if pct < 85 else QColor("#dc2626")
        w = int(r.width() * min(pct, 100) / 100)
        if w > 0:
            painter.setBrush(color)
            painter.drawRoundedRect(QRect(r.left(), r.top(), w, r.height()), 3, 3)
        painter.setPen(pal.color(QPalette.Text) if pct < 50 else QColor("white"))
        painter.drawText(r.adjusted(4, 0, -4, 0), Qt.AlignVCenter | Qt.AlignRight, text)
        painter.restore()


class DataPage(QWidget):
    """One inventory list. Emits the node id of what the user selects or opens."""

    nodeSelected = Signal(str)
    nodeActivated = Signal(str)
    contextRequested = Signal(object, object)  # (row dict, global QPoint)

    def __init__(self, key: str, title: str, columns: list[Column], hint: str = "", parent=None):
        super().__init__(parent)
        self.key = key
        self.title = title
        self.model = RowsModel(columns, self)
        self.proxy = FilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortCaseSensitivity(Qt.CaseInsensitive)

        self.heading = QLabel(f"<b>{title}</b>")
        self.count = QLabel()
        self.count.setObjectName("muted")
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(hint or "Filter… (words match any column; column:value for one, e.g. role:switch)")
        self.filter.setClearButtonEnabled(True)
        # filter as you type, but not on every keystroke of a 20,000-row list
        from PySide6.QtCore import QTimer

        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(180)
        self._filter_timer.timeout.connect(lambda: self._on_filter(self.filter.text()))
        self.filter.textChanged.connect(lambda _: self._filter_timer.start())
        self.filter.returnPressed.connect(lambda: (self._filter_timer.stop(), self._on_filter(self.filter.text())))
        self.columns_btn = QToolButton()
        self.columns_btn.setText("Columns")
        self.columns_btn.setPopupMode(QToolButton.InstantPopup)
        self.columns_btn.setMenu(QMenu(self.columns_btn))
        self.columns_btn.menu().aboutToShow.connect(self._fill_columns_menu)
        self.export_btn = QToolButton()
        self.export_btn.setText("Export CSV…")
        self.export_btn.clicked.connect(self.export_csv)

        top = QHBoxLayout()
        top.setContentsMargins(8, 6, 8, 4)
        top.addWidget(self.heading)
        top.addWidget(self.count)
        top.addStretch(1)
        top.addWidget(self.filter, 3)
        top.addWidget(self.columns_btn)
        top.addWidget(self.export_btn)

        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.view.setWordWrap(False)
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(24)
        self.view.horizontalHeader().setHighlightSections(False)
        self.view.horizontalHeader().setSectionsMovable(True)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.horizontalHeader().setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.horizontalHeader().customContextMenuRequested.connect(lambda p: self._columns_menu().exec(self.view.horizontalHeader().mapToGlobal(p)))
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._on_context)
        self.view.doubleClicked.connect(self._on_activate)
        self.view.selectionModel().currentRowChanged.connect(self._on_current)
        self.view.setIconSize(self.view.iconSize().expandedTo(self.view.iconSize()))
        for i, c in enumerate(columns):
            if c.kind == "pct":
                self.view.setItemDelegateForColumn(i, BarDelegate(self.view))
            if c.width:
                self.view.setColumnWidth(i, c.width)
            self.view.setColumnHidden(i, not c.visible)
        copy = QAction("Copy", self.view)
        copy.setShortcut(QKeySequence.Copy)
        copy.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        copy.triggered.connect(self.copy_selection)
        self.view.addAction(copy)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addLayout(top)
        lay.addWidget(self.view, 1)
        self._restore_state()
        self._sorted_once = False

    # ---- data ----
    def set_rows(self, rows: list[dict]) -> None:
        """Replace the rows, keeping selection, scroll position and sort."""
        keep = self.selected_ids()
        scroll = self.view.verticalScrollBar().value()
        self.model.set_rows(rows)
        if not self._sorted_once and rows:
            self._sorted_once = True
            hdr = self.view.horizontalHeader()
            if not self._restored or hdr.sortIndicatorSection() >= self.model.columnCount():
                # Qt's default indicator is descending; a fresh list reads A-Z by its first column
                self.view.sortByColumn(0, Qt.AscendingOrder)
            else:
                self.view.sortByColumn(hdr.sortIndicatorSection(), hdr.sortIndicatorOrder())
        if keep:
            self.select_ids(keep, scroll=False)
        self.view.verticalScrollBar().setValue(scroll)
        self._update_count()

    def selected_rows(self) -> list[dict]:
        out = []
        for idx in self.view.selectionModel().selectedRows():
            out.append(idx.data(ROW_ROLE))
        return out

    def selected_ids(self) -> list[str]:
        return [r["_id"] for r in self.selected_rows() if r and r.get("_id")]

    def select_ids(self, ids, scroll: bool = True) -> bool:
        ids = set(ids)
        sm = self.view.selectionModel()
        sm.clearSelection()
        first = None
        for r in range(self.proxy.rowCount()):
            idx = self.proxy.index(r, 0)
            if idx.data(ID_ROLE) in ids:
                sm.select(idx, sm.SelectionFlag.Select | sm.SelectionFlag.Rows)
                if first is None:
                    first = idx
        if first is not None:
            sm.setCurrentIndex(first, sm.SelectionFlag.NoUpdate)
            if scroll:
                self.view.scrollTo(first, QAbstractItemView.PositionAtCenter)
        return first is not None

    # ---- events ----
    def _on_filter(self, text):
        self.proxy.hidden = {i for i in range(self.model.columnCount()) if self.view.isColumnHidden(i)}
        self.proxy.set_filter(text)
        self._update_count()

    def _update_count(self):
        total = self.model.rowCount()
        shown = self.proxy.rowCount()
        self.count.setText(f"  {shown:,} of {total:,}" if shown != total else f"  {total:,}")

    def _on_current(self, cur, _prev):
        nid = cur.data(ID_ROLE) if cur.isValid() else None
        if nid:
            self.nodeSelected.emit(nid)

    def _on_activate(self, idx):
        nid = idx.data(ID_ROLE)
        if nid:
            self.nodeActivated.emit(nid)

    def _on_context(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        self.contextRequested.emit(idx.data(ROW_ROLE), self.view.viewport().mapToGlobal(pos))

    # ---- columns ----
    def _columns_menu(self) -> QMenu:
        m = QMenu(self)
        self._fill(m)
        return m

    def _fill_columns_menu(self):
        self._fill(self.columns_btn.menu())

    def _fill(self, m: QMenu):
        m.clear()
        for i, c in enumerate(self.model.columns):
            a = m.addAction(c.title)
            a.setCheckable(True)
            a.setChecked(not self.view.isColumnHidden(i))
            a.toggled.connect(lambda on, i=i: (self.view.setColumnHidden(i, not on), self._save_state()))
        m.addSeparator()
        m.addAction("Reset columns", self._reset_columns)

    def _reset_columns(self):
        hdr = self.view.horizontalHeader()
        for i, c in enumerate(self.model.columns):
            hdr.moveSection(hdr.visualIndex(i), i)
            self.view.setColumnHidden(i, not c.visible)
            if c.width:
                self.view.setColumnWidth(i, c.width)
        self._save_state()

    def _save_state(self):
        s = QSettings()
        s.setValue(f"tables/{self.key}/header", self.view.horizontalHeader().saveState())

    def _restore_state(self):
        st = QSettings().value(f"tables/{self.key}/header")
        self._restored = False
        if st is not None:
            try:
                self._restored = bool(self.view.horizontalHeader().restoreState(st))
            except TypeError:
                pass
        self.view.horizontalHeader().sectionResized.connect(lambda *_: self._save_state())
        self.view.horizontalHeader().sectionMoved.connect(lambda *_: self._save_state())
        self.view.horizontalHeader().sortIndicatorChanged.connect(lambda *_: self._save_state())

    # ---- output ----
    def visible_table(self, selected_only: bool = False) -> tuple[list[str], list[list[str]]]:
        hdr = self.view.horizontalHeader()
        cols = [hdr.logicalIndex(v) for v in range(hdr.count())]
        cols = [c for c in cols if not self.view.isColumnHidden(c)]
        headers = [self.model.columns[c].title for c in cols]
        rows = []
        if selected_only:
            idxs = sorted(self.view.selectionModel().selectedRows(), key=lambda i: i.row())
            prow = [i.row() for i in idxs]
        else:
            prow = range(self.proxy.rowCount())
        for r in prow:
            rows.append([str(self.proxy.index(r, c).data(Qt.DisplayRole) or "") for c in cols])
        return headers, rows

    def copy_selection(self):
        headers, rows = self.visible_table(selected_only=True)
        if not rows:
            return
        text = "\n".join("\t".join(r) for r in [headers] + rows)
        QGuiApplication.clipboard().setText(text)

    def export_csv(self, path: str = ""):
        if not path:
            path, _ = QFileDialog.getSaveFileName(self, f"Export {self.title}", f"{self.key}.csv", "CSV files (*.csv)")
        if not path:
            return
        headers, rows = self.visible_table()
        with open(path, "w", newline="", encoding="utf-8-sig") as f:  # BOM: Excel opens it as UTF-8
            w = csv.writer(f)
            w.writerow(headers)
            w.writerows(rows)
        return path
