"""A table page: filter box, column chooser, CSV export, sortable view over `views` rows."""
from __future__ import annotations

import csv
import re
from typing import Callable, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QRect, QSettings, QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QAction, QBrush, QColor, QGuiApplication, QKeySequence, QPainter, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
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
from .fileutil import ask_save_path
from .icons import ROLE_LABELS, role_icon

ID_ROLE = Qt.UserRole + 1
ROW_ROLE = Qt.UserRole + 2
SORT_ROLE = Qt.UserRole + 3

SEVERITY_COLORS = {"attention": "#dc2626", "check": "#d97706", "info": "#64748b", "high": "#dc2626", "medium": "#d97706", "low": "#64748b"}
ICON_COLUMNS = {"name", "cidr", "a", "device", "ip"}
ROLE_COLUMNS = {"role"}  # raw role keys shown as their labels (workstation -> Workstation)
DASH = "—"

# the column a fresh list is sorted by when the user has not chosen one (else column 0)
DEFAULT_SORT = {"hosts": "ip"}
# pages whose rows can be acknowledged (hidden until "Show acknowledged" is ticked)
ACK_PAGES = {"findings", "compliance"}

EMPTY_TEXT = {
    "devices": "No network devices yet — run a scan (Scan ▸ New scan) or open a project.",
    "hosts": "No hosts yet — run a scan (Scan ▸ New scan) or open a project.",
    "subnets": "No subnets yet — they appear as soon as a scan finds a device with an address.",
    "vlans": "No VLANs yet — they come from the switches a scan polls.",
    "links": "No links yet — a scan learns them from LLDP/CDP and routing tables.",
    "interfaces": "No interfaces yet — run a scan to poll the devices.",
    "hardware": "No hardware inventory yet — run a scan to poll the devices.",
    "dependencies": "No dependencies yet — Tools ▸ Inspect servers collects the connections they are built from.",
    "findings": "Nothing needs attention — or nothing has been scanned yet.",
    "compliance": "No compliance findings — or nothing has been scanned yet.",
    "history": "No scans yet — Scan ▸ New scan records one here.",
}
FILTERED_TEXT = "Nothing matches the filter."


def display(col: Column, v) -> str:
    if v is None or v == "":
        return ""
    if col.kind == "time":
        return fmt_time(v)
    if col.kind == "duration":
        return fmt_duration(v) or DASH
    if col.kind == "pct":
        return f"{float(v):.1f}%"
    if col.kind == "bool":
        return "yes" if v else "no"
    if col.key in ROLE_COLUMNS:
        return ROLE_LABELS.get(str(v), str(v))
    return str(v)


def _row_sort_key(kind: str, key: str, row: dict):
    return sort_key(kind, row.get(key))


class RowsModel(QAbstractTableModel):
    """Rows as dicts. Sorting happens here, once per sort, with a precomputed key per row:
    at 14,000 rows this is ~200x cheaper than the proxy comparing cells through lessThan."""

    def __init__(self, columns: list[Column], parent=None):
        super().__init__(parent)
        self.columns = columns
        self.rows: list[dict] = []
        self._icons: dict = {}
        self._sort_col = -1
        self._sort_order = Qt.AscendingOrder

    def set_rows(self, rows: list[dict]) -> None:
        self.beginResetModel()
        self.rows = list(rows)
        if 0 <= self._sort_col < len(self.columns):
            self._sort_rows(self._sort_col, self._sort_order)
        self.endResetModel()

    def _sort_rows(self, column: int, order) -> None:
        col = self.columns[column]
        kind, key = col.kind, col.key
        rev = order == Qt.DescendingOrder
        try:
            self.rows.sort(key=lambda r: _row_sort_key(kind, key, r), reverse=rev)
        except TypeError:  # mixed key shapes: fall back to their text
            self.rows.sort(key=lambda r: str(_row_sort_key(kind, key, r)), reverse=rev)

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:  # noqa: D401 - Qt API
        if column < 0 or column >= len(self.columns):
            self._sort_col = -1
            return
        self._sort_col = column
        self._sort_order = order
        if not self.rows:
            return
        self.layoutAboutToBeChanged.emit()
        self._sort_rows(column, order)
        self.layoutChanged.emit()

    def sort_state(self) -> tuple[int, Qt.SortOrder]:
        return self._sort_col, self._sort_order

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
            if row.get("_ack"):
                return QBrush(QColor("#94a3b8"))
            if col.key == "severity":
                return QBrush(QColor(SEVERITY_COLORS.get(str(v).lower(), "#64748b")))
            if col.key == "status" and v in ("down", "disabled"):
                return QBrush(QColor("#94a3b8"))
            if (col.key == "speed" and row.get("_mismatch")) or (col.key == "names" and row.get("_conflict")):
                return QBrush(QColor("#d97706"))
        if role == Qt.FontRole and (col.key == "severity" or row.get("_ack")):
            from PySide6.QtGui import QFont

            f = QFont()
            f.setBold(col.key == "severity" and not row.get("_ack"))
            f.setStrikeOut(bool(row.get("_ack")))
            return f
        if role == Qt.TextAlignmentRole and col.kind in ("int", "pct", "duration"):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None


class FilterProxy(QSortFilterProxyModel):
    """Every word must match some visible column; `column:text` narrows a word to one column
    (by key or by the start of its title), e.g. ``role:switch vendor:cisco``.

    Sorting is delegated to the source RowsModel (one pass with precomputed keys) instead of
    the proxy's per-comparison lessThan; dynamic re-sorting is off, the model re-sorts when
    its rows are replaced."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.terms: list[tuple[Optional[int], str]] = []
        self.hidden: set[int] = set()
        self.setSortRole(SORT_ROLE)
        self.setDynamicSortFilter(False)

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:  # noqa: D401 - Qt API
        src = self.sourceModel()
        if isinstance(src, RowsModel):
            src.sort(column, order)
        else:
            super().sort(column, order)

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
        # cache the lowercased per-column text on the row: filtering re-checks every
        # visible cell on each keystroke, and re-rendering them all is the cost at scale.
        # The cache lives on the row dict, which is rebuilt on every set_rows.
        texts = row.get("_disp")
        if texts is None:
            texts = []
            for c in model.columns:
                t = display(c, row.get(c.key)).lower()
                if c.key in ROLE_COLUMNS and row.get(c.key):
                    t += " " + str(row.get(c.key)).lower()  # role:dc still finds "Domain controller"
                texts.append(t)
            row["_disp"] = texts
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


def bar_text_color(pct: float, bar_rect: QRect, text_width: int, text_pad: int = 4) -> str:
    """'white' when the filled part of the bar covers the (right-aligned) percentage text,
    else 'text' (the palette's text colour). A half-full bar leaves the number over the
    unfilled track, where white would be unreadable."""
    fill_end = bar_rect.left() + int(bar_rect.width() * min(max(pct, 0.0), 100.0) / 100)
    text_left = bar_rect.right() - text_pad - text_width
    return "white" if fill_end >= bar_rect.right() - text_pad - 1 or (fill_end >= text_left + text_width) else "text"


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
        tw = painter.fontMetrics().horizontalAdvance(text)
        painter.setPen(QColor("white") if bar_text_color(pct, r, tw) == "white" else pal.color(QPalette.Text))
        painter.drawText(r.adjusted(4, 0, -4, 0), Qt.AlignVCenter | Qt.AlignRight, text)
        painter.restore()


class PlaceholderTableView(QTableView):
    """A table that says why it is empty instead of showing a blank grid."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.placeholder = ""
        self.filtered_placeholder = FILTERED_TEXT

    def set_placeholder(self, text: str) -> None:
        self.placeholder = text
        self.viewport().update()

    def _empty_text(self) -> str:
        m = self.model()
        if m is None or m.rowCount() > 0:
            return ""
        src = m.sourceModel() if isinstance(m, QSortFilterProxyModel) else None
        if src is not None and src.rowCount() > 0:
            return self.filtered_placeholder
        return self.placeholder

    def paintEvent(self, e):
        super().paintEvent(e)
        text = self._empty_text()
        if not text:
            return
        p = QPainter(self.viewport())
        p.setPen(self.palette().color(QPalette.PlaceholderText))
        r = self.viewport().rect().adjusted(24, 24, -24, -24)
        p.drawText(r, Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap, text)
        p.end()


class DataPage(QWidget):
    """One inventory list. Emits the node id of what the user selects or opens."""

    nodeSelected = Signal(str)
    nodeActivated = Signal(str)
    contextRequested = Signal(object, object)  # (row dict, global QPoint)
    showAcknowledgedChanged = Signal(bool)

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
        self.show_ack = QCheckBox("Show acknowledged")
        self.show_ack.setToolTip("Rows you acknowledged (right-click ▸ Acknowledge) are hidden unless this is ticked")
        self.show_ack.setVisible(key in ACK_PAGES)
        self.show_ack.toggled.connect(self.showAcknowledgedChanged)
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
        top.addWidget(self.show_ack)
        top.addWidget(self.columns_btn)
        top.addWidget(self.export_btn)

        self.view = PlaceholderTableView()
        self.view.set_placeholder(EMPTY_TEXT.get(key, f"No {title.lower()} yet — run a scan or open a project."))
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
                # role keys become labels ("Domain controller"): give that column the room
                self.view.setColumnWidth(i, max(c.width, 130) if c.key in ROLE_COLUMNS else c.width)
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
    def _default_sort_column(self) -> int:
        want = DEFAULT_SORT.get(self.key)
        if want:
            for i, c in enumerate(self.model.columns):
                if c.key == want:
                    return i
        return 0

    def set_rows(self, rows: list[dict]) -> None:
        """Replace the rows, keeping selection, scroll position and sort."""
        keep = self.selected_ids()
        scroll = self.view.verticalScrollBar().value()
        hdr = self.view.horizontalHeader()
        if not self._sorted_once and rows:
            self._sorted_once = True
            untouched = hdr.sortIndicatorSection() == 0 and hdr.sortIndicatorOrder() == Qt.DescendingOrder  # Qt's own default
            if not self._restored or untouched or hdr.sortIndicatorSection() >= self.model.columnCount():
                # Qt's default indicator is descending; a fresh list reads A-Z (or by address)
                hdr.setSortIndicator(self._default_sort_column(), Qt.AscendingOrder)
            self.model.sort(hdr.sortIndicatorSection(), hdr.sortIndicatorOrder())
        self.model.set_rows(rows)  # re-applies the remembered sort in one pass
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
        self.view.viewport().update()

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
        # a layout pass before the first rows arrive (a hidden page being resized) must not
        # persist Qt's untouched default sort as if the user had chosen it
        if not getattr(self, "_sorted_once", False):
            return
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
            path = ask_save_path(self, f"Export {self.title}", f"{self.key}.csv", "CSV files (*.csv)")
        if not path:
            return
        headers, rows = self.visible_table()
        with open(path, "w", newline="", encoding="utf-8-sig") as f:  # BOM: spreadsheet apps open it as UTF-8
            w = csv.writer(f)
            w.writerow(headers)
            w.writerows(rows)
        return path
