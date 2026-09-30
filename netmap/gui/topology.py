"""The topology map: a zoomable, draggable diagram of the inventory.

Three presets answer the questions people ask of an inherited network:

* Physical - what is cabled to what (LLDP/CDP links; hosts on their switch ports).
* Logical  - how it routes (routers, L3 switches and the subnets they serve).
* Everything - both at once.

Positions the user drags are saved in the project per preset, so the diagram they
tidied up is the one they get next time and the one that goes into the report.
"""
from __future__ import annotations

import math
from typing import Optional

from PySide6.QtCore import QPointF, QRectF, QSizeF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QAction,
    QActionGroup,
    QBrush,
    QColor,
    QFont,
    QFontMetricsF,
    QImage,
    QKeySequence,
    QPainter,
    QPainterPath,
    QPainterPathStroker,
    QPalette,
    QPen,
)
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QStyleOptionGraphicsItem,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import layout as L
from ..graph import edge_ports
from .icons import ROLE_LABELS, paint_badge, role_color, role_pixmap

PRESETS = {
    "physical": {"title": "Physical (cabling)", "l2": True, "l3": True, "subnets": False, "hosts": False, "unpolled": True},
    "logical": {"title": "Logical (routing & subnets)", "l2": False, "l3": True, "subnets": True, "hosts": False, "unpolled": False},
    "all": {"title": "Everything", "l2": True, "l3": True, "subnets": True, "hosts": False, "unpolled": True},
}
LAYOUTS = {"layered": "Layered (core on top)", "organic": "Organic", "radial": "Radial around selection"}
EDGE_TITLES = {"lldp": "LLDP", "cdp": "CDP", "l3": "Routing", "member": "Subnet", "fdb": "MAC table"}

NODE_SIZE = {"device": 40.0, "host": 26.0, "subnet": 30.0}


def _is_dark(pal: QPalette) -> bool:
    return pal.color(QPalette.Window).lightness() < 128


class NodeItem(QGraphicsObject):
    def __init__(self, node_id: str, attrs: dict, page: "TopologyPage"):
        super().__init__()
        self.node_id = node_id
        self.attrs = attrs
        self.page = page
        self.kind = attrs.get("kind", "device")
        self.role = attrs.get("role") or ("subnet" if self.kind == "subnet" else "unknown")
        self.size = NODE_SIZE.get(self.kind, 36.0)
        self.edges: list[EdgeItem] = []
        self.dimmed = False
        self.found = False
        self.setFlags(QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemIsSelectable | QGraphicsItem.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)
        self.setZValue(2 if self.kind == "device" else 1)
        self._label = str(attrs.get("label") or node_id)
        if self.kind == "device":
            ip = attrs.get("ip") or ""
            self._sub = ip if ip and ip != self._label else ""
        elif self.kind == "subnet":
            v = attrs.get("vlan")
            self._sub = f"VLAN {v}" if v else ""
        else:
            self._sub = attrs.get("ip", "") if attrs.get("label") and attrs.get("label") != attrs.get("ip") else ""
        self._font = QFont()
        self._font.setPointSizeF(8.5 if self.kind != "host" else 7.5)
        self._font.setBold(self.kind == "device")
        self._small = QFont()
        self._small.setPointSizeF(7.5 if self.kind != "host" else 7.0)
        fm = QFontMetricsF(self._font)
        fs = QFontMetricsF(self._small)
        self._text_w = min(max(fm.horizontalAdvance(self._label), fs.horizontalAdvance(self._sub)) + 8, 190.0)
        self._text_h = fm.height() + (fs.height() if self._sub else 0) + 2
        tip = [f"<b>{self._label}</b>", ROLE_LABELS.get(self.role, self.role)]
        for k in ("ip", "vendor", "model", "mac"):
            if attrs.get(k):
                tip.append(f"{k}: {attrs[k]}")
        if attrs.get("site"):
            tip.append(f"site: {attrs['site']}")
        self.setToolTip("<br>".join(str(t) for t in tip))

    def icon_rect(self) -> QRectF:
        s = self.size
        return QRectF(-s / 2, -s / 2, s, s)

    def boundingRect(self) -> QRectF:
        s = self.size
        w = max(s + (s * 0.6 if self.kind == "subnet" else 0), self._text_w) + 8
        return QRectF(-w / 2, -s / 2 - 5, w, s + 8 + self._text_h + 4)

    def shape(self):
        p = QPainterPath()
        r = self.icon_rect().adjusted(-3, -3, 3, 3)
        p.addRoundedRect(r, 6, 6)
        p.addRect(QRectF(-self._text_w / 2, self.size / 2 + 2, self._text_w, self._text_h))
        return p

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget=None):
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        pal = self.page.palette()
        dark = _is_dark(pal)
        painter.setOpacity(0.25 if self.dimmed else 1.0)
        r = self.icon_rect()
        if self.isSelected() or self.found:
            painter.setPen(Qt.NoPen)
            halo = QColor("#f59e0b") if self.found and not self.isSelected() else pal.color(QPalette.Highlight)
            halo.setAlpha(110)
            painter.setBrush(halo)
            painter.drawRoundedRect(r.adjusted(-7, -7, 7, 7), 10, 10)
        if lod < 0.22:
            painter.setPen(Qt.NoPen)
            painter.setBrush(role_color("subnet" if self.kind == "subnet" else self.role))
            painter.drawEllipse(r)
            return
        paint_badge(painter, r, self.role, self.kind, dashed=self.role == "unpolled")
        if lod < 0.45 and self.kind == "host":
            return
        if lod < 0.3:
            return
        text = QColor("#e5e7eb") if dark else QColor("#111827")
        muted = QColor("#94a3b8") if dark else QColor("#4b5563")
        y = self.size / 2 + 3
        tr = QRectF(-self._text_w / 2, y, self._text_w, self._text_h)
        bg = QColor(pal.color(QPalette.Base))
        bg.setAlpha(200)
        painter.setPen(Qt.NoPen)
        painter.setBrush(bg)
        painter.drawRoundedRect(tr, 3, 3)
        painter.setFont(self._font)
        painter.setPen(text)
        fm = QFontMetricsF(self._font)
        painter.drawText(QRectF(tr.left(), y, tr.width(), fm.height()), Qt.AlignHCenter | Qt.AlignTop, fm.elidedText(self._label, Qt.ElideMiddle, tr.width() - 4))
        if self._sub:
            painter.setFont(self._small)
            painter.setPen(muted)
            painter.drawText(QRectF(tr.left(), y + fm.height(), tr.width(), tr.height() - fm.height()), Qt.AlignHCenter | Qt.AlignTop, self._sub)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for e in self.edges:
                e.update_path()
            self.page.node_moved(self)
        elif change == QGraphicsItem.ItemSelectedHasChanged:
            for e in self.edges:
                e.update()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        for e in self.edges:
            e.hover = True
            e.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        for e in self.edges:
            e.hover = False
            e.update()
        super().hoverLeaveEvent(event)

    def mouseDoubleClickEvent(self, event):
        self.page.nodeActivated.emit(self.node_id)
        super().mouseDoubleClickEvent(event)


class EdgeItem(QGraphicsPathItem):
    def __init__(self, a: NodeItem, b: NodeItem, attrs: dict, page: "TopologyPage", slot: int = 0, slots: int = 1):
        super().__init__()
        self.a = a
        self.b = b
        self.attrs = attrs
        self.page = page
        self.kind = attrs.get("kind", "")
        self.slot = slot
        self.slots = slots
        self.hover = False
        self.setZValue(0)
        self.setAcceptHoverEvents(True)
        self.port_a, self.port_b = edge_ports(a.node_id, b.node_id, attrs)
        if self.kind in ("lldp", "cdp"):
            tip = f"{a._label} {self.port_a}  ↔  {b._label} {self.port_b}  ({EDGE_TITLES[self.kind]})"
        elif self.kind == "l3":
            tip = f"{a._label} ↔ {b._label}: {attrs.get('label', '')} (routing next-hop)"
        elif self.kind == "fdb":
            tip = f"{b._label if a.kind == 'device' else a._label} learned on {attrs.get('port', '')}" + (f", VLAN {attrs['vlan']}" if attrs.get("vlan") else "")
        else:
            tip = attrs.get("label") or EDGE_TITLES.get(self.kind, self.kind)
        self.setToolTip(tip)
        self.update_path()

    def _pen(self) -> QPen:
        dark = _is_dark(self.page.palette())
        hi = self.hover or self.a.isSelected() or self.b.isSelected()
        if self.kind in ("lldp", "cdp"):
            c = QColor("#60a5fa") if dark else QColor("#2563eb")
            pen = QPen(c, 2.2)
        elif self.kind == "l3":
            c = QColor("#fb923c") if dark else QColor("#ea580c")
            pen = QPen(c, 1.6, Qt.DashLine)
        elif self.kind == "member":
            c = QColor("#64748b") if dark else QColor("#94a3b8")
            pen = QPen(c, 1.2, Qt.DotLine)
        else:
            c = QColor("#475569") if dark else QColor("#cbd5e1")
            pen = QPen(c, 1.0)
        if hi:
            pen.setColor(self.page.palette().color(QPalette.Highlight))
            pen.setWidthF(pen.widthF() + 1.2)
        pen.setCosmetic(False)
        return pen

    def update_path(self):
        pa = self.a.pos()
        pb = self.b.pos()
        path = QPainterPath(pa)
        if self.slots > 1:
            off = (self.slot - (self.slots - 1) / 2) * 16.0
            dx, dy = pb.x() - pa.x(), pb.y() - pa.y()
            d = math.hypot(dx, dy) or 1.0
            mid = QPointF((pa.x() + pb.x()) / 2 - dy / d * off * 2, (pa.y() + pb.y()) / 2 + dx / d * off * 2)
            path.quadTo(mid, pb)
        else:
            path.lineTo(pb)
        self.prepareGeometryChange()
        self.setPath(path)

    def boundingRect(self):
        return super().boundingRect().adjusted(-60, -20, 60, 20)

    def shape(self):
        s = QPainterPathStroker()
        s.setWidth(8)
        return s.createStroke(self.path())

    def paint(self, painter: QPainter, option, widget=None):
        faded = self.a.dimmed or self.b.dimmed
        painter.setOpacity(0.15 if faded else 1.0)
        painter.setPen(self._pen())
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(self.path())
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        if self.page.show_ports and self.kind in ("lldp", "cdp") and lod > 0.7 and not faded:
            self._port_label(painter, self.a, self.port_a, 0.18)
            self._port_label(painter, self.b, self.port_b, 0.82)

    def _port_label(self, painter: QPainter, near: NodeItem, text: str, t: float):
        if not text:
            return
        p = self.path().pointAtPercent(t)
        f = QFont()
        f.setPointSizeF(6.8)
        painter.setFont(f)
        fm = QFontMetricsF(f)
        text = fm.elidedText(text, Qt.ElideRight, 90)
        w = fm.horizontalAdvance(text) + 6
        r = QRectF(p.x() - w / 2, p.y() - fm.height() / 2, w, fm.height())
        pal = self.page.palette()
        bg = QColor(pal.color(QPalette.Base))
        bg.setAlpha(225)
        painter.setPen(QPen(QColor("#94a3b8"), 0.6))
        painter.setBrush(bg)
        painter.drawRoundedRect(r, 3, 3)
        painter.setPen(pal.color(QPalette.Text))
        painter.drawText(r, Qt.AlignCenter, text)


class MapView(QGraphicsView):
    zoomChanged = Signal(float)

    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing | QPainter.SmoothPixmapTransform)
        self.setViewportUpdateMode(QGraphicsView.SmartViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setFrameShape(QFrame.NoFrame)
        self._zoom = 1.0

    def wheelEvent(self, event):
        steps = event.angleDelta().y() / 120.0
        if not steps:
            return
        self.zoom_by(1.18 ** steps)

    def zoom_by(self, factor: float):
        new = max(0.03, min(self._zoom * factor, 6.0))
        factor = new / self._zoom
        self._zoom = new
        self.scale(factor, factor)
        self.zoomChanged.emit(self._zoom)

    def fit(self, rect: Optional[QRectF] = None):
        r = rect or self.scene().itemsBoundingRect()
        if r.isEmpty():
            return
        self.fitInView(r.adjusted(-40, -40, 40, 40), Qt.KeepAspectRatio)
        self._zoom = self.transform().m11()
        if self._zoom > 1.6:  # a two-node map should not fill the screen with giant icons
            self.zoom_by(1.6 / self._zoom)
        self.zoomChanged.emit(self._zoom)

    def mousePressEvent(self, event):
        # Shift+drag on the background selects a group; plain drag pans
        if event.modifiers() & Qt.ShiftModifier and self.itemAt(event.position().toPoint()) is None:
            self.setDragMode(QGraphicsView.RubberBandDrag)
        elif event.button() == Qt.MiddleButton:
            self.setDragMode(QGraphicsView.ScrollHandDrag)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self.setDragMode(QGraphicsView.ScrollHandDrag)

    def drawBackground(self, painter: QPainter, rect: QRectF):
        pal = self.palette()
        painter.fillRect(rect, pal.color(QPalette.Base))
        if self._zoom < 0.35:
            return
        dark = _is_dark(pal)
        c = QColor("#1f2937") if dark else QColor("#eef2f7")
        painter.setPen(QPen(c, 1.0 / max(self._zoom, 0.01)))
        step = 40
        left = int(math.floor(rect.left() / step) * step)
        top = int(math.floor(rect.top() / step) * step)
        x = left
        pts = []
        while x < rect.right():
            y = top
            while y < rect.bottom():
                pts.append(QPointF(x, y))
                y += step
            x += step
            if len(pts) > 40000:
                break
        painter.drawPoints(pts)


class Legend(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("legend")
        self.setFrameShape(QFrame.StyledPanel)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(8, 6, 8, 6)
        self.lay.setSpacing(2)

    def set_content(self, roles: list[tuple[str, str]], edges: list[str]):
        while self.lay.count():
            w = self.lay.takeAt(0).widget()
            if w:
                w.deleteLater()
        for role, kind in roles:
            row = QWidget()
            h = QHBoxLayout(row)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(6)
            ic = QLabel()
            ic.setPixmap(role_pixmap(role, 16, kind))
            h.addWidget(ic)
            h.addWidget(QLabel(ROLE_LABELS.get(role, role)))
            h.addStretch(1)
            self.lay.addWidget(row)
        for k in edges:
            self.lay.addWidget(QLabel({"l2": "━━  cabling (LLDP/CDP)", "l3": "╍╍  routing next-hop", "member": "┈┈  subnet membership", "fdb": "──  host on switch port"}[k]))
        self.adjustSize()


class TopologyPage(QWidget):
    nodeSelected = Signal(str)
    nodeActivated = Signal(str)
    contextRequested = Signal(str, object)  # node id, global pos
    layoutChanged = Signal()  # positions changed by the user (project is dirty)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.inv = None
        self.g = None
        self.preset = "physical"
        self.layout_kind = "layered"
        self.flags = dict(PRESETS["physical"])
        self.show_ports = True
        self.focus: Optional[tuple[str, int]] = None  # (node, hops)
        self.hidden_nodes: set[str] = set()
        self.nodes: dict[str, NodeItem] = {}
        self.edges: list[EdgeItem] = []
        self._building = False
        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(400)
        self._save_timer.timeout.connect(self._store_positions)

        self.scene = QGraphicsScene(self)
        self.scene.setItemIndexMethod(QGraphicsScene.BspTreeIndex)
        self.scene.selectionChanged.connect(self._on_selection)
        self.view = MapView(self.scene, self)
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._on_context)

        tb = QToolBar()
        tb.setIconSize(tb.iconSize() * 0.8)
        self.preset_box = QComboBox()
        for k, p in PRESETS.items():
            self.preset_box.addItem(p["title"], k)
        self.preset_box.currentIndexChanged.connect(lambda _: self.set_preset(self.preset_box.currentData()))
        tb.addWidget(QLabel(" View "))
        tb.addWidget(self.preset_box)
        self.layout_box = QComboBox()
        for k, t in LAYOUTS.items():
            self.layout_box.addItem(t, k)
        self.layout_box.currentIndexChanged.connect(lambda _: self._set_layout_kind(self.layout_box.currentData()))
        tb.addWidget(QLabel("  Layout "))
        tb.addWidget(self.layout_box)
        self.relayout_act = tb.addAction("Re-arrange", self.relayout)
        self.relayout_act.setToolTip("Discard hand-placed positions for this view and lay it out again")
        tb.addSeparator()
        self.toggles: dict[str, QAction] = {}
        for key, text, tip in (
            ("l2", "Cabling", "Links learned from LLDP/CDP"),
            ("l3", "Routing", "Routing next-hop adjacencies"),
            ("subnets", "Subnets", "Subnets and which devices have an address in them"),
            ("hosts", "Hosts", "Endpoints: on their switch port (physical) or in their subnet (logical)"),
            ("unpolled", "Unpolled", "Neighbours seen over LLDP/CDP that were not polled"),
        ):
            a = QAction(text, self)
            a.setCheckable(True)
            a.setToolTip(tip)
            a.toggled.connect(lambda on, key=key: self._toggle(key, on))
            tb.addAction(a)
            self.toggles[key] = a
        self.ports_act = QAction("Port names", self)
        self.ports_act.setCheckable(True)
        self.ports_act.setChecked(True)
        self.ports_act.setToolTip("Show interface names at both ends of cabling links (when zoomed in)")
        self.ports_act.toggled.connect(self._toggle_ports)
        tb.addAction(self.ports_act)
        tb.addSeparator()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Find on map: name, IP, MAC, serial…")
        self.search.setClearButtonEnabled(True)
        self.search.setMaximumWidth(260)
        self.search.returnPressed.connect(self.find_next)
        self.search.textChanged.connect(self._on_search)
        tb.addWidget(self.search)
        tb.addSeparator()
        tb.addAction("Fit", lambda: self.view.fit()).setShortcut(QKeySequence("Ctrl+0"))
        tb.addAction("+", lambda: self.view.zoom_by(1.25)).setShortcut(QKeySequence.ZoomIn)
        tb.addAction("−", lambda: self.view.zoom_by(0.8)).setShortcut(QKeySequence.ZoomOut)
        self.export_btn = QToolButton()
        self.export_btn.setText("Export")
        self.export_btn.setPopupMode(QToolButton.InstantPopup)
        self.export_menu = QMenu(self.export_btn)
        self.export_btn.setMenu(self.export_menu)
        tb.addWidget(self.export_btn)

        self.banner = QWidget()
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(10, 4, 10, 4)
        self.banner_text = QLabel()
        self.banner_btn = QPushButton("Show everything")
        self.banner_btn.clicked.connect(self.clear_focus)
        bl.addWidget(self.banner_text, 1)
        bl.addWidget(self.banner_btn)
        self.banner.setObjectName("banner")
        self.banner.hide()

        self.info = QLabel()
        self.info.setObjectName("muted")

        self.legend = Legend(self.view)
        self.legend.move(10, 10)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(tb)
        lay.addWidget(self.banner)
        lay.addWidget(self.view, 1)
        foot = QHBoxLayout()
        foot.setContentsMargins(8, 2, 8, 2)
        foot.addWidget(self.info)
        foot.addStretch(1)
        hint = QLabel("Drag to pan · wheel to zoom · Shift+drag to select · drag a node to move it · right-click for actions")
        hint.setObjectName("muted")
        foot.addWidget(hint)
        lay.addLayout(foot)
        self._sync_toggles()

    # ------------------------------------------------------------ data in
    def set_data(self, inv, g, keep_view: bool = True) -> None:
        self.inv = inv
        self.g = g
        self.rebuild(keep_view=keep_view)

    def set_preset(self, key: str) -> None:
        if key not in PRESETS:
            return
        self.preset = key
        self.flags = {k: v for k, v in PRESETS[key].items() if k != "title"}
        i = self.preset_box.findData(key)
        if self.preset_box.currentIndex() != i:
            self.preset_box.blockSignals(True)
            self.preset_box.setCurrentIndex(i)
            self.preset_box.blockSignals(False)
        self._sync_toggles()
        self.rebuild(keep_view=False)

    def _sync_toggles(self):
        for k, a in self.toggles.items():
            a.blockSignals(True)
            a.setChecked(bool(self.flags.get(k)))
            a.blockSignals(False)

    def _toggle(self, key, on):
        self.flags[key] = on
        self.rebuild(keep_view=True)

    def _toggle_ports(self, on):
        self.show_ports = on
        for e in self.edges:
            e.update()

    def _set_layout_kind(self, kind):
        self.layout_kind = kind
        self.relayout()

    # ------------------------------------------------------------ which nodes/edges
    def visible_graph(self) -> tuple[dict, list]:
        g = self.g
        f = self.flags
        nodes: dict[str, dict] = {}
        edges: list[tuple[str, str, dict]] = []
        if g is None:
            return nodes, edges
        for n, a in g.nodes(data=True):
            kind = a.get("kind")
            if n in self.hidden_nodes:
                continue
            if kind == "device":
                if a.get("role") == "unpolled" and not f.get("unpolled"):
                    continue
                nodes[n] = a
            elif kind == "subnet" and f.get("subnets"):
                nodes[n] = a
            elif kind == "host" and f.get("hosts"):
                nodes[n] = a
        for u, v, a in g.edges(data=True):
            k = a.get("kind")
            if u not in nodes or v not in nodes:
                continue
            if k in ("lldp", "cdp") and not f.get("l2"):
                # hosts announced over LLDP (APs, phones) still hang off their switch
                if not f.get("hosts") or (nodes[u].get("kind") == "device" and nodes[v].get("kind") == "device"):
                    continue
            if k == "l3" and not f.get("l3"):
                continue
            if k == "member":
                hostside = nodes[u].get("kind") == "host" or nodes[v].get("kind") == "host"
                if not f.get("subnets"):
                    continue
                if hostside and f.get("l2") and self.preset == "physical":
                    continue
            if k == "fdb" and not f.get("hosts"):
                continue
            edges.append((u, v, a))
        if f.get("hosts"):
            # a host with nothing to hang off (no switch port, no subnet shown) is noise on a diagram
            linked = {x for u, v, _ in edges for x in (u, v)}
            for n in [n for n, a in nodes.items() if a.get("kind") == "host" and n not in linked]:
                del nodes[n]
        if self.focus:
            center, hops = self.focus
            if center in nodes:
                keep = {center}
                frontier = {center}
                adj: dict[str, set] = {}
                for u, v, _ in edges:
                    adj.setdefault(u, set()).add(v)
                    adj.setdefault(v, set()).add(u)
                for _ in range(hops):
                    frontier = {m for n in frontier for m in adj.get(n, ())} - keep
                    keep |= frontier
                nodes = {n: a for n, a in nodes.items() if n in keep}
                edges = [(u, v, a) for u, v, a in edges if u in keep and v in keep]
        return nodes, edges

    def _layout_key(self) -> str:
        return self.preset

    # ------------------------------------------------------------ build scene
    def rebuild(self, keep_view: bool = True) -> None:
        if self._building:
            return
        self._building = True
        try:
            center = self.view.mapToScene(self.view.viewport().rect().center())
            zoom = self.view._zoom
            selected = {i.node_id for i in self.scene.selectedItems() if isinstance(i, NodeItem)}
            self.scene.clear()
            self.nodes = {}
            self.edges = []
            nodes, edges = self.visible_graph()
            pos = self._positions(nodes, edges)
            for n, a in nodes.items():
                it = NodeItem(n, a, self)
                x, y = pos.get(n, (0.0, 0.0))
                it.setPos(x, y)
                self.scene.addItem(it)
                self.nodes[n] = it
            pair_count: dict = {}
            for u, v, _ in edges:
                k = tuple(sorted((u, v)))
                pair_count[k] = pair_count.get(k, 0) + 1
            pair_seen: dict = {}
            for u, v, a in edges:
                k = tuple(sorted((u, v)))
                slot = pair_seen.get(k, 0)
                pair_seen[k] = slot + 1
                e = EdgeItem(self.nodes[u], self.nodes[v], a, self, slot, pair_count[k])
                self.nodes[u].edges.append(e)
                self.nodes[v].edges.append(e)
                self.scene.addItem(e)
                self.edges.append(e)
            for n in selected:
                if n in self.nodes:
                    self.nodes[n].setSelected(True)
            br = self.scene.itemsBoundingRect()
            self.scene.setSceneRect(br.adjusted(-2000, -2000, 2000, 2000))
            self._update_legend(nodes, edges)
            self._update_info(nodes, edges)
            if keep_view and self.nodes and zoom:
                self.view.centerOn(center)
            else:
                QTimer.singleShot(0, self.view.fit)
            if self.search.text():
                self._on_search(self.search.text())
        finally:
            self._building = False

    def _positions(self, nodes: dict, edges: list) -> dict:
        pairs = [(u, v) for u, v, _ in edges]
        saved = (self.inv.layout.get(self._layout_key()) if self.inv is not None else None) or {}
        if self.layout_kind == "radial":
            root = self._radial_root(nodes)
            if root:
                return L.radial(nodes, pairs, root)
        auto = L.layered(nodes, pairs)
        if self.layout_kind == "organic":
            auto = L.organic(nodes, pairs, init=auto)
        if not saved or self.focus:
            return auto
        # hand-placed positions win; anything new is placed relative to a neighbour that has one
        pos = {n: tuple(saved[n]) for n in nodes if n in saved}
        if not pos:
            return auto
        dxs = [pos[n][0] - auto[n][0] for n in pos if n in auto]
        dys = [pos[n][1] - auto[n][1] for n in pos if n in auto]
        shift = (sum(dxs) / len(dxs), sum(dys) / len(dys)) if dxs else (0.0, 0.0)
        adj: dict[str, list] = {}
        for u, v in pairs:
            adj.setdefault(u, []).append(v)
            adj.setdefault(v, []).append(u)
        for n in nodes:
            if n in pos:
                continue
            anchor = next((m for m in adj.get(n, []) if m in pos and m in auto), None)
            if anchor is not None and n in auto:
                pos[n] = (pos[anchor][0] + auto[n][0] - auto[anchor][0], pos[anchor][1] + auto[n][1] - auto[anchor][1])
            else:
                x, y = auto.get(n, (0.0, 0.0))
                pos[n] = (x + shift[0], y + shift[1])
        return pos

    def _radial_root(self, nodes) -> Optional[str]:
        sel = [i.node_id for i in self.scene.selectedItems() if isinstance(i, NodeItem) and i.node_id in nodes]
        if sel:
            return sel[0]
        devs = [n for n, a in nodes.items() if a.get("kind") == "device"]
        if not devs:
            return None
        deg = {n: 0 for n in devs}
        if self.g is not None:
            for n in devs:
                deg[n] = self.g.degree(n)
        return max(devs, key=lambda n: deg[n])

    def relayout(self):
        """Forget hand-placed positions for this view and arrange it afresh."""
        if self.inv is not None and self._layout_key() in self.inv.layout:
            del self.inv.layout[self._layout_key()]
            self.layoutChanged.emit()
        self.rebuild(keep_view=False)

    def node_moved(self, item: NodeItem):
        if not self._building:
            self._save_timer.start()

    def _store_positions(self):
        if self.inv is None or self.focus:
            return
        store = self.inv.layout.setdefault(self._layout_key(), {})
        for n, it in self.nodes.items():
            store[n] = [round(it.pos().x(), 1), round(it.pos().y(), 1)]
        self.layoutChanged.emit()

    def positions(self) -> dict:
        return {n: (it.pos().x(), it.pos().y()) for n, it in self.nodes.items()}

    # ------------------------------------------------------------ focus / selection
    def focus_on(self, node_id: str, hops: int = 1):
        self.focus = (node_id, hops)
        name = self.g.nodes[node_id].get("label", node_id) if self.g is not None and node_id in self.g else node_id
        self.banner_text.setText(f"Showing only what is within {hops} hop{'s' if hops > 1 else ''} of <b>{name}</b>.")
        self.banner.show()
        self.rebuild(keep_view=False)
        self.select(node_id, center=False)

    def clear_focus(self):
        self.focus = None
        self.hidden_nodes.clear()
        self.banner.hide()
        self.rebuild(keep_view=False)

    def hide_node(self, node_id: str):
        self.hidden_nodes.add(node_id)
        self.banner_text.setText(f"{len(self.hidden_nodes)} item(s) hidden from the map.")
        self.banner.show()
        self.rebuild(keep_view=True)

    def select(self, node_id: str, center: bool = True) -> bool:
        it = self.nodes.get(node_id)
        if it is None:
            return False
        self.scene.blockSignals(True)
        self.scene.clearSelection()
        it.setSelected(True)
        self.scene.blockSignals(False)
        if center:
            self.view.centerOn(it)
            if self.view._zoom < 0.6:
                self.view.zoom_by(0.9 / self.view._zoom)
                self.view.centerOn(it)
        for e in self.edges:
            e.update()
        return True

    def ensure_visible(self, node_id: str) -> bool:
        """Show a node even if the current filters hide it (e.g. a host picked in a table)."""
        if node_id in self.nodes:
            return self.select(node_id)
        if self.g is None or node_id not in self.g:
            return False
        kind = self.g.nodes[node_id].get("kind")
        if kind == "host":
            self.toggles["hosts"].setChecked(True)
        elif kind == "subnet":
            self.toggles["subnets"].setChecked(True)
        elif self.g.nodes[node_id].get("role") == "unpolled":
            self.toggles["unpolled"].setChecked(True)
        if node_id in self.hidden_nodes:
            self.hidden_nodes.discard(node_id)
            self.rebuild()
        if self.focus and node_id not in self.nodes:
            self.clear_focus()
        return self.select(node_id)

    def _on_selection(self):
        sel = [i for i in self.scene.selectedItems() if isinstance(i, NodeItem)]
        for e in self.edges:
            e.update()
        if len(sel) == 1:
            self.nodeSelected.emit(sel[0].node_id)

    def _on_context(self, pos):
        it = self.view.itemAt(pos)
        while it is not None and not isinstance(it, NodeItem):
            it = it.parentItem()
        if isinstance(it, NodeItem):
            if not it.isSelected():
                self.select(it.node_id, center=False)
            self.contextRequested.emit(it.node_id, self.view.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------ search
    def _match(self, it: NodeItem, q: str) -> bool:
        a = it.attrs
        hay = " ".join(str(a.get(k, "")) for k in ("label", "ip", "mac", "vendor", "model", "serial", "hostname", "sysdescr", "site", "tags", "chassis_id"))
        return q in (hay + " " + it.node_id).lower()

    def _on_search(self, text: str):
        q = text.strip().lower()
        hits = []
        for it in self.nodes.values():
            m = bool(q) and self._match(it, q)
            if m != it.found or it.dimmed != (bool(q) and not m):
                it.found = m
                it.dimmed = bool(q) and not m
                it.update()
            if m:
                hits.append(it)
        for e in self.edges:
            e.update()
        self._hits = hits
        self._hit_i = -1
        if q:
            self.info.setText(f"{len(hits)} match{'es' if len(hits) != 1 else ''} for “{text.strip()}” — Enter to step through")
        else:
            self._update_info(*self.visible_graph())

    def find_next(self):
        hits = getattr(self, "_hits", [])
        if not hits:
            return
        self._hit_i = (self._hit_i + 1) % len(hits)
        it = hits[self._hit_i]
        self.select(it.node_id)

    # ------------------------------------------------------------ chrome
    def _update_legend(self, nodes, edges):
        seen = {}
        for a in nodes.values():
            kind = a.get("kind", "device")
            role = "subnet" if kind == "subnet" else (a.get("role") or "unknown")
            seen.setdefault(role, kind)
        order = list(ROLE_LABELS)
        roles = sorted(seen.items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)
        ek = []
        kinds = {a.get("kind") for _, _, a in edges}
        if kinds & {"lldp", "cdp"}:
            ek.append("l2")
        if "l3" in kinds:
            ek.append("l3")
        if "member" in kinds:
            ek.append("member")
        if "fdb" in kinds:
            ek.append("fdb")
        self.legend.set_content(roles, ek)
        self.legend.setVisible(bool(nodes))

    def _update_info(self, nodes, edges):
        kinds: dict = {}
        for a in nodes.values():
            kinds[a.get("kind")] = kinds.get(a.get("kind"), 0) + 1
        parts = [f"{kinds.get('device', 0)} devices"]
        if kinds.get("subnet"):
            parts.append(f"{kinds['subnet']} subnets")
        if kinds.get("host"):
            parts.append(f"{kinds['host']} hosts")
        parts.append(f"{len(edges)} links")
        saved = self.inv is not None and self._layout_key() in self.inv.layout and not self.focus
        self.info.setText(" · ".join(parts) + ("   (hand-arranged)" if saved else ""))

    # ------------------------------------------------------------ output
    def render_image(self, scale: float = 2.0, background: Optional[QColor] = None) -> QImage:
        rect = self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)
        scale = min(scale, 16000 / max(rect.width(), 1), 16000 / max(rect.height(), 1))
        img = QImage(max(1, int(rect.width() * scale)), max(1, int(rect.height() * scale)), QImage.Format_ARGB32_Premultiplied)
        img.fill(background or self.palette().color(QPalette.Base))
        p = QPainter(img)
        p.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing)
        self._render_to(p, QRectF(0, 0, img.width(), img.height()), rect)
        p.end()
        return img

    def _render_to(self, painter: QPainter, target: QRectF, source: QRectF):
        sel = self.scene.selectedItems()
        for it in sel:
            it.setSelected(False)
        self.scene.render(painter, target, source, Qt.KeepAspectRatio)
        for it in sel:
            it.setSelected(True)

    def export_svg(self, path: str, title: str = "Network map"):
        from PySide6.QtSvg import QSvgGenerator

        rect = self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)
        gen = QSvgGenerator()
        gen.setFileName(path)
        gen.setSize(rect.size().toSize())
        gen.setViewBox(QRectF(0, 0, rect.width(), rect.height()))
        gen.setTitle(title)
        p = QPainter(gen)
        p.fillRect(QRectF(0, 0, rect.width(), rect.height()), self.palette().color(QPalette.Base))
        self._render_to(p, QRectF(0, 0, rect.width(), rect.height()), rect)
        p.end()

    def export_pdf(self, path: str, title: str = "Network map"):
        from PySide6.QtCore import QMarginsF
        from PySide6.QtGui import QPageLayout, QPageSize, QPdfWriter

        rect = self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)
        w = QPdfWriter(path)
        w.setTitle(title)
        w.setCreator("netmap")
        orient = QPageLayout.Landscape if rect.width() >= rect.height() else QPageLayout.Portrait
        w.setPageLayout(QPageLayout(QPageSize(QPageSize.A3), orient, QMarginsF(10, 10, 10, 10)))
        w.setResolution(300)
        p = QPainter(w)
        page = QRectF(w.pageLayout().paintRectPixels(w.resolution()))
        page.moveTo(0, 0)
        head = QFont()
        head.setPointSizeF(12)
        p.setFont(head)
        p.drawText(page.adjusted(0, 0, 0, -page.height() + 120), Qt.AlignLeft | Qt.AlignTop, title)
        self._render_to(p, page.adjusted(0, 130, 0, 0), rect)
        p.end()

    def print_map(self, printer):
        p = QPainter(printer)
        page = QRectF(printer.pageLayout().paintRectPixels(printer.resolution()))
        page.moveTo(0, 0)
        self._render_to(p, page, self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30))
        p.end()
