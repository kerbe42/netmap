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

from .. import diagram
from ..diagram import PRESETS
from ..graph import edge_ports
from ..views import is_mac, short_port
from .icons import ROLE_LABELS, paint_badge, role_color, role_pixmap

LAYOUTS = {"layered": "Layered (core on top)", "organic": "Organic", "radial": "Radial around selection"}
EDGE_TITLES = {"lldp": "LLDP", "cdp": "CDP", "l3": "Routing", "member": "Subnet", "fdb": "MAC table"}

NODE_SIZE = {"device": 40.0, "host": 26.0, "subnet": 30.0}
MAX_RENDER_SIDE = 8192  # a PNG's long side; beyond this a 32-bit image is hundreds of MB
LABEL_MAX_SCALE = 1.7


def map_label(name: str) -> str:
    """ap-fl1-01.mgmt.example.com -> ap-fl1-01 on the diagram; addresses stay whole."""
    import re

    if "." in name and not re.match(r"^[\d.]+(/\d+)?$", name):
        return name.split(".", 1)[0]
    return name


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
        self._label = map_label(str(attrs.get("label") or node_id))
        if self.kind == "device":
            ip = attrs.get("ip") or ""
            self._sub = ip if ip and ip != self._label else ""
        elif self.kind == "subnet":
            v = attrs.get("vlan")
            self._sub = (f"VLAN {v}" + (f" {attrs['vlan_name']}" if attrs.get("vlan_name") else "")) if v else ""
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
        tip = [f"<b>{attrs.get('label') or node_id}</b>", ROLE_LABELS.get(self.role, self.role)]
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
        w = max(s + (s * 0.6 if self.kind == "subnet" else 0), self._text_w * LABEL_MAX_SCALE) + 8
        return QRectF(-w / 2, -s / 2 - 8, w, s + 12 + self._text_h * LABEL_MAX_SCALE + 4)

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
        if self.role == "unpolled":
            painter.setPen(Qt.NoPen)
            painter.setBrush(pal.color(QPalette.Base))
            painter.drawRoundedRect(r, r.width() * 0.22, r.width() * 0.22)
        paint_badge(painter, r, self.role, self.kind, dashed=self.role == "unpolled")
        if lod < 0.45 and self.kind == "host":
            return
        if lod < 0.3:
            return
        text = QColor("#e5e7eb") if dark else QColor("#111827")
        muted = QColor("#94a3b8") if dark else QColor("#4b5563")
        # zoomed out to fit a whole site, 8pt captions become unreadable: let them grow in
        # the diagram as the view shrinks (up to a limit), so they keep a legible size on screen
        k = min(max(1.0, 0.85 / max(lod, 0.01)), LABEL_MAX_SCALE)
        painter.save()
        painter.translate(0, self.size / 2 + 3)
        painter.scale(k, k)
        y = 0.0
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
        painter.restore()

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
        pa, pb = edge_ports(a.node_id, b.node_id, attrs)
        # an endpoint's LLDP port id is usually just its MAC: noise on a diagram
        self.port_a = "" if is_mac(pa) else short_port(pa)
        self.port_b = "" if is_mac(pb) else short_port(pb)
        if self.kind in ("lldp", "cdp"):
            tip = f"{a._label} {pa}  ↔  {b._label} {pb}  ({EDGE_TITLES[self.kind]})"
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
            c = QColor("#7c8aa0") if dark else QColor("#64748b")
            pen = QPen(c, 1.4, Qt.DashDotLine)
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
            self._port_label(painter, self.a, self.b, self.port_a, False)
            self._port_label(painter, self.b, self.a, self.port_b, True)

    def _port_label(self, painter: QPainter, near: NodeItem, far: NodeItem, text: str, from_end: bool):
        """Interface name just outside the node it belongs to - below its caption when the
        link leaves downwards, so the two never overlap."""
        if not text:
            return
        length = self.path().length()
        if length < 1:
            return
        dx = far.pos().x() - near.pos().x()
        dy = far.pos().y() - near.pos().y()
        dist = near.size / 2 + 14
        if dy > 0 and abs(dx) < dy * 1.6:
            dist = near.size / 2 + near._text_h + 16
        t = min(dist / length, 0.42)
        p = self.path().pointAtPercent(1 - t if from_end else t)
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
        self.lay.setSizeConstraint(QVBoxLayout.SetFixedSize)  # follow the content as it changes

    def set_content(self, roles: list[tuple[str, str]], edges: list[str]):
        while self.lay.count():
            w = self.lay.takeAt(0).widget()
            if w:
                w.hide()
                w.setParent(None)
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
            row.show()
        for k in edges:
            lab = QLabel({"l2": "━━  cabling (LLDP/CDP)", "l3": "╍╍  routing next-hop", "member": "┈┈  subnet membership", "fdb": "──  host on switch port"}[k])
            self.lay.addWidget(lab)
            lab.show()
        self.adjustSize()


class TopologyPage(QWidget):
    nodeSelected = Signal(str)
    nodeActivated = Signal(str)
    contextRequested = Signal(str, object)  # node id, global pos
    layoutChanged = Signal()  # positions changed by the user (project is dirty)
    layoutDiscarded = Signal(str, dict)  # Re-arrange dropped hand-placed positions: (preset, the old positions) for undo

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
        self._pending_fit = 0  # token of a deferred whole-map fit; any explicit fit/select cancels it
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
        self.show_btn = QToolButton()
        self.show_btn.setText("Show")
        self.show_btn.setPopupMode(QToolButton.InstantPopup)
        self.show_btn.setToolTip("Choose what the map shows")
        show = QMenu(self.show_btn)
        self.show_btn.setMenu(show)
        tb.addSeparator()
        tb.addWidget(self.show_btn)
        self.toggles: dict[str, QAction] = {}
        for key, text, tip in (
            ("l2", "Cabling (LLDP/CDP links)", "Links learned from LLDP/CDP"),
            ("l3", "Routing next-hops", "Routing next-hop adjacencies"),
            ("subnets", "Subnets", "Subnets and which devices have an address in them"),
            ("hosts", "Hosts", "Endpoints: on their switch port (physical) or in their subnet (logical)"),
            ("unpolled", "Neighbours not polled", "Neighbours seen over LLDP/CDP that were not polled"),
            ("l2devices", "Layer-2 switches", "Switches that do not route (hidden on the logical view)"),
        ):
            a = QAction(text, self)
            a.setCheckable(True)
            a.setToolTip(tip)
            a.toggled.connect(lambda on, key=key: self._toggle(key, on))
            show.addAction(a)
            self.toggles[key] = a
        show.addSeparator()
        self.ports_act = QAction("Port names on links", self)
        self.ports_act.setCheckable(True)
        self.ports_act.setChecked(True)
        self.ports_act.toggled.connect(self._toggle_ports)
        show.addAction(self.ports_act)
        self.legend_act = QAction("Legend", self)
        self.legend_act.setCheckable(True)
        self.legend_act.setChecked(True)
        self.legend_act.toggled.connect(self._toggle_legend)
        show.addAction(self.legend_act)
        tb.addSeparator()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Find on map: name, IP, MAC, serial…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(150)  # never collapses to "Fi…" when the toolbar is squeezed
        self.search.setMaximumWidth(260)
        self.search.returnPressed.connect(self.find_next)
        self.search.textChanged.connect(self._on_search)
        tb.addWidget(self.search)
        tb.addSeparator()
        tb.addAction("Fit", lambda: self.fit()).setShortcut(QKeySequence("Ctrl+0"))
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

        # a child of the page, not of the view's viewport: the viewport scrolls its children
        self.legend = Legend(self)
        self.show_legend = True

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(tb)
        lay.addWidget(self.banner)
        lay.addWidget(self.view, 1)
        foot = QHBoxLayout()
        foot.setContentsMargins(8, 2, 8, 2)
        foot.addWidget(self.info, 1)
        lay.addLayout(foot)
        self.view.setToolTip("Drag the background to pan · wheel to zoom · Shift+drag to select several · drag a node to move it · right-click for actions")
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
            a.setChecked(bool(self.flags.get(k, k == "l2devices")))
            a.blockSignals(False)

    def _toggle(self, key, on):
        self.flags[key] = on
        self.rebuild(keep_view=True)

    def _toggle_legend(self, on):
        self.show_legend = on
        self.legend.setVisible(on and bool(self.nodes))
        self._place_legend()

    def _place_legend(self):
        g = self.view.geometry()
        self.legend.move(g.left() + 10, g.top() + 10)
        self.legend.raise_()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._place_legend()

    def showEvent(self, e):
        super().showEvent(e)
        QTimer.singleShot(0, self._place_legend)

    def _toggle_ports(self, on):
        self.show_ports = on
        for e in self.edges:
            e.update()

    def _set_layout_kind(self, kind):
        self.layout_kind = kind
        self.relayout()

    # ------------------------------------------------------------ which nodes/edges
    def visible_graph(self) -> tuple[dict, list]:
        nodes, edges = diagram.select(self.g, self.flags, self.preset)
        if self.hidden_nodes:
            nodes = {n: a for n, a in nodes.items() if n not in self.hidden_nodes}
            edges = [(u, v, a) for u, v, a in edges if u in nodes and v in nodes]
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
            # clear() deselects item by item and each step would emit selectionChanged: with
            # several nodes selected the Details panel would flip to whichever went last
            self.scene.blockSignals(True)
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
            self.scene.blockSignals(False)
            for e in self.edges:
                e.update()
            br = self.scene.itemsBoundingRect()
            self.scene.setSceneRect(br.adjusted(-2000, -2000, 2000, 2000))
            self._update_legend(nodes, edges)
            self._update_info(nodes, edges)
            if keep_view and self.nodes and zoom:
                self.view.centerOn(center)
            else:
                self._pending_fit += 1
                QTimer.singleShot(0, lambda tok=self._pending_fit: self._deferred_fit(tok))
            if self.search.text():
                self._on_search(self.search.text())
        finally:
            self.scene.blockSignals(False)
            self._building = False

    def _deferred_fit(self, token: int):
        """The whole-map fit scheduled by rebuild(), unless something fitted or centred the
        view since (a traced path, a selected node): the later, more specific view wins."""
        if token == self._pending_fit:
            self._pending_fit = 0
            self.view.fit()

    def fit(self, rect: Optional[QRectF] = None):
        """Fit the view now and cancel any deferred whole-map fit."""
        self._pending_fit = 0
        self.view.fit(rect)

    def _positions(self, nodes: dict, edges: list) -> dict:
        saved = None if self.focus or self.inv is None else self.inv.layout.get(self._layout_key())
        root = self._radial_root(nodes) if self.layout_kind == "radial" else None
        return diagram.positions(nodes, edges, saved, self.layout_kind, root)

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
            self.flush_positions()
            old = dict(self.inv.layout.get(self._layout_key(), {}))
            del self.inv.layout[self._layout_key()]
            self.layoutChanged.emit()
            self.layoutDiscarded.emit(self._layout_key(), old)
        self.rebuild(keep_view=False)

    def restore_layout(self, key: str, positions: dict) -> None:
        """Put back hand-placed positions (undo of Re-arrange) and redraw from them."""
        if self.inv is None:
            return
        self._save_timer.stop()
        self.inv.layout[key] = dict(positions)
        if key == self._layout_key():
            self.rebuild(keep_view=False)

    def node_moved(self, item: NodeItem):
        if not self._building:
            self._save_timer.start()

    def flush_positions(self) -> bool:
        """Write dragged positions into the project now instead of in 400 ms: called before
        a save, so the last drag before Ctrl+S is in the file. True if there was one pending."""
        if self._save_timer.isActive():
            self._save_timer.stop()
            self._store_positions()
            return True
        return False

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

    def show_path(self, node_ids: list, label: str = "") -> bool:
        """Dim everything except the given ordered path and highlight it. Makes any hidden
        hops visible first."""
        ids = [n for n in node_ids if n]
        for n in ids:
            if n not in self.nodes and self.g is not None and n in self.g:
                self.ensure_visible(n)
        present = [n for n in ids if n in self.nodes]
        if len(present) < 2:
            return False
        pathset = set(present)
        self.scene.blockSignals(True)
        self.scene.clearSelection()
        for nid, it in self.nodes.items():
            it.dimmed = nid not in pathset
            it.found = nid in pathset
            if nid in pathset:
                it.setSelected(True)
            it.update()
        self.scene.blockSignals(False)
        for e in self.edges:
            e.update()
        self.banner_text.setText(label or f"Path across {len(present)} devices highlighted.")
        self.banner.show()
        rect = None
        for n in present:
            r = self.nodes[n].sceneBoundingRect()
            rect = r if rect is None else rect.united(r)
        if rect is not None:
            self.fit(rect)
        return True

    def clear_focus(self):
        self.focus = None
        self.hidden_nodes.clear()
        self.banner.hide()
        for it in self.nodes.values():
            it.dimmed = False
            it.found = False
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
            self._pending_fit = 0
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
        if self._building:
            return
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
        self.legend.setVisible(bool(nodes) and self.show_legend)
        self._place_legend()

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
    def render_size(self, scale: float = 2.0) -> tuple[float, int, int]:
        """(effective scale, width, height) for a PNG: the long side is capped so the image
        stays a few hundred MB at most rather than a gigabyte."""
        rect = self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)
        long_side = max(rect.width(), rect.height(), 1.0)
        scale = max(0.01, min(scale, MAX_RENDER_SIDE / long_side))
        return scale, max(1, int(rect.width() * scale)), max(1, int(rect.height() * scale))

    def render_image(self, scale: float = 2.0, background: Optional[QColor] = None) -> QImage:
        """The map as an image; a null QImage if the allocation failed (check isNull())."""
        rect = self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)
        scale, w, h = self.render_size(scale)
        img = QImage(w, h, QImage.Format_ARGB32_Premultiplied)
        if img.isNull():
            return img
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
