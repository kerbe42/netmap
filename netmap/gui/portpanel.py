"""A switch front-panel view: each port drawn as it sits on the faceplate, coloured by state,
with PoE, trunk/access and neighbour shown. Uses the interface data already collected."""
from __future__ import annotations

import re

from PySide6.QtCore import QRect, QSize, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFontMetrics, QPainter, QPalette, QPen
from PySide6.QtWidgets import QLabel, QSizePolicy, QToolTip, QVBoxLayout, QWidget

from ..views import short_port

UP = QColor("#16a34a")
DOWN = QColor("#94a3b8")
DISABLED = QColor("#4b5563")
ERR = QColor("#dc2626")
UPLINK = QColor("#2563eb")


def _port_sort_key(name: str):
    nums = [int(x) for x in re.findall(r"\d+", name or "")]
    return (nums, name or "")


# logical interfaces that have no place on a faceplate. Anchored so that "Port 1" / "Port24"
# (many small switches name their physical ports so) is not mistaken for a port-channel.
_LOGICAL_RE = re.compile(r"^(vlan|vl|po|port-channel|lo|loopback|tunnel|tu|null|nu|mgmt)(\d|[-_ ./:]|$)")


def is_logical_interface(name: str) -> bool:
    return bool(_LOGICAL_RE.match((name or "").strip().lower()))


def port_label(port: dict) -> str:
    """What is written in a port's cell: its number, or for a port with a neighbour (an
    uplink, another switch, an AP) the whole short name so Te1/1/1 is not just another "1"."""
    name = port.get("name", "")
    if port.get("neighbor"):
        return short_port(name) or name
    num = re.findall(r"\d+", name)
    return num[-1] if num else "?"


class _Faceplate(QWidget):
    portClicked = Signal(str)  # neighbour node id, if any

    def __init__(self, parent=None):
        super().__init__(parent)
        self.ports: list[dict] = []
        self.cell = 26
        self.cell_w = 26
        self.gap = 3
        self.cols = 24
        self.rows = 1
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_ports(self, ports: list[dict]):
        self.ports = ports
        n = len(ports)
        # two rows like a real switch when there are many access ports
        self.rows = 2 if n > 12 else 1
        self.cols = max(1, (n + 1) // 2) if self.rows == 2 else max(n, 1)
        # cells widen to fit the longest label (a full "Te1/1/1" on an uplink)
        f = self.font()
        f.setPointSizeF(6.5)
        fm = QFontMetrics(f)
        widest = max((fm.horizontalAdvance(port_label(p)) for p in ports), default=0)
        self.cell_w = max(self.cell, widest + 6)
        self.updateGeometry()
        self.update()

    def _grid_pos(self, i):
        # fill top row even ports / bottom odd, as on a switch: port1 top-left, port2 below it
        if self.rows == 1:
            return i, 0
        return i // 2, i % 2

    def sizeHint(self):
        step_x = self.cell_w + self.gap
        step_y = self.cell + self.gap
        return QSize(self.cols * step_x + 4, self.rows * step_y + 24)

    def minimumSizeHint(self):
        return self.sizeHint()

    def _rect(self, i):
        col, row = self._grid_pos(i)
        return QRect(2 + col * (self.cell_w + self.gap), 2 + row * (self.cell + self.gap), self.cell_w, self.cell)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        pal = self.palette()
        f = p.font()
        f.setPointSizeF(6.5)
        p.setFont(f)
        for i, port in enumerate(self.ports):
            r = self._rect(i)
            color = self._color(port)
            p.setPen(QPen(color.darker(140), 1))
            p.setBrush(color)
            p.drawRoundedRect(r, 3, 3)
            if port.get("neighbor"):
                p.setPen(QPen(UPLINK, 2))
                p.setBrush(Qt.NoBrush)
                p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 3, 3)
            if port.get("poe"):
                p.setPen(Qt.NoPen)
                p.setBrush(QColor("#f59e0b"))
                p.drawEllipse(r.right() - 6, r.top() + 2, 4, 4)
            p.setPen(QColor("white") if color.lightness() < 150 else QColor("#111827"))
            p.drawText(r, Qt.AlignCenter, port_label(port))

    def _color(self, port):
        if port.get("err"):
            return ERR
        status = port.get("status")
        if status == "up":
            return UP
        if status == "disabled":
            return DISABLED
        return DOWN

    def _at(self, pos):
        for i in range(len(self.ports)):
            if self._rect(i).contains(pos):
                return self.ports[i]
        return None

    def mouseMoveEvent(self, e):
        port = self._at(e.position().toPoint())
        if port:
            lines = [f"<b>{port['name']}</b>", f"status: {port.get('status', '')}"]
            for k in ("speed", "vlan", "mode", "duplex"):
                if port.get(k):
                    lines.append(f"{k}: {port[k]}")
            if port.get("poe"):
                lines.append(f"PoE: {port['poe']}")
            if port.get("neighbor"):
                lines.append(f"neighbour: {port['neighbor']}")
            if port.get("util"):
                lines.append(f"utilisation: {port['util']}%")
            if port.get("errcount"):
                lines.append(f"errors: {port['errcount']}")
            QToolTip.showText(e.globalPosition().toPoint(), "<br>".join(str(x) for x in lines), self)
            self.setCursor(Qt.PointingHandCursor if port.get("neighbor_id") else Qt.ArrowCursor)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, e):
        port = self._at(e.position().toPoint())
        if port and port.get("neighbor_id"):
            self.portClicked.emit(port["neighbor_id"])


class PortPanel(QWidget):
    """Front-panel of one device, built from the snapshot's interface/port data."""

    openNode = Signal(str)

    def __init__(self, snapshot, device_id: str, parent=None):
        super().__init__(parent)
        self.plate = _Faceplate()
        self.plate.portClicked.connect(self.openNode)
        legend = QLabel("<span style='color:#16a34a'>█</span> up  "
                        "<span style='color:#94a3b8'>█</span> down  "
                        "<span style='color:#4b5563'>█</span> disabled  "
                        "<span style='color:#dc2626'>█</span> errors  "
                        "<span style='color:#2563eb'>▢</span> has a neighbour  "
                        "<span style='color:#f59e0b'>●</span> PoE")
        legend.setObjectName("muted")
        legend.setTextFormat(Qt.RichText)
        legend.setWordWrap(True)
        self.summary = QLabel()
        self.summary.setObjectName("muted")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.addWidget(self.summary)
        lay.addWidget(self.plate)
        lay.addWidget(legend)
        lay.addStretch(1)
        self._build(snapshot, device_id)

    def _build(self, s, device_id):
        dev = s.inv.devices.get(device_id)
        if dev is None:
            return
        # physical ports only (skip SVIs / port-channels / loopbacks), ordered like a faceplate
        phys = [i for i in dev.interfaces if not is_logical_interface(i.name or i.descr or "")]
        phys.sort(key=lambda i: _port_sort_key(i.name or i.descr))
        ports = []
        up = 0
        for i in phys:
            status = ("up" if i.oper_up else "down") if i.admin_up else "disabled"
            up += 1 if status == "up" else 0
            nbrs = s.port_neighbors.get((device_id, i.index), [])
            nbr_id = ""
            for nb in dev.neighbors:
                if nb.local_if_index == i.index:
                    for ipx in nb.remote_mgmt_ips:
                        if ipx in s.inv.ip_to_device:
                            nbr_id = s.inv.ip_to_device[ipx]
                            break
            ports.append({
                "name": i.name or i.descr or f"if{i.index}", "status": status,
                "speed": _speed(i.speed_mbps), "vlan": i.vlan, "mode": i.mode, "duplex": i.duplex,
                "poe": (f"{i.poe_status} {i.poe_watts}W".strip() if i.poe_status else ""),
                "neighbor": "; ".join(nbrs), "neighbor_id": nbr_id,
                "util": max(i.in_util_pct, i.out_util_pct) or "", "err": (i.err_rate or 0) >= 1,
                "errcount": (i.in_errors + i.out_errors) or "",
            })
        self.plate.set_ports(ports)
        self.summary.setText(f"<b>{s.name(device_id)}</b> — {up} of {len(phys)} ports up"
                             + (f" · PoE {dev.poe_used_w:.0f}/{dev.poe_budget_w:.0f} W" if getattr(dev, 'poe_budget_w', 0) else ""))


def _speed(mbps):
    if not mbps:
        return ""
    return f"{mbps // 1000}G" if mbps >= 1000 and mbps % 1000 == 0 else (f"{mbps/1000:.1f}G" if mbps >= 1000 else f"{mbps}M")
