"""Vector icons for device roles, drawn with QPainter so they stay sharp at any zoom and
DPI and need no image files. The same glyphs are used on the map, in tables and in the
details panel, so a camera looks like a camera everywhere."""
from __future__ import annotations

import math
from functools import lru_cache

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

ROLE_COLORS = {
    "firewall": "#dc2626",
    "router": "#ea580c",
    "l3switch": "#ca8a04",
    "switch": "#2563eb",
    "wireless": "#7c3aed",
    "server": "#059669",
    "vm": "#10b981",
    "database": "#b45309",
    "windows": "#0284c7",
    "workstation": "#64748b",
    "host": "#64748b",
    "printer": "#a16207",
    "phone": "#9333ea",
    "camera": "#e11d48",
    "nas": "#0891b2",
    "ups": "#d97706",
    "plc": "#0d9488",
    "bms": "#0369a1",
    "ot": "#0d9488",
    "bmc": "#7c3aed",
    "unpolled": "#6b7280",
    "unknown": "#6b7280",
    "subnet": "#475569",
}

ROLE_LABELS = {
    "firewall": "Firewall",
    "router": "Router",
    "l3switch": "L3 switch",
    "switch": "Switch",
    "wireless": "Wireless",
    "server": "Server",
    "vm": "Virtual machine",
    "database": "Database",
    "windows": "Windows host",
    "workstation": "Workstation",
    "host": "Host",
    "printer": "Printer",
    "phone": "Phone",
    "camera": "Camera",
    "nas": "Storage / NAS",
    "ups": "UPS / power",
    "plc": "PLC / controller",
    "bms": "Building automation",
    "ot": "OT / industrial",
    "bmc": "Lights-out (BMC)",
    "unpolled": "Not polled",
    "unknown": "Unknown",
    "subnet": "Subnet",
}

ROLES = list(ROLE_LABELS)


def role_color(role: str) -> QColor:
    return QColor(ROLE_COLORS.get(role or "unknown", ROLE_COLORS["unknown"]))


def _arrow(path: QPainterPath, x1, y1, x2, y2, head=0.09):
    """Line from (x1,y1) to (x2,y2) with an arrowhead at the end (unit coordinates)."""
    path.moveTo(x1, y1)
    path.lineTo(x2, y2)
    ang = math.atan2(y2 - y1, x2 - x1)
    for s in (-1, 1):
        a = ang + math.pi + s * 0.55
        path.moveTo(x2, y2)
        path.lineTo(x2 + head * math.cos(a), y2 + head * math.sin(a))


def glyph(role: str) -> tuple[QPainterPath, QPainterPath]:
    """(stroke path, fill path) for a role's white glyph in a 0..1 box."""
    return _glyph(role or "unknown")


@lru_cache(maxsize=None)
def _glyph(role: str) -> tuple[QPainterPath, QPainterPath]:
    s = QPainterPath()  # stroked
    f = QPainterPath()  # filled
    if role == "router":
        _arrow(s, 0.30, 0.30, 0.44, 0.44)
        _arrow(s, 0.70, 0.70, 0.56, 0.56)
        _arrow(s, 0.56, 0.44, 0.70, 0.30)
        _arrow(s, 0.44, 0.56, 0.30, 0.70)
    elif role in ("switch", "l3switch"):
        _arrow(s, 0.26, 0.40, 0.74, 0.40)
        _arrow(s, 0.74, 0.60, 0.26, 0.60)
        if role == "l3switch":
            _arrow(s, 0.50, 0.30, 0.50, 0.16, head=0.07)
            _arrow(s, 0.50, 0.70, 0.50, 0.84, head=0.07)
    elif role == "firewall":
        for r in range(4):
            y = 0.24 + r * 0.14
            f.addRect(QRectF(0.22, y, 0.56, 0.10))
        # mortar gaps
        s.moveTo(0.50, 0.24), s.lineTo(0.50, 0.34)
        s.moveTo(0.36, 0.38), s.lineTo(0.36, 0.48)
        s.moveTo(0.64, 0.38), s.lineTo(0.64, 0.48)
        s.moveTo(0.50, 0.52), s.lineTo(0.50, 0.62)
        s.moveTo(0.36, 0.66), s.lineTo(0.36, 0.76)
        s.moveTo(0.64, 0.66), s.lineTo(0.64, 0.76)
    elif role == "wireless":
        f.addEllipse(QPointF(0.5, 0.66), 0.06, 0.06)
        for r in (0.16, 0.28, 0.40):
            s.arcMoveTo(QRectF(0.5 - r, 0.66 - r, 2 * r, 2 * r), 45)
            s.arcTo(QRectF(0.5 - r, 0.66 - r, 2 * r, 2 * r), 45, 90)
    elif role in ("server", "nas"):
        for i in range(3):
            y = 0.22 + i * 0.19
            s.addRoundedRect(QRectF(0.26, y, 0.48, 0.15), 0.03, 0.03)
            f.addEllipse(QPointF(0.66, y + 0.075), 0.025, 0.025)
            if role == "nas":
                s.moveTo(0.33, y + 0.075), s.lineTo(0.52, y + 0.075)
    elif role == "vm":
        s.addRoundedRect(QRectF(0.22, 0.22, 0.38, 0.38), 0.04, 0.04)
        s.addRoundedRect(QRectF(0.40, 0.40, 0.38, 0.38), 0.04, 0.04)
    elif role == "database":
        s.addEllipse(QRectF(0.28, 0.20, 0.44, 0.14))
        s.moveTo(0.28, 0.27), s.lineTo(0.28, 0.73)
        s.moveTo(0.72, 0.27), s.lineTo(0.72, 0.73)
        s.arcMoveTo(QRectF(0.28, 0.66, 0.44, 0.14), 180)
        s.arcTo(QRectF(0.28, 0.66, 0.44, 0.14), 180, 180)
        s.arcMoveTo(QRectF(0.28, 0.43, 0.44, 0.14), 180)
        s.arcTo(QRectF(0.28, 0.43, 0.44, 0.14), 180, 180)
    elif role in ("workstation", "host", "windows"):
        s.addRoundedRect(QRectF(0.22, 0.24, 0.56, 0.38), 0.04, 0.04)
        s.moveTo(0.50, 0.62), s.lineTo(0.50, 0.72)
        s.moveTo(0.36, 0.74), s.lineTo(0.64, 0.74)
        if role == "windows":
            for dx, dy in ((0, 0), (1, 0), (0, 1), (1, 1)):
                f.addRect(QRectF(0.38 + dx * 0.125, 0.32 + dy * 0.115, 0.105, 0.095))
    elif role == "phone":
        s.addRoundedRect(QRectF(0.32, 0.20, 0.36, 0.60), 0.06, 0.06)
        s.addRect(QRectF(0.38, 0.27, 0.24, 0.13))
        for r in range(3):
            for c in range(3):
                f.addEllipse(QPointF(0.41 + c * 0.09, 0.50 + r * 0.085), 0.022, 0.022)
    elif role == "printer":
        s.addRect(QRectF(0.34, 0.20, 0.32, 0.18))
        s.addRoundedRect(QRectF(0.22, 0.38, 0.56, 0.26), 0.04, 0.04)
        s.addRect(QRectF(0.34, 0.56, 0.32, 0.22))
        f.addEllipse(QPointF(0.70, 0.45), 0.025, 0.025)
    elif role == "camera":
        s.addRoundedRect(QRectF(0.20, 0.34, 0.44, 0.32), 0.05, 0.05)
        s.moveTo(0.64, 0.44), s.lineTo(0.80, 0.36), s.lineTo(0.80, 0.64), s.lineTo(0.64, 0.56)
        f.addEllipse(QPointF(0.42, 0.50), 0.07, 0.07)
    elif role == "ups":
        s.addRoundedRect(QRectF(0.24, 0.30, 0.48, 0.40), 0.04, 0.04)
        s.addRect(QRectF(0.72, 0.42, 0.05, 0.16))
        f.moveTo(0.50, 0.33), f.lineTo(0.38, 0.52), f.lineTo(0.48, 0.52), f.lineTo(0.44, 0.67), f.lineTo(0.60, 0.46), f.lineTo(0.50, 0.46), f.closeSubpath()
    elif role == "subnet":
        for i, x in enumerate((0.26, 0.42, 0.58, 0.74)):
            f.addEllipse(QPointF(x, 0.62), 0.045, 0.045)
            s.moveTo(x, 0.62), s.lineTo(x, 0.44)
        s.moveTo(0.20, 0.44), s.lineTo(0.80, 0.44)
    elif role in ("plc", "ot"):
        s.addRoundedRect(QRectF(0.26, 0.26, 0.48, 0.48), 0.04, 0.04)
        f.addRect(QRectF(0.40, 0.40, 0.20, 0.20))
        for k in range(4):
            x = 0.30 + k * 0.133
            s.moveTo(x, 0.20), s.lineTo(x, 0.26)
            s.moveTo(x, 0.74), s.lineTo(x, 0.80)
            s.moveTo(0.20, x), s.lineTo(0.26, x)
            s.moveTo(0.74, x), s.lineTo(0.80, x)
    elif role == "bms":
        s.addRect(QRectF(0.30, 0.22, 0.40, 0.56))
        for r in range(3):
            for c in range(3):
                f.addRect(QRectF(0.36 + c * 0.10, 0.30 + r * 0.14, 0.06, 0.08))
    elif role == "bmc":
        s.addRoundedRect(QRectF(0.24, 0.30, 0.52, 0.40), 0.04, 0.04)
        f.addEllipse(QPointF(0.34, 0.5), 0.04, 0.04)
        s.moveTo(0.44, 0.5), s.lineTo(0.70, 0.5)
    else:  # unknown / unpolled: a question mark
        s.moveTo(0.38, 0.36)
        s.cubicTo(0.38, 0.20, 0.62, 0.20, 0.62, 0.36)
        s.cubicTo(0.62, 0.46, 0.50, 0.46, 0.50, 0.58)
        f.addEllipse(QPointF(0.50, 0.71), 0.04, 0.04)
    return s, f


def badge_path(kind: str, rect: QRectF) -> QPainterPath:
    """Outline shape by kind: rounded square for network devices, circle for hosts,
    rounded bar for subnets."""
    p = QPainterPath()
    if kind == "host":
        p.addEllipse(rect)
    elif kind == "subnet":
        p.addRoundedRect(rect.adjusted(-rect.width() * 0.25, rect.height() * 0.12, rect.width() * 0.25, -rect.height() * 0.12), rect.height() * 0.3, rect.height() * 0.3)
    else:
        r = rect.width() * 0.22
        p.addRoundedRect(rect, r, r)
    return p


def paint_badge(painter: QPainter, rect: QRectF, role: str, kind: str = "device", dashed: bool = False, border: QColor | None = None) -> None:
    """Coloured badge with the white role glyph inside `rect`."""
    role = role or "unknown"
    color = role_color("subnet" if kind == "subnet" else role)
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing, True)
    shape = badge_path(kind, rect)
    if dashed:
        painter.setBrush(QBrush(QColor(color.red(), color.green(), color.blue(), 60)))
        pen = QPen(color, max(1.2, rect.width() * 0.05))
        pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
    else:
        grad_top = color.lighter(118)
        painter.setBrush(QBrush(grad_top))
        painter.setPen(QPen(border or color.darker(135), max(1.0, rect.width() * 0.035)))
    painter.drawPath(shape)
    s, f = glyph("subnet" if kind == "subnet" else role)
    painter.translate(rect.topLeft())
    painter.scale(rect.width(), rect.height())
    fg = QColor("#374151") if dashed else QColor("white")
    pen = QPen(fg, 0.065 if kind != "host" else 0.075)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    painter.drawPath(s)
    painter.setPen(Qt.NoPen)
    painter.setBrush(fg)
    painter.drawPath(f)
    painter.restore()


@lru_cache(maxsize=256)
def role_pixmap(role: str, size: int = 20, kind: str = "device", dpr: float = 2.0) -> QPixmap:
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    m = size * 0.06
    rect = QRectF(m, m, size - 2 * m, size - 2 * m)
    if kind == "subnet":
        rect = QRectF(size * 0.2, size * 0.2, size * 0.6, size * 0.6)
    paint_badge(p, rect, role, kind, dashed=role == "unpolled")
    p.end()
    return pm


def role_icon(role: str, kind: str = "device") -> QIcon:
    icon = QIcon()
    for s in (16, 20, 24, 32):
        icon.addPixmap(role_pixmap(role or "unknown", s, kind))
    return icon


def app_pixmap(size: int = 256) -> QPixmap:
    """The application icon: three linked nodes on a blue tile."""
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    r = QRectF(size * 0.04, size * 0.04, size * 0.92, size * 0.92)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#1d4ed8"))
    p.drawRoundedRect(r, size * 0.2, size * 0.2)
    pts = [QPointF(size * 0.50, size * 0.26), QPointF(size * 0.26, size * 0.70), QPointF(size * 0.74, size * 0.70)]
    pen = QPen(QColor("#bfdbfe"), size * 0.055)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    p.drawLine(pts[0], pts[1])
    p.drawLine(pts[0], pts[2])
    p.drawLine(pts[1], pts[2])
    p.setPen(QPen(QColor("#1e3a8a"), size * 0.03))
    for i, pt in enumerate(pts):
        p.setBrush(QColor("#f59e0b") if i == 0 else QColor("white"))
        p.drawEllipse(pt, size * 0.115, size * 0.115)
    p.end()
    return pm


def app_icon() -> QIcon:
    icon = QIcon()
    for s in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(app_pixmap(s))
    return icon
