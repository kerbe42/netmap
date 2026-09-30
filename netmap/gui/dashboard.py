"""The overview page: what is in this network at a glance, and where to look first."""
from __future__ import annotations

import html
from collections import Counter

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPalette
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..views import Snapshot, finding_rows, fmt_time
from .icons import ROLE_LABELS, role_color, role_pixmap


class Card(QFrame):
    clicked = Signal()

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setCursor(Qt.PointingHandCursor)
        self.value = QLabel("0")
        self.value.setObjectName("cardValue")
        self.title = QLabel(title)
        self.title.setObjectName("cardTitle")
        self.sub = QLabel("")
        self.sub.setObjectName("muted")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(0)
        lay.addWidget(self.title)
        lay.addWidget(self.value)
        lay.addWidget(self.sub)

    def set(self, value, sub: str = ""):
        self.value.setText(f"{value:,}" if isinstance(value, int) else str(value))
        self.sub.setText(sub)

    def mousePressEvent(self, e):
        self.clicked.emit()


class BarList(QWidget):
    """Label, bar and count per row; optional role icon. Rows: (key, label, value, color, icon_role, kind, suffix)."""

    rowClicked = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list[tuple] = []
        self.row_h = 22
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_rows(self, rows):
        self.rows = rows
        self.setFixedHeight(max(len(rows), 1) * self.row_h + 4)
        self.update()

    def sizeHint(self):
        return QSize(320, max(len(self.rows), 1) * self.row_h + 4)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pal = self.palette()
        if not self.rows:
            p.setPen(pal.color(QPalette.PlaceholderText))
            p.drawText(self.rect(), Qt.AlignLeft | Qt.AlignVCenter, "nothing yet")
            return
        top = max((r[2] for r in self.rows), default=1) or 1
        label_w = min(170, int(self.width() * 0.38))
        count_w = 70
        bar_w = max(self.width() - label_w - count_w - 30, 40)
        for i, (key, label, value, color, icon_role, kind, suffix) in enumerate(self.rows):
            y = i * self.row_h + 2
            x = 0
            if icon_role:
                p.drawPixmap(0, y + 2, role_pixmap(icon_role, 16, kind))
                x = 22
            p.setPen(pal.color(QPalette.Text))
            fm = p.fontMetrics()
            p.drawText(QRectF(x, y, label_w - x, self.row_h), Qt.AlignVCenter | Qt.AlignLeft, fm.elidedText(label, Qt.ElideRight, label_w - x - 4))
            track = QRectF(label_w, y + 5, bar_w, self.row_h - 10)
            p.setPen(Qt.NoPen)
            p.setBrush(pal.color(QPalette.Midlight))
            p.drawRoundedRect(track, 3, 3)
            w = bar_w * (value / top) if top else 0
            p.setBrush(QColor(color))
            p.drawRoundedRect(QRectF(label_w, y + 5, max(w, 2), self.row_h - 10), 3, 3)
            p.setPen(pal.color(QPalette.Text))
            p.drawText(QRectF(label_w + bar_w + 6, y, count_w + 20, self.row_h), Qt.AlignVCenter | Qt.AlignLeft, f"{value:,}{suffix}" if isinstance(value, int) else f"{value}{suffix}")
        p.end()

    def mousePressEvent(self, e):
        i = int(e.position().y() // self.row_h)
        if 0 <= i < len(self.rows):
            self.rowClicked.emit(self.rows[i][0])


def _box(title: str, content: QWidget, hint: str = "") -> QFrame:
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(14, 10, 14, 12)
    t = QLabel(title)
    t.setObjectName("h2")
    lay.addWidget(t)
    if hint:
        h = QLabel(hint)
        h.setObjectName("muted")
        h.setWordWrap(True)
        lay.addWidget(h)
    lay.addWidget(content)
    lay.addStretch(1)
    return f


class Dashboard(QWidget):
    navigate = Signal(str, str)  # page key, filter text
    openNode = Signal(str)
    newScan = Signal()
    openProject = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        outer.addWidget(sa)
        body = QWidget()
        sa.setWidget(body)
        self.lay = QVBoxLayout(body)
        self.lay.setContentsMargins(20, 16, 20, 16)
        self.lay.setSpacing(14)

        head = QHBoxLayout()
        tl = QVBoxLayout()
        self.title = QLabel("Network overview")
        self.title.setObjectName("h1")
        self.sub = QLabel()
        self.sub.setObjectName("muted")
        self.sub.setWordWrap(True)
        tl.addWidget(self.title)
        tl.addWidget(self.sub)
        head.addLayout(tl, 1)
        self.scan_btn = QPushButton("New scan…")
        self.scan_btn.clicked.connect(self.newScan)
        self.map_btn = QPushButton("Open map")
        self.map_btn.clicked.connect(lambda: self.navigate.emit("map", ""))
        head.addWidget(self.map_btn)
        head.addWidget(self.scan_btn)
        self.lay.addLayout(head)

        # welcome (empty project)
        self.welcome = QFrame()
        self.welcome.setObjectName("card")
        wl = QVBoxLayout(self.welcome)
        wl.setContentsMargins(24, 20, 24, 20)
        wt = QLabel("Start by scanning the network")
        wt.setObjectName("h1")
        wl.addWidget(wt)
        wtext = QLabel(
            "NetMap builds an inventory and a topology diagram from what the network's own devices report over SNMP "
            "(read-only): LLDP/CDP neighbours, routing tables, ARP and MAC address tables, VLANs, interfaces and hardware.<br><br>"
            "<b>1.</b> Enter the address ranges you are responsible for (and any you must stay out of).<br>"
            "<b>2.</b> Add the SNMP read-only community or SNMPv3 user for the devices.<br>"
            "<b>3.</b> Optionally name one or two core switches or routers to start from.<br><br>"
            "Everything found is saved in a project file. Document devices as you go, rescan later, and export the inventory "
            "to Excel or the diagram to PDF, SVG or draw.io."
        )
        wtext.setWordWrap(True)
        wtext.setTextFormat(Qt.RichText)
        wl.addWidget(wtext)
        wb = QHBoxLayout()
        b1 = QPushButton("New scan…")
        b1.setDefault(True)
        b1.clicked.connect(self.newScan)
        b2 = QPushButton("Open a project…")
        b2.clicked.connect(self.openProject)
        wb.addWidget(b1)
        wb.addWidget(b2)
        wb.addStretch(1)
        wl.addLayout(wb)
        self.lay.addWidget(self.welcome)

        self.cards_w = QWidget()
        cards = QGridLayout(self.cards_w)
        cards.setContentsMargins(0, 0, 0, 0)
        cards.setSpacing(12)
        self.c_dev = Card("Network devices")
        self.c_host = Card("Hosts / endpoints")
        self.c_sub = Card("Subnets")
        self.c_vlan = Card("VLANs")
        self.c_link = Card("Links")
        self.c_find = Card("Needs attention")
        for i, (c, page) in enumerate(((self.c_dev, "devices"), (self.c_host, "hosts"), (self.c_sub, "subnets"), (self.c_vlan, "vlans"), (self.c_link, "links"), (self.c_find, "findings"))):
            cards.addWidget(c, 0, i)
            c.clicked.connect(lambda page=page: self.navigate.emit(page, ""))
        self.lay.addWidget(self.cards_w)

        self.grid_w = QWidget()
        grid = QGridLayout(self.grid_w)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)
        self.b_roles = BarList()
        self.b_roles.rowClicked.connect(lambda k: self.navigate.emit("devices", f"role:{k}"))
        self.b_vendors = BarList()
        self.b_vendors.rowClicked.connect(lambda k: self.navigate.emit("devices", f'vendor:"{k}"'))
        self.b_hosts = BarList()
        self.b_hosts.rowClicked.connect(lambda k: self.navigate.emit("hosts", f"type:{k}"))
        self.b_subnets = BarList()
        self.b_subnets.rowClicked.connect(self.openNode)
        self.b_find = BarList()
        self.b_find.rowClicked.connect(lambda k: self.navigate.emit("findings", f'finding:"{k}"'))
        self.b_os = BarList()
        self.b_os.rowClicked.connect(lambda k: self.navigate.emit("devices", f'os:"{k}"'))
        grid.addWidget(_box("Devices by role", self.b_roles), 0, 0)
        grid.addWidget(_box("Devices by vendor", self.b_vendors), 0, 1)
        grid.addWidget(_box("Endpoints by type", self.b_hosts, "From MAC vendor, open ports and LLDP; correct any in the Hosts list."), 0, 2)
        grid.addWidget(_box("Busiest subnets", self.b_subnets, "Addresses seen in use. Unswept subnets can only undercount."), 1, 0)
        grid.addWidget(_box("Needs attention", self.b_find, "Things to check before you rely on this inventory."), 1, 1)
        grid.addWidget(_box("Software versions", self.b_os, "OS versions reported by the devices."), 1, 2)
        for c in range(3):
            grid.setColumnStretch(c, 1)
        self.lay.addWidget(self.grid_w)
        self.lay.addStretch(1)

    def set_snapshot(self, s: Snapshot, project_name: str = ""):
        inv = s.inv
        empty = not inv.devices and not inv.hosts
        self.welcome.setVisible(empty)
        self.cards_w.setVisible(not empty)
        self.grid_w.setVisible(not empty)
        self.map_btn.setVisible(not empty)
        self.title.setText(html.escape(project_name or "Network overview"))
        last = inv.history[-1] if inv.history else None
        bits = []
        if inv.project.get("description"):
            bits.append(html.escape(inv.project["description"]))
        if last:
            bits.append(f"Last scan {fmt_time(last.get('started'))}" + (" (stopped early)" if last.get("cancelled") else "") + f" · {len(inv.history)} scan(s) in this project")
        self.sub.setText("<br>".join(bits))
        if empty:
            return
        devices = [d for d in inv.devices.values()]
        hosts = [h for ip, h in inv.hosts.items() if ip not in inv.ip_to_device]
        findings = finding_rows(s)
        attention = [f for f in findings if f["severity"] in ("attention", "check")]
        self.c_dev.set(len(devices), f"+ {len(s.stubs)} seen but not polled" if s.stubs else "all polled")
        swept = sum(1 for sub in inv.subnets.values() if sub.swept)
        self.c_host.set(len(hosts), f"{sum(1 for h in hosts if h.mac)} with a MAC address")
        self.c_sub.set(len(inv.subnets), f"{swept} swept")
        self.c_vlan.set(len(s.vlans), f"{sum(1 for n, _ in s.vlans.values() if len(n) > 1)} named inconsistently" if any(len(n) > 1 for n, _ in s.vlans.values()) else "")
        kinds = Counter(a.get("kind") for _, _, a in s.links)
        self.c_link.set(len(s.links), f"{kinds.get('lldp', 0) + kinds.get('cdp', 0)} cabled · {kinds.get('l3', 0)} routed")
        self.c_find.set(len(attention), f"{len(findings)} findings in total")

        roles = Counter((inv.note(d.id).get("role") or d.role) for d in devices)
        self.b_roles.set_rows([(r, ROLE_LABELS.get(r, r), n, role_color(r).name(), r, "device", "") for r, n in roles.most_common(10)])
        vendors = Counter(d.vendor or "unknown" for d in devices)
        self.b_vendors.set_rows([(v, v, n, "#3b82f6", "", "", "") for v, n in vendors.most_common(8)])
        hroles = Counter((inv.note(h.ip).get("role") or s.role(h.ip) or h.role) for h in hosts)
        self.b_hosts.set_rows([(r, ROLE_LABELS.get(r, r), n, role_color(r).name(), r, "host", "") for r, n in hroles.most_common(10)])
        busiest = sorted(s.ipam.values(), key=lambda r: (-r["utilisation_pct"], -r["used"]))[:8]
        self.b_subnets.set_rows([(r["cidr"], r["cidr"] + (f"  VLAN {r['vlan']}" if r["vlan"] else ""), r["utilisation_pct"],
                                  "#16a34a" if r["utilisation_pct"] < 60 else "#d97706" if r["utilisation_pct"] < 85 else "#dc2626", "subnet", "subnet", "%") for r in busiest])
        cats = Counter(f["category"] for f in findings)
        sev = {f["category"]: f["severity"] for f in findings}
        color = {"attention": "#dc2626", "check": "#d97706", "info": "#94a3b8"}
        order = {"attention": 0, "check": 1, "info": 2}
        self.b_find.set_rows([(c, c, n, color[sev[c]], "", "", "") for c, n in sorted(cats.items(), key=lambda kv: (order[sev[kv[0]]], -kv[1]))[:8]])
        osv = Counter(f"{d.vendor} {d.os_version}".strip() for d in devices if d.os_version)
        self.b_os.set_rows([(k.split(" ", 1)[-1], k, n, "#8b5cf6", "", "", "") for k, n in osv.most_common(8)])
