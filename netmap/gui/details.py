"""The details panel: everything known about the selected device, host, subnet or VLAN,
plus the documentation fields people fill in while they work through the network."""
from __future__ import annotations

import html
import ipaddress
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableView,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..util import oui_vendor
from ..views import (
    HARDWARE_COLUMNS,
    IFACE_COLUMNS,
    STATUSES,
    Column,
    Snapshot,
    fmt_duration,
    fmt_time,
    hardware_rows,
    interface_rows,
    subnet_addresses,
)
from .icons import ROLE_LABELS, ROLES, role_pixmap
from .ipgrid import IpGrid
from .table import ID_ROLE, FilterProxy, RowsModel

ROUTE_PROTO = {1: "other", 2: "connected", 3: "static", 4: "icmp", 8: "rip", 9: "is-is", 13: "ospf", 14: "bgp", 16: "eigrp", 11: "igrp"}


def _peers_summary(peers) -> str:
    from collections import Counter
    if not peers:
        return ""
    c = Counter((p["proto"], p["state"]) for p in peers)
    return ", ".join(f"{n} {proto.upper()} {state}" for (proto, state), n in sorted(c.items()))


def _eol_summary(dev) -> str:
    try:
        from ..eol import annotate_device
        e = annotate_device(dev)
    except Exception:  # noqa: BLE001
        return ""
    if not e:
        return ""
    label = {"active": "supported", "end-of-sale": "end-of-sale", "end-of-support": "END OF SUPPORT", "unknown": "support dates unknown"}.get(e["status"], e["status"])
    bits = [label]
    if e.get("eol"):
        bits.append(f"EoL {e['eol']}")
    if e.get("family"):
        bits.append(f"({e['family']})")
    return " ".join(bits) + "  — verify with the vendor"


def _mgmt_summary(mgmt) -> str:
    if not mgmt:
        return ""
    on = [k.upper() for k in ("telnet", "ssh", "http", "https") if mgmt.get(k)]
    warn = " ⚠ cleartext" if (mgmt.get("telnet") or mgmt.get("http")) else ""
    return (", ".join(on) or "none reachable") + warn


def _stp_summary(stp) -> str:
    if not stp or not stp.get("root"):
        return ""
    if stp.get("is_root"):
        return f"root bridge (priority {stp.get('priority', '')})"
    return f"root is {stp['root']}" + (f", via {stp['root_port']}" if stp.get("root_port") else "")


def _table(columns: list[Column], rows: list[dict], on_open=None) -> QTableView:
    model = RowsModel(columns)
    model.set_rows(rows)
    proxy = FilterProxy()
    proxy.setSourceModel(model)
    v = QTableView()
    v.setModel(proxy)
    v.setSortingEnabled(True)
    v.sortByColumn(-1, Qt.AscendingOrder)
    v.setAlternatingRowColors(True)
    v.setSelectionBehavior(QAbstractItemView.SelectRows)
    v.setEditTriggers(QAbstractItemView.NoEditTriggers)
    v.verticalHeader().setVisible(False)
    v.verticalHeader().setDefaultSectionSize(22)
    v.horizontalHeader().setStretchLastSection(True)
    v.setWordWrap(False)
    for i, c in enumerate(columns):
        if c.width:
            v.setColumnWidth(i, min(c.width, 170))
        v.setColumnHidden(i, not c.visible)
    v._model = model  # keep a reference
    v._proxy = proxy
    if on_open:
        v.doubleClicked.connect(lambda idx: idx.data(ID_ROLE) and on_open(idx.data(ID_ROLE)))
    return v


def _cols(*specs) -> list[Column]:
    return [Column(*s) if isinstance(s, tuple) else s for s in specs]


class DocForm(QWidget):
    """Editable documentation for one node; changes are saved as you type."""

    changed = Signal(str, dict)  # node id, fields

    def __init__(self, parent=None):
        super().__init__(parent)
        self.node_id = ""
        self._loading = False
        self.name = QLineEdit()
        self.name.setPlaceholderText("what people call it (overrides the discovered name)")
        self.role = QComboBox()
        self.role.addItem("(as discovered)", "")
        for r in ROLES:
            if r not in ("subnet", "unpolled"):
                self.role.addItem(ROLE_LABELS[r], r)
        self.site = QLineEdit()
        self.site.setPlaceholderText("building, floor, closet, rack…")
        self.owner = QLineEdit()
        self.owner.setPlaceholderText("team or person responsible")
        self.asset = QLineEdit()
        self.status = QComboBox()
        self.status.setEditable(True)
        for s in STATUSES:
            self.status.addItem(s)
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("comma separated, e.g. core, pci, contract-renewal")
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Anything worth knowing: what it is for, who to call, what to change…")
        self.notes.setMinimumHeight(120)
        form = QFormLayout(self)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form.addRow("Name", self.name)
        form.addRow("Role", self.role)
        form.addRow("Site", self.site)
        form.addRow("Owner", self.owner)
        form.addRow("Asset tag", self.asset)
        form.addRow("Status", self.status)
        form.addRow("Tags", self.tags)
        form.addRow("Notes", self.notes)
        hint = QLabel("Saved in the project file. A rescan never overwrites these.")
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        form.addRow(hint)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._emit)
        for w in (self.name, self.site, self.owner, self.asset, self.tags):
            w.textEdited.connect(self._timer.start)
            w.editingFinished.connect(self._flush)
        self.notes.textChanged.connect(lambda: None if self._loading else self._timer.start())
        self.role.currentIndexChanged.connect(lambda _: None if self._loading else self._emit())
        self.status.currentTextChanged.connect(lambda _: None if self._loading else self._timer.start())

    def load(self, node_id: str, note: dict, kind: str):
        self._loading = True
        self._timer.stop()
        self.node_id = node_id
        self.name.setText(note.get("name", ""))
        i = self.role.findData(note.get("role", ""))
        self.role.setCurrentIndex(max(i, 0))
        self.role.setEnabled(kind in ("device", "host"))
        self.site.setText(note.get("site", ""))
        self.owner.setText(note.get("owner", ""))
        self.asset.setText(note.get("asset_tag", ""))
        self.status.setCurrentText(note.get("status", ""))
        self.tags.setText(", ".join(note.get("tags", [])))
        self.notes.setPlainText(note.get("notes", ""))
        self._loading = False

    def _flush(self):
        if self._timer.isActive():
            self._timer.stop()
            self._emit()

    def _emit(self):
        if self._loading or not self.node_id:
            return
        tags = [t.strip() for t in self.tags.text().split(",") if t.strip()]
        self.changed.emit(
            self.node_id,
            {
                "name": self.name.text().strip(),
                "role": self.role.currentData() or "",
                "site": self.site.text().strip(),
                "owner": self.owner.text().strip(),
                "asset_tag": self.asset.text().strip(),
                "status": self.status.currentText().strip(),
                "tags": tags,
                "notes": self.notes.toPlainText().rstrip(),
            },
        )


class DetailsPanel(QWidget):
    showOnMap = Signal(str)
    openNode = Signal(str)
    annotationChanged = Signal(str, dict)
    actionRequested = Signal(str, str)  # action, node id  (browse / ping / rescan / focus)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.snapshot: Optional[Snapshot] = None
        self.node_id = ""
        self.icon = QLabel()
        self.icon.setFixedSize(44, 44)
        self.title = QLabel()
        self.title.setObjectName("h1")
        self.title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.title.setWordWrap(True)
        self.subtitle = QLabel()
        self.subtitle.setObjectName("muted")
        self.subtitle.setWordWrap(True)
        head = QHBoxLayout()
        head.addWidget(self.icon, 0, Qt.AlignTop)
        tl = QVBoxLayout()
        tl.setSpacing(1)
        tl.addWidget(self.title)
        tl.addWidget(self.subtitle)
        head.addLayout(tl, 1)
        self.buttons = QHBoxLayout()
        self.btn_map = QPushButton("Show on map")
        self.btn_map.clicked.connect(lambda: self.showOnMap.emit(self.node_id))
        self.btn_web = QToolButton()
        self.btn_web.setText("Open")
        self.btn_web.setPopupMode(QToolButton.InstantPopup)
        from PySide6.QtWidgets import QMenu

        m = QMenu(self.btn_web)
        m.addAction("Web page (https)", lambda: self.actionRequested.emit("https", self.node_id))
        m.addAction("Web page (http)", lambda: self.actionRequested.emit("http", self.node_id))
        m.addAction("SSH session", lambda: self.actionRequested.emit("ssh", self.node_id))
        m.addAction("Ping", lambda: self.actionRequested.emit("ping", self.node_id))
        m.addAction("Traceroute", lambda: self.actionRequested.emit("traceroute", self.node_id))
        self.btn_web.setMenu(m)
        self.btn_rescan = QPushButton("Rescan")
        self.btn_rescan.setToolTip("Poll this device again now")
        self.btn_rescan.clicked.connect(lambda: self.actionRequested.emit("rescan", self.node_id))
        for b in (self.btn_map, self.btn_web, self.btn_rescan):
            self.buttons.addWidget(b)
        self.buttons.addStretch(1)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.doc = DocForm()
        self.doc.changed.connect(self.annotationChanged)
        # one scroll area for the life of the panel: a widget must never be handed to a
        # second scroll area while the first still points at it
        self.doc_scroll = self._scroll(self.doc)

        self.empty = QLabel("Select a device, host or subnet — in a list or on the map — to see its details here.")
        self.empty.setWordWrap(True)
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setObjectName("muted")

        self.body = QWidget()
        bl = QVBoxLayout(self.body)
        bl.setContentsMargins(10, 10, 10, 6)
        bl.addLayout(head)
        bl.addLayout(self.buttons)
        bl.addWidget(self.tabs, 1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.empty, 1)
        lay.addWidget(self.body, 1)
        self.body.hide()
        self._last_tab: dict[str, str] = {}

    # ------------------------------------------------------------ entry
    def clear(self):
        self.node_id = ""
        self._clear_tabs()
        self.body.hide()
        self.empty.show()

    def show_node(self, snapshot: Snapshot, node_id: str, force: bool = False):
        if not force and node_id == self.node_id and snapshot is self.snapshot:
            return
        prev_kind = self.snapshot.kind(self.node_id) if self.snapshot and self.node_id else ""
        if self.tabs.count() and prev_kind:
            self._last_tab[prev_kind] = self.tabs.tabText(self.tabs.currentIndex()).split(" (")[0]
        self.snapshot = snapshot
        self.node_id = node_id
        inv = snapshot.inv
        self._clear_tabs()
        if node_id in inv.devices:
            self._device(snapshot, inv.devices[node_id])
            kind = "device"
        elif node_id.startswith("stub:"):
            self._stub(snapshot, node_id)
            kind = "device"
        elif node_id in inv.hosts:
            self._host(snapshot, node_id)
            kind = "host"
        elif node_id in inv.subnets:
            self._subnet(snapshot, node_id)
            kind = "subnet"
        elif node_id.startswith("vlan:"):
            self._vlan(snapshot, node_id)
            kind = "vlan"
        elif node_id in inv.ip_to_device:
            return self.show_node(snapshot, inv.ip_to_device[node_id], force=True)
        else:
            self.clear()
            return
        self.doc.load(node_id, inv.note(node_id), kind)
        self.tabs.insertTab(1, self.doc_scroll, "Notes")
        self.tabs.setTabToolTip(1, "Your documentation for this item: name, role, site, owner, asset tag, status, tags, notes")
        want = self._last_tab.get(snapshot.kind(node_id) or kind)
        for i in range(self.tabs.count()):
            if want and self.tabs.tabText(i).split(" (")[0] == want:
                self.tabs.setCurrentIndex(i)
        self.btn_map.setEnabled(node_id in snapshot.g)
        is_dev = node_id in inv.devices
        self.btn_rescan.setVisible(is_dev)
        self.btn_web.setVisible(kind in ("device", "host"))
        self.empty.hide()
        self.body.show()

    def _clear_tabs(self):
        """Remove and delete the previous item's pages (QTabWidget.clear only hides them)."""
        while self.tabs.count():
            w = self.tabs.widget(0)
            self.tabs.removeTab(0)
            if w is not self.doc_scroll:
                w.deleteLater()

    # ------------------------------------------------------------ builders
    def _head(self, role: str, kind: str, title: str, subtitle: str):
        self.icon.setPixmap(role_pixmap(role or "unknown", 44, kind))
        self.title.setText(html.escape(title))
        self.subtitle.setText(subtitle)

    def _scroll(self, w: QWidget) -> QScrollArea:
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.NoFrame)
        sa.setWidget(w)
        return sa

    def _facts(self, pairs: list[tuple[str, object]], extra: Optional[QWidget] = None) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        form.setLabelAlignment(Qt.AlignRight)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        for k, v in pairs:
            if v in (None, "", [], 0) and k not in ("Management IP",):
                continue
            lab = QLabel(html.escape(str(v)) if not isinstance(v, QWidget) else "")
            if isinstance(v, QWidget):
                form.addRow(k, v)
                continue
            lab.setWordWrap(True)
            lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
            lab.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            form.addRow(f"<span style='color:gray'>{k}</span>", lab)
        if extra is not None:
            form.addRow(extra)
        return self._scroll(w)

    def _link(self, text: str, node: str) -> QLabel:
        lab = QLabel(f"<a href='{html.escape(node)}'>{html.escape(text)}</a>")
        lab.linkActivated.connect(self.openNode)
        return lab

    def _device(self, s: Snapshot, d):
        inv = s.inv
        note = inv.note(d.id)
        role = note.get("role") or d.role
        sub = " · ".join(x for x in (ROLE_LABELS.get(role, role), " ".join(x for x in (d.vendor, d.model) if x), d.id) if x)
        self._head(role, "device", s.name(d.id), sub)
        up = sum(1 for i in d.interfaces if i.oper_up)
        pairs = [
            ("Management IP", d.id),
            ("Other addresses", ", ".join(ip for ip in d.ips if ip != d.id)),
            ("DNS name", d.dns_name),
            ("sysName", d.name if note.get("name") else ""),
            ("Role", ROLE_LABELS.get(role, role) + (" (set by you)" if note.get("role") else "")),
            ("Vendor", d.vendor),
            ("Model", d.model),
            ("Serial", d.serial),
            ("OS version", d.os_version),
            ("Support status", _eol_summary(d)),
            ("Management", _mgmt_summary(getattr(d, "mgmt", {}))),
            ("Description", d.sysdescr),
            ("Location (SNMP)", d.location),
            ("Site", note.get("site")),
            ("Contact", d.contact),
            ("Owner", note.get("owner")),
            ("Status", note.get("status")),
            ("Tags", ", ".join(note.get("tags", []))),
            ("Uptime", fmt_duration(d.uptime_s)),
            ("Ports", f"{up} up of {len(d.interfaces)}" if d.interfaces else ""),
            ("PoE", f"{d.poe_used_w:.0f} W of {d.poe_budget_w:.0f} W used" if getattr(d, "poe_budget_w", 0) else ""),
            ("VLANs", len(d.vlans)),
            ("Redundancy", "; ".join(f"{g['proto'].upper()} grp {g['group']} {g['state']} for {g['vip']}" + (f" on {g['interface']}" if g.get('interface') else "") for g in getattr(d, "redundancy", []))),
            ("Routing peers", _peers_summary(getattr(d, "peers", []))),
            ("Spanning tree", _stp_summary(getattr(d, "stp", {}))),
            ("Found", f"{d.discovered_via} (depth {d.depth})"),
            ("Credential", d.credential),
            ("First seen", fmt_time(d.first_seen)),
            ("Last polled", fmt_time(d.collected_at) + (f" in {d.collect_seconds:.1f}s" if d.collect_seconds else "")),
            ("Problems", "; ".join(d.errors)),
        ]
        self.tabs.addTab(self._facts(pairs), "Overview")
        icols = [c for c in IFACE_COLUMNS if c.key != "device"]
        self.tabs.addTab(_table(icols, interface_rows(s, d.id)), "Ports")
        nb_rows = []
        for nb in d.neighbors:
            target = None
            for ip in nb.remote_mgmt_ips:
                target = inv.ip_to_device.get(ip) or (ip if ip in inv.hosts else None)
                if target:
                    break
            if target is None and nb.remote_chassis_id in inv.mac_to_device:
                target = inv.mac_to_device[nb.remote_chassis_id]
            if target is None:
                dd = inv.device_for_name(nb.remote_name)
                target = dd.id if dd else None
            nb_rows.append(
                {
                    "_id": target or "", "_role": s.role(target) if target else "unpolled", "_kind": "device",
                    "neighbor": nb.remote_name or nb.remote_chassis_id, "local": nb.local_port, "remote": nb.remote_port,
                    "proto": nb.proto.upper(), "ip": ", ".join(nb.remote_mgmt_ips), "platform": nb.remote_platform, "caps": nb.remote_caps,
                }
            )
        ncols = _cols(("neighbor", "Neighbour", "text", 150), ("local", "Local port", "port", 90), ("remote", "Their port", "port", 90),
                      ("proto", "Via", "text", 50), ("ip", "Address", "ip", 100), ("platform", "Platform", "text", 160), ("caps", "Capabilities", "text", 100))
        self.tabs.addTab(_table(ncols, nb_rows, self.openNode), "Neighbours")
        hosts = s.fdb_hosts.get(d.id, [])
        if hosts:
            hrows = []
            for hip, port, vlan in hosts:
                h = inv.hosts.get(hip)
                hrows.append({"_id": hip, "_role": s.role(hip), "_kind": "host", "name": s.name(hip), "ip": hip, "mac": h.mac if h else "",
                              "vendor": h.vendor if h else "", "port": port, "vlan": vlan if vlan is not None else ""})
            hcols = _cols(("name", "Host", "text", 140), ("ip", "IP", "ip", 100), ("port", "Port", "port", 70), ("vlan", "VLAN", "int", 45),
                          ("mac", "MAC", "text", 120), ("vendor", "Vendor", "text", 140))
            self.tabs.addTab(_table(hcols, hrows, self.openNode), "Hosts")
        hw = hardware_rows(s, d.id)
        if hw:
            self.tabs.addTab(_table([c for c in HARDWARE_COLUMNS if c.key != "device"], hw), "Hardware")
        if d.arp:
            arows = [{"_id": a.ip if a.ip in inv.hosts or a.ip in inv.ip_to_device else "", "_role": "", "ip": a.ip, "mac": a.mac,
                      "vendor": oui_vendor(a.mac), "iface": d.iface_label(a.if_index), "name": s.name(inv.ip_to_device.get(a.ip, a.ip))} for a in d.arp]
            acols = _cols(("ip", "IP", "ip", 105), ("mac", "MAC", "text", 120), ("vendor", "Vendor", "text", 140), ("iface", "Interface", "port", 90), ("name", "Name", "text", 140))
            self.tabs.addTab(_table(acols, arows, self.openNode), "ARP")
        if d.routes:
            rrows = []
            for r in d.routes:
                nh_dev = inv.ip_to_device.get(r.nexthop)
                rrows.append({"_id": nh_dev or "", "_role": "", "dest": r.dest, "nexthop": r.nexthop if r.nexthop != "0.0.0.0" else "(connected)",
                              "via": s.name(nh_dev) if nh_dev else "", "iface": d.iface_label(r.if_index) if r.if_index else "",
                              "proto": ROUTE_PROTO.get(r.proto, str(r.proto) if r.proto else "")})
            rcols = _cols(("dest", "Destination", "cidr", 120), ("nexthop", "Next hop", "ip", 105), ("via", "Next-hop device", "text", 130),
                          ("iface", "Interface", "port", 90), ("proto", "Learned by", "text", 80))
            self.tabs.addTab(_table(rcols, rrows, self.openNode), "Routes")
        if d.vlans:
            vrows = [{"_id": f"vlan:{v}", "_role": "", "vlan": v, "name": n} for v, n in sorted(d.vlans.items())]
            self.tabs.addTab(_table(_cols(("vlan", "VLAN", "int", 60), ("name", "Name", "text", 200)), vrows, self.openNode), "VLANs")
        revs = s.inv.configs.get(d.id)
        if revs:
            from .capturedlg import ConfigView

            self.tabs.addTab(ConfigView(revs), "Config")
        self._add_path_tab(s, d.id)

    def _add_path_tab(self, s: Snapshot, node_id: str):
        """Show how the network reaches this node: the path from the core across the backbone."""
        from .. import paths

        try:
            p = paths.path_to(s.inv, s.g, node_id)
        except Exception:  # noqa: BLE001 - a path view must never break the panel
            return
        if not p.ok or len(p.hops) < 2:
            return
        rows = []
        for i, hop in enumerate(p.hops):
            link = ""
            if hop.out_port or hop.in_port:
                link = f"{hop.out_port} → {hop.in_port}".strip(" →")
            rows.append({"_id": hop.node if hop.node in s.inv.devices or hop.node in s.inv.hosts else "", "_role": hop.role or s.role(hop.node),
                         "_kind": s.kind(hop.node) or "device", "step": i, "hop": s.name(hop.node) if (hop.node in s.inv.devices or hop.node in s.inv.hosts) else hop.node,
                         "via": {"start": "from here", "lldp": "cabling", "cdp": "cabling", "l3": "routing", "route": "routing", "access": "switch port"}.get(hop.kind, hop.kind),
                         "link": link, "detail": hop.detail})
        cols = _cols(("step", "#", "int", 30), ("hop", "Hop", "text", 170), ("via", "Via", "text", 80), ("link", "Ports", "port", 130), ("detail", "Detail", "text", 200))
        origin = s.name(p.origin)
        self.tabs.addTab(_table(cols, rows, self.openNode), "Path")

    def _stub(self, s: Snapshot, sid: str):
        a = s.g.nodes[sid] if sid in s.g else {}
        seen = []
        for n in (s.g.neighbors(sid) if sid in s.g else []):
            seen.append(s.name(n))
        self._head("unpolled", "device", s.name(sid), "Seen over LLDP/CDP, not polled")
        pairs = [
            ("Announced as", a.get("label")),
            ("Address", ", ".join(a.get("ips", [])) or a.get("ip")),
            ("Chassis ID", a.get("chassis_id")),
            ("Platform", a.get("model")),
            ("Capabilities", a.get("caps")),
            ("Seen from", ", ".join(sorted(set(seen)))),
            ("Why not polled", "No credential answered, SNMP is filtered, or its address is outside the scope. "
                               "Add a credential or widen the scope and rescan to inventory it."),
        ]
        self.tabs.addTab(self._facts(pairs), "Overview")

    def _host(self, s: Snapshot, ip: str):
        inv = s.inv
        h = inv.hosts[ip]
        note = inv.note(ip)
        role = note.get("role") or s.role(ip) or h.role
        self._head(role, "host", s.name(ip), " · ".join(x for x in (ROLE_LABELS.get(role, role), h.vendor, ip) if x))
        dev, port, vlan = s.placement.get(ip, ("", "", None))
        where = None
        if dev:
            where = self._link(f"{s.name(dev)}  port {port}" + (f"  (VLAN {vlan})" if vlan is not None else ""), dev)
        subnet = inv.subnet_for_ip(ip)
        conf = {"high": "high confidence", "medium": "medium confidence", "low": "low confidence"}.get(h.confidence, h.confidence)
        alt = "; ".join(f"{k}: {v}" for k, v in (h.names or {}).items() if v and v != h.hostname)
        pairs = [
            ("IP address", ip),
            ("Name", h.hostname),
            ("Also known as", alt),
            ("MAC", (h.mac + (f"  (from {h.mac_source})" if h.mac_source else "")) if h.mac else ""),
            ("Vendor", h.vendor),
            ("Type", ROLE_LABELS.get(role, role) + (" (set by you)" if note.get("role") else (f" - {conf}" if conf else ""))),
            ("Operating system", h.os or h.os_family),
            ("Model", h.model),
            ("Switch port", where if where is not None else ""),
            ("Subnet", self._link(subnet, subnet) if subnet else ""),
            ("Open ports", ", ".join(f"{p['port']}/{p.get('proto', '')} {p.get('service', '')} {p.get('product', '')}".strip() for p in h.ports)),
            ("Seen via", ", ".join(h.sources)),
            ("Seen in ARP of", ", ".join(sorted({s.name(x['device']) for x in h.seen_on if x.get('via') == 'arp'}))),
            ("SNMP", "probed, no answer" if h.snmp_failed else ""),
            ("First seen", fmt_time(h.first_seen)),
            ("Last seen", fmt_time(h.last_seen)),
        ]
        self.tabs.addTab(self._facts(pairs), "Overview")
        if h.evidence:
            ecols = _cols(("source", "Signal", "text", 90), ("observed", "What was seen", "text", 220), ("implies", "Suggests", "text", 150))
            self.tabs.addTab(_table(ecols, [{"_id": "", "_role": "", **e} for e in h.evidence]), "Why")
        self._add_path_tab(s, ip)

    def _subnet(self, s: Snapshot, cidr: str):
        inv = s.inv
        r = s.ipam.get(cidr, {})
        note = inv.note(cidr)
        vlan = r.get("vlan", "")
        self._head("subnet", "subnet", note.get("name") or cidr,
                   " · ".join(x for x in (cidr if note.get("name") else "", f"VLAN {vlan}" if vlan else "",
                                          f"{r.get('used', 0)} of {r.get('usable', 0)} in use ({r.get('utilisation_pct', 0)}%)") if x))
        grid = IpGrid()
        grid.set_subnet(s, cidr)
        grid.nodeClicked.connect(self.openNode)
        gws = []
        sub = inv.subnets.get(cidr)
        for g in (sub.gateways if sub else []):
            gws.append(s.name(g))
        vgw = "; ".join(f"{v['proto'].upper()} {v['vip']}" + (f" (active {s.name(v['active'])})" if v.get("active") else "") for v in s.vgw.get(cidr, []))
        pairs = [
            ("Virtual gateway", vgw),
            ("Gateway(s)", ", ".join(gws)),
            ("VLAN", vlan),
            ("Addresses", f"{r.get('size', '')} ({r.get('usable', '')} usable)"),
            ("In use", f"{r.get('used', 0)}" + ("" if r.get("swept") else "  — a floor: never swept, so only addresses seen in ARP/routes are counted")),
            ("Free", r.get("free")),
            ("Found via", r.get("sources")),
        ]
        net = ipaddress.ip_network(cidr)
        if net.num_addresses <= 65536:
            self.tabs.addTab(self._facts(pairs, grid), "Overview")
        else:
            self.tabs.addTab(self._facts(pairs), "Overview")
        used = [c for c in subnet_addresses(s, cidr, limit=65536) if c["state"] not in ("free", "reserved")]
        rows = [{"_id": c.get("node", ""), "_role": c.get("role", ""), "_kind": "host", "ip": c["ip"], "what": c["state"], "name": c.get("label", "")} for c in used]
        self.tabs.addTab(_table(_cols(("ip", "Address", "ip", 110), ("what", "What", "text", 90), ("name", "Name", "text", 200)), rows, self.openNode),
                         "Addresses")

    def _vlan(self, s: Snapshot, vid_id: str):
        vid = int(vid_id.split(":", 1)[1])
        names, devs = s.vlans.get(vid, (set(), set()))
        self._head("switch", "device", f"VLAN {vid}", " / ".join(sorted(names)))
        subs = [c for c, r in s.ipam.items() if str(vid) in str(r["vlan"]).split()]
        pairs = [
            ("Name(s)", " / ".join(sorted(names)) + ("  — switches disagree" if len(names) > 1 else "")),
            ("Carried on", ", ".join(sorted(devs))),
            ("Subnet(s)", ", ".join(subs)),
        ]
        self.tabs.addTab(self._facts(pairs), "Overview")
