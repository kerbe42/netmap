"""The New Scan dialog: where to look, which credentials, how hard to look."""
from __future__ import annotations

import ipaddress
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..scan import ScanRequest, resolve_scope
from ..snmp import Credential
from ..sweep import find_nmap
from .credentials import CredentialsDialog, CredentialStore


def parse_ranges(text: str) -> tuple[list[str], list[str]]:
    """Subnets/addresses from free text (one per line, commas or spaces, '#' comments).

    Also accepts first-last ranges (10.0.0.10-10.0.0.40 or 10.0.0.10-40), turned into the
    covering CIDR blocks. Returns (valid CIDRs, problems).
    """
    out, bad = [], []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        for item in re.split(r"[,\s;]+", line):
            if not item:
                continue
            try:
                if "-" in item and "/" not in item:
                    a, b = item.split("-", 1)
                    start = ipaddress.ip_address(a)
                    if "." not in b and ":" not in b:
                        b = a.rsplit(".", 1)[0] + "." + b
                    end = ipaddress.ip_address(b)
                    out += [str(n) for n in ipaddress.summarize_address_range(start, end)]
                else:
                    out.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                bad.append(item)
    return list(dict.fromkeys(out)), bad


class ScanDialog(QDialog):
    def __init__(self, store: CredentialStore, defaults: dict | None = None, has_data: bool = False, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New scan")
        self.store = store
        d = defaults or {}
        tabs = QTabWidget()

        # ---- where
        where = QWidget()
        wl = QVBoxLayout(where)
        t1 = QLabel("<b>Address ranges to inventory</b> — every live address in these is checked. "
                    "One per line; CIDR (10.20.0.0/24), single addresses, or ranges (10.20.0.10-60).")
        t1.setWordWrap(True)
        wl.addWidget(t1)
        self.targets = QPlainTextEdit("\n".join(d.get("targets", [])))
        self.targets.setPlaceholderText("# e.g.\n10.20.0.0/24\n10.30.0.0/23   # server VLANs\n192.168.5.10")
        self.targets.setMinimumHeight(110)
        wl.addWidget(self.targets)
        row = QHBoxLayout()
        load = QPushButton("Load from file…")
        load.clicked.connect(self._load_file)
        row.addWidget(load)
        row.addStretch(1)
        wl.addLayout(row)
        f = QFormLayout()
        self.seeds = QLineEdit(" ".join(d.get("seeds", [])))
        self.seeds.setPlaceholderText("optional: core switch / router addresses to start from, e.g. 10.10.0.1 10.10.0.2")
        f.addRow("Start from devices", self.seeds)
        self.scope = QLineEdit(" ".join(d.get("scope", [])))
        self.scope.setPlaceholderText("optional: wider ranges the scan may follow links into (default: the ranges above)")
        f.addRow("May also follow into", self.scope)
        self.exclude = QLineEdit(" ".join(d.get("exclude", [])))
        self.exclude.setPlaceholderText("never send anything here, e.g. OT, medical or partner networks")
        f.addRow("Never touch", self.exclude)
        wl.addLayout(f)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.summary.setObjectName("muted")
        wl.addWidget(self.summary)
        tabs.addTab(where, "Where")

        # ---- credentials
        cw = QWidget()
        cl = QVBoxLayout(cw)
        ct = QLabel("SNMP credentials to try, in order. Read-only is all NetMap needs.")
        ct.setWordWrap(True)
        cl.addWidget(ct)
        self.creds = QListWidget()
        cl.addWidget(self.creds, 1)
        cr = QHBoxLayout()
        manage = QPushButton("Manage credentials…")
        manage.clicked.connect(self._manage)
        cr.addWidget(manage)
        cr.addStretch(1)
        cl.addLayout(cr)
        qf = QFormLayout()
        self.quick = QLineEdit()
        self.quick.setEchoMode(QLineEdit.Password)
        self.quick.setPlaceholderText("try this v2c community too, for this scan only")
        qf.addRow("Extra community", self.quick)
        cl.addLayout(qf)
        tabs.addTab(cw, "Credentials")

        # ---- options
        ow = QWidget()
        ol = QVBoxLayout(ow)
        g1 = QGroupBox("Finding devices")
        g1l = QVBoxLayout(g1)
        self.ping_first = QRadioButton("Ping the ranges first, then query what answers")
        self.probe_all = QRadioButton("Query every address with SNMP (for networks that block ping)")
        (self.probe_all if d.get("probe_all") else self.ping_first).setChecked(True)
        g1l.addWidget(self.ping_first)
        g1l.addWidget(self.probe_all)
        self.follow = QCheckBox("Follow neighbours, routes and gateways to more devices")
        self.follow.setChecked(d.get("max_depth", 6) > 0)
        self.depth = QSpinBox()
        self.depth.setRange(1, 20)
        self.depth.setValue(max(d.get("max_depth", 6), 1))
        dl = QHBoxLayout()
        dl.addWidget(self.follow)
        dl.addWidget(QLabel("up to"))
        dl.addWidget(self.depth)
        dl.addWidget(QLabel("hops"))
        dl.addStretch(1)
        g1l.addLayout(dl)
        self.probe_hosts = QCheckBox("Also try SNMP on every address seen in ARP tables (finds APs, printers, UPSs, servers; slower)")
        self.probe_hosts.setChecked(d.get("probe_hosts", False))
        g1l.addWidget(self.probe_hosts)
        ol.addWidget(g1)
        g2 = QGroupBox("Hosts and names")
        g2l = QVBoxLayout(g2)
        self.sweep = QCheckBox("Ping-sweep every subnet the devices report (counts every live address)")
        self.sweep.setChecked(d.get("sweep", False))
        self.dns = QCheckBox("Name devices and hosts from reverse DNS")
        self.dns.setChecked(d.get("resolve_names", True))
        self.identify = QCheckBox("Identify hosts actively (NetBIOS, mDNS/Bonjour, SSDP/UPnP, web/TLS) — profiles like Cisco ISE")
        self.identify.setChecked(d.get("identify", True))
        self.identify.setToolTip("Sends a few small read-only probes to each host to work out what it is, its OS and its name.\nWorks without Nmap or admin rights.")
        nmap = find_nmap()
        self.fingerprint = QCheckBox("Identify services on live hosts with Nmap" + ("" if nmap else "  (Nmap not found)"))
        self.fingerprint.setChecked(bool(nmap) and d.get("fingerprint", False))
        self.fingerprint.setEnabled(bool(nmap))
        self.fingerprint.setToolTip(nmap or "Install Nmap (nmap.org) to enable service identification and MAC-level ping sweeps")
        self.cisco_vlan = QCheckBox("Read per-VLAN MAC tables on older Cisco IOS switches (community@vlan)")
        self.cisco_vlan.setChecked(d.get("cisco_vlan_fdb", False))
        for w in (self.sweep, self.dns, self.identify, self.fingerprint, self.cisco_vlan):
            g2l.addWidget(w)
        ol.addWidget(g2)
        g3 = QGroupBox("This project already has data")
        g3l = QVBoxLayout(g3)
        self.refresh = QCheckBox("Poll devices already in the project again (update them)")
        self.refresh.setChecked(d.get("refresh", has_data))
        self.retry = QCheckBox("Retry addresses that did not answer last time")
        self.retry.setChecked(d.get("retry_unreachable", False))
        g3l.addWidget(self.refresh)
        g3l.addWidget(self.retry)
        g3.setEnabled(has_data)
        ol.addWidget(g3)
        g4 = QGroupBox("Pace")
        g4l = QFormLayout(g4)
        self.workers = QSpinBox()
        self.workers.setRange(1, 64)
        self.workers.setValue(d.get("workers", 12))
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(0.5, 30)
        self.timeout.setSingleStep(0.5)
        self.timeout.setValue(d.get("timeout", 2.0))
        self.retries = QSpinBox()
        self.retries.setRange(0, 5)
        self.retries.setValue(d.get("retries", 1))
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(d.get("port", 161))
        self.maxpfx = QSpinBox()
        self.maxpfx.setRange(8, 32)
        self.maxpfx.setPrefix("/")
        self.maxpfx.setValue(d.get("sweep_max_prefix", 22))
        g4l.addRow("Devices polled at once", self.workers)
        g4l.addRow("SNMP timeout (seconds)", self.timeout)
        g4l.addRow("SNMP retries", self.retries)
        g4l.addRow("SNMP port", self.port)
        g4l.addRow("Largest range to sweep", self.maxpfx)
        ol.addWidget(g4)
        ol.addStretch(1)
        tabs.addTab(ow, "Options")

        self.bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.bb.button(QDialogButtonBox.Ok).setText("Start scan")
        self.bb.accepted.connect(self._accept)
        self.bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(tabs)
        lay.addWidget(self.bb)
        self._fill_creds(d.get("credential_ids"))
        for w in (self.targets,):
            w.textChanged.connect(self._update_summary)
        for w in (self.seeds, self.scope, self.exclude):
            w.textChanged.connect(self._update_summary)
        self.follow.toggled.connect(self.depth.setEnabled)
        self.depth.setEnabled(self.follow.isChecked())
        self._update_summary()
        self.resize(640, 600)

    # ---- credentials
    def _fill_creds(self, checked_ids=None):
        prev = {self.creds.item(i).data(Qt.UserRole): self.creds.item(i).checkState() for i in range(self.creds.count())}
        self.creds.clear()
        for c in self.store.load():
            it = QListWidgetItem(f"{c.label}  —  {c.describe()}")
            it.setData(Qt.UserRole, c.id)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            if c.id in prev:
                state = prev[c.id]
            elif checked_ids is not None:
                state = Qt.Checked if c.id in checked_ids else Qt.Unchecked
            else:
                state = Qt.Checked if c.enabled else Qt.Unchecked
            it.setCheckState(state)
            self.creds.addItem(it)
        if not self.creds.count():
            it = QListWidgetItem("No saved credentials yet — use “Manage credentials…” or type a community below.")
            it.setFlags(Qt.NoItemFlags)
            self.creds.addItem(it)

    def _manage(self):
        CredentialsDialog(self.store, self).exec()
        self._fill_creds()

    def selected_credentials(self) -> tuple[list[Credential], list[str]]:
        by = {c.id: c for c in self.store.load()}
        out, ids = [], []
        for i in range(self.creds.count()):
            it = self.creds.item(i)
            cid = it.data(Qt.UserRole)
            if cid in by and it.checkState() == Qt.Checked:
                out.append(self.store.to_credential(by[cid]))
                ids.append(cid)
        if self.quick.text():
            out.append(Credential.from_dict({"kind": "v2c", "community": self.quick.text(), "label": "typed in"}))
        return out, ids

    # ---- where
    def _load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load ranges", "", "Text files (*.txt *.csv);;All files (*)")
        if path:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            cur = self.targets.toPlainText().rstrip()
            self.targets.setPlainText((cur + "\n" if cur else "") + text)

    def _values(self):
        targets, bad_t = parse_ranges(self.targets.toPlainText())
        seeds = [s for s in re.split(r"[,\s;]+", self.seeds.text()) if s]
        bad_s = [s for s in seeds if not _is_ip(s)]
        scope, bad_sc = parse_ranges(self.scope.text())
        exclude, bad_x = parse_ranges(self.exclude.text())
        return targets, [s for s in seeds if _is_ip(s)], scope, exclude, bad_t + bad_s + bad_sc + bad_x

    def _update_summary(self):
        targets, seeds, scope, exclude, bad = self._values()
        ok = bool(targets or seeds)
        lines = []
        if targets:
            n = sum(ipaddress.ip_network(t).num_addresses for t in targets)
            lines.append(f"{len(targets)} range(s), {n:,} addresses to check.")
        if seeds:
            lines.append(f"Starting from {len(seeds)} device(s).")
        if ok:
            sc, ex = resolve_scope(targets, scope, exclude)
            if not targets and not scope:
                lines.append("<b>No ranges given:</b> links will be followed anywhere in private address space (10/8, 172.16/12, 192.168/16).")
            else:
                shown = ", ".join(str(n) for n in sc[:6]) + (" …" if len(sc) > 6 else "")
                lines.append(f"Nothing outside {shown} will be contacted.")
            if ex:
                lines.append("Excluded: " + ", ".join(str(n) for n in ex[:6]) + (" …" if len(ex) > 6 else ""))
        else:
            lines.append("Enter at least one address range or starting device.")
        if bad:
            lines.append(f"<span style='color:#dc2626'>Not understood: {', '.join(bad[:6])}</span>")
        self.summary.setText("<br>".join(lines))
        self.bb.button(QDialogButtonBox.Ok).setEnabled(ok and not bad)

    def _accept(self):
        creds, _ = self.selected_credentials()
        if not creds:
            from PySide6.QtWidgets import QMessageBox

            if QMessageBox.question(self, "No credentials", "No SNMP credentials are selected. Scan anyway with the community “public” only?") != QMessageBox.Yes:
                return
        self.accept()

    def request(self) -> tuple[ScanRequest, dict]:
        """The ScanRequest to run, and the settings to remember in the project (no secrets)."""
        targets, seeds, scope, exclude, _ = self._values()
        creds, ids = self.selected_credentials()
        if not creds:
            creds = [Credential.from_dict({"kind": "v2c", "community": "public", "label": "public"})]
        req = ScanRequest(
            seeds=seeds,
            targets=targets,
            scope=scope,
            exclude=exclude,
            credentials=creds,
            probe_all=self.probe_all.isChecked(),
            sweep=self.sweep.isChecked(),
            fingerprint=self.fingerprint.isChecked(),
            probe_hosts=self.probe_hosts.isChecked(),
            resolve_names=self.dns.isChecked(),
            identify=self.identify.isChecked(),
            follow_routes=self.follow.isChecked(),
            follow_gateways=self.follow.isChecked(),
            cisco_vlan_fdb=self.cisco_vlan.isChecked(),
            refresh=self.refresh.isChecked() and self.refresh.isEnabled(),
            retry_unreachable=self.retry.isChecked() and self.retry.isEnabled(),
            max_depth=self.depth.value() if self.follow.isChecked() else 0,
            workers=self.workers.value(),
            timeout=self.timeout.value(),
            retries=self.retries.value(),
            port=self.port.value(),
            sweep_max_prefix=self.maxpfx.value(),
        )
        remember = {
            "targets": targets, "seeds": seeds, "scope": scope, "exclude": exclude, "credential_ids": ids,
            "probe_all": req.probe_all, "sweep": req.sweep, "fingerprint": req.fingerprint, "probe_hosts": req.probe_hosts,
            "resolve_names": req.resolve_names, "identify": req.identify, "cisco_vlan_fdb": req.cisco_vlan_fdb, "max_depth": req.max_depth,
            "workers": req.workers, "timeout": req.timeout, "retries": req.retries, "port": req.port, "sweep_max_prefix": req.sweep_max_prefix,
        }
        return req, remember


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
