"""Application settings: the default scan parameters (so you can raise the sweep cap, change
timeouts, ports, etc. once) and the theme. Stored in QSettings and used as the starting point
for every New Scan."""
from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

# key -> (default, kind) where kind is int/float/bool
SCAN_KEYS = {
    "workers": (12, int), "timeout": (2.0, float), "retries": (1, int), "port": (161, int),
    "sweep_max_prefix": (22, int), "top_ports": (200, int), "max_depth": (6, int),
    "dns": (True, bool), "identify": (True, bool), "port_scan": (True, bool), "os_detect": (False, bool),
    "sweep": (False, bool), "probe_all": (False, bool), "probe_hosts": (False, bool), "cisco_vlan_fdb": (False, bool),
}


def _coerce(v, kind):
    if kind is bool:
        return v in (True, "true", "True", 1, "1")
    try:
        return kind(v)
    except (TypeError, ValueError):
        return v


def scan_defaults() -> dict:
    """The saved default scan settings, with built-in fallbacks."""
    s = QSettings()
    out = {}
    for key, (default, kind) in SCAN_KEYS.items():
        out[key] = _coerce(s.value(f"scan_defaults/{key}", default), kind)
    return out


class PreferencesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        d = scan_defaults()
        self.fields: dict = {}

        pace = QGroupBox("Scan defaults — pace and limits")
        pf = QFormLayout(pace)
        self.fields["workers"] = self._spin(1, 128, d["workers"])
        self.fields["timeout"] = self._dspin(0.2, 60, d["timeout"])
        self.fields["retries"] = self._spin(0, 10, d["retries"])
        self.fields["port"] = self._spin(1, 65535, d["port"])
        self.fields["max_depth"] = self._spin(0, 30, d["max_depth"])
        self.fields["top_ports"] = self._spin(10, 65535, d["top_ports"])
        self.maxpfx = self._spin(8, 32, d["sweep_max_prefix"])
        self.maxpfx.setPrefix("/")
        self.maxpfx_hint = QLabel()
        self.maxpfx.valueChanged.connect(self._hint)
        self.fields["sweep_max_prefix"] = self.maxpfx
        pf.addRow("Devices polled at once", self.fields["workers"])
        pf.addRow("SNMP timeout (seconds)", self.fields["timeout"])
        pf.addRow("SNMP retries", self.fields["retries"])
        pf.addRow("SNMP port", self.fields["port"])
        pf.addRow("Follow neighbours up to (hops)", self.fields["max_depth"])
        pf.addRow("Nmap ports per host", self.fields["top_ports"])
        pf.addRow("Largest subnet to sweep/probe", self.maxpfx)
        pf.addRow("", self.maxpfx_hint)

        steps = QGroupBox("Scan defaults — what runs")
        sf = QVBoxLayout(steps)
        for key, label in (("dns", "Resolve names from reverse DNS"), ("identify", "Actively identify hosts (NetBIOS/mDNS/SSDP/HTTP)"),
                           ("port_scan", "Scan ports & services with Nmap"), ("os_detect", "Detect OS with Nmap (needs admin)"),
                           ("sweep", "Ping-sweep every discovered subnet"), ("probe_all", "Query every address (skip ping)"),
                           ("probe_hosts", "Try SNMP on ARP-learned hosts"), ("cisco_vlan_fdb", "Read Cisco per-VLAN MAC tables")):
            cb = QCheckBox(label)
            cb.setChecked(bool(d[key]))
            self.fields[key] = cb
            sf.addWidget(cb)

        appg = QGroupBox("Application")
        af = QFormLayout(appg)
        self.theme = QComboBox()
        for k, t in (("system", "Follow the OS"), ("light", "Light"), ("dark", "Dark")):
            self.theme.addItem(t, k)
        cur = QSettings().value("ui/theme", "system")
        self.theme.setCurrentIndex(max(0, self.theme.findData(cur)))
        af.addRow("Theme", self.theme)

        note = QLabel("These are the starting values for every New Scan; you can still change them per scan. "
                      "Raising the sweep limit (a lower /prefix) lets you scan bigger ranges like a /16.")
        note.setWordWrap(True)
        note.setObjectName("muted")
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(pace)
        lay.addWidget(steps)
        lay.addWidget(appg)
        lay.addWidget(note)
        lay.addWidget(bb)
        self._hint()
        self.resize(460, 0)

    def _spin(self, lo, hi, val):
        w = QSpinBox()
        w.setRange(lo, hi)
        w.setValue(int(val))
        return w

    def _dspin(self, lo, hi, val):
        w = QDoubleSpinBox()
        w.setRange(lo, hi)
        w.setSingleStep(0.5)
        w.setValue(float(val))
        return w

    def _hint(self):
        n = 2 ** (32 - self.maxpfx.value())
        self.maxpfx_hint.setText(f"allows up to {n:,} addresses per range" + ("  — large!" if self.maxpfx.value() < 20 else ""))
        self.maxpfx_hint.setObjectName("muted")

    def chosen_theme(self) -> str:
        return self.theme.currentData()

    def _save(self):
        s = QSettings()
        for key, (_default, kind) in SCAN_KEYS.items():
            w = self.fields[key]
            val = w.isChecked() if kind is bool else w.value()
            s.setValue(f"scan_defaults/{key}", val)
        s.setValue("ui/theme", self.theme.currentData())
        self.accept()
