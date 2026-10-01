"""The main window: navigation, pages, details, scans and project files."""
from __future__ import annotations

import html
import ipaddress
import logging
import os
import shutil
import subprocess
import sys
import time
from typing import Optional

from PySide6.QtCore import QByteArray, QSettings, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QActionGroup, QDesktopServices, QGuiApplication, QKeySequence, QUndoStack
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QStyle,
    QTabWidget,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..model import Inventory
from ..scan import ScanRequest, nets, resolve_scope
from ..views import PAGES, Snapshot, fmt_duration, fmt_time
from .compare import CompareDialog
from .credentials import CredentialsDialog, CredentialStore
from .dashboard import Dashboard
from .details import DetailsPanel
from .fileutil import ask_save_path, backup_paths, clear_recovery, read_recovery, recovery_paths, rotate_backups, write_recovery_meta
from .icons import app_icon, role_icon
from .jobs import JobRegistry, copy_inventory, run_blocking, with_retry
from .scandialog import ScanDialog
from .table import ACK_PAGES, DataPage
from .theme import apply_theme
from .tools import ToolsPanel
from .topology import TopologyPage
from .undo import AnnotateCommand, ForgetCommand, RelayoutCommand
from .worker import LogBridge, ScanWorker, SnapshotBuilder

log = logging.getLogger("netmap.gui")

FILE_FILTER = "NetMap projects (*.netmap *.json);;All files (*)"
RECOVERY_INTERVAL_MS = 120_000  # while the project is dirty, a recovery copy this often
CLOSE_WAIT_MS = 3000  # how long a close request waits for stopped workers before deferring

NAV = [
    ("overview", "Overview", None),
    ("map", "Topology map", None),
    (None, "Inventory", None),
    ("devices", "Network devices", ("switch", "device")),
    ("hosts", "Hosts", ("workstation", "host")),
    ("subnets", "Subnets & IP addresses", ("subnet", "subnet")),
    ("vlans", "VLANs", None),
    ("links", "Links", None),
    ("dependencies", "Dependencies", None),
    ("interfaces", "Interfaces", None),
    ("hardware", "Hardware", None),
    (None, "Review", None),
    ("findings", "Needs attention", None),
    ("compliance", "Compliance", None),
    ("history", "Scan history", None),
]

PAGE_TITLES = {
    "devices": ("Network devices", "Everything that answered SNMP, plus neighbours it announced that could not be polled."),
    "hosts": ("Hosts", "Addresses seen in ARP and MAC tables, sweeps and LLDP announcements that are not network devices."),
    "subnets": ("Subnets & IP addresses", "Every subnet a device has an address in, with how much of it is in use."),
    "vlans": ("VLANs", ""),
    "links": ("Links", ""),
    "interfaces": ("Interfaces", ""),
    "hardware": ("Hardware", "Chassis, stack members, modules, power supplies, fans and transceivers with serial numbers."),
    "dependencies": ("Dependencies", "Which host talks to which server and on what service, from the connections seen during server inspection."),
    "findings": ("Needs attention", ""),
    "compliance": ("Compliance", "Where the network does not meet common enterprise hardening standards. Everything here is read-only and best-effort - confirm before acting."),
    "history": ("Scan history", ""),
}


def _host_key_lines(result: dict, inv) -> list[str]:
    """Hosts whose SSH host key changed since the last inspection: called out one per line,
    with the message the inspector wrote (it names the known_hosts file). Reads both the
    result summary and the per-host facts, whichever the core provides."""
    out = []
    seen = set()
    for ip, msg in (result.get("host_key_changed") or {}).items() if isinstance(result.get("host_key_changed"), dict) else ():
        seen.add(ip)
        out.append(f"HOST KEY CHANGED for {ip}: {msg}")
    for ip, h in inv.hosts.items():
        if ip in seen:
            continue
        facts = getattr(h, "system", None) or {}
        flag = facts.get("host_key_changed") if isinstance(facts, dict) else None
        if flag:
            out.append(f"HOST KEY CHANGED for {ip}: {flag if isinstance(flag, str) else 'the SSH host key differs from the one recorded earlier'}")
    return out


class MainWindow(QMainWindow):
    def __init__(self, log_path: str = "", recovery_dir: Optional[str] = None):
        super().__init__()
        self.log_path = log_path
        # where the crash-recovery copy lives: beside the log unless told otherwise; None disables it
        self.recovery_dir = recovery_dir if recovery_dir is not None else (os.path.dirname(log_path) if log_path else None)
        self.inv = Inventory()
        self.path: Optional[str] = None
        self.dirty = False
        self.snapshot: Optional[Snapshot] = None
        self.worker: Optional[ScanWorker] = None
        self._sched_timer = None
        self.current_node = ""
        self.store = CredentialStore()
        self.logbridge = LogBridge(self)
        self.logbridge.record.connect(self._on_log)
        self._stale: set[str] = set()
        self._scan_started = 0.0
        # every thread the window starts: one place to ask "busy?", to stop, and to wait on close
        self._jobs = JobRegistry(self)
        self._jobs.idle.connect(self._on_jobs_idle)
        self._closing = False
        self._saving = False
        self._saved_this_session = False  # an explicit or completed-scan save happened (gates autosave of cancelled scans)
        self._live_builder: Optional[SnapshotBuilder] = None
        self._recovery_thread = None
        self.undo_stack = QUndoStack(self)
        self.undo_stack.setUndoLimit(200)
        self.setWindowIcon(app_icon())
        self.setAcceptDrops(True)
        self.setDockOptions(QMainWindow.AnimatedDocks | QMainWindow.AllowTabbedDocks)

        # ---- pages
        self.stack = QStackedWidget()
        self.pages: dict[str, QWidget] = {}
        self.dashboard = Dashboard()
        self.dashboard.navigate.connect(self.navigate)
        self.dashboard.openNode.connect(self.open_node)
        self.dashboard.newScan.connect(self.new_scan)
        self.dashboard.openProject.connect(lambda: self.open_project())
        self.dashboard.openSample.connect(self.open_sample)
        self.dashboard.openPath.connect(lambda p: self.open_project(p))
        self._add_page("overview", self.dashboard)
        self.topology = TopologyPage()
        self.topology.nodeSelected.connect(self.select_node)
        self.topology.nodeActivated.connect(self.open_node)
        self.topology.contextRequested.connect(lambda nid, pos: self.node_menu(nid, pos, from_map=True))
        self.topology.layoutChanged.connect(lambda: self.set_dirty(True))
        self.topology.layoutDiscarded.connect(lambda key, old: self.undo_stack.push(RelayoutCommand(self, key, old)))
        self._add_page("map", self.topology)
        for key, (cols, _fn) in PAGES.items():
            title, hint = PAGE_TITLES.get(key, (key.title(), ""))
            page = DataPage(key, title, cols)
            if hint:
                page.heading.setToolTip(hint)
            page.nodeSelected.connect(self.select_node)
            page.nodeActivated.connect(self.open_node)
            page.contextRequested.connect(lambda row, pos, key=key: self._row_menu(row, pos, key))
            page.showAcknowledgedChanged.connect(lambda _on, key=key: self._load_page(key))
            self._add_page(key, page)

        self.nav = QTreeWidget()
        self.nav.setObjectName("nav")
        self.nav.setHeaderHidden(True)
        self.nav.setRootIsDecorated(False)
        self.nav.setIndentation(10)
        self.nav.setIconSize(QSize(18, 18))
        self.nav_items: dict[str, QTreeWidgetItem] = {}
        st = self.style()
        std = {"overview": QStyle.SP_FileDialogInfoView, "map": QStyle.SP_DriveNetIcon, "vlans": QStyle.SP_FileDialogListView,
               "links": QStyle.SP_ArrowRight, "interfaces": QStyle.SP_FileDialogDetailedView, "hardware": QStyle.SP_ComputerIcon,
               "dependencies": QStyle.SP_FileDialogContentsView, "findings": QStyle.SP_MessageBoxWarning, "compliance": QStyle.SP_DialogApplyButton, "history": QStyle.SP_BrowserReload}
        for key, title, icon in NAV:
            it = QTreeWidgetItem([title])
            if key is None:
                it.setFlags(Qt.NoItemFlags)
                f = it.font(0)
                f.setBold(True)
                f.setPointSizeF(f.pointSizeF() * 0.9)
                it.setFont(0, f)
            else:
                it.setData(0, Qt.UserRole, key)
                it.setData(0, Qt.UserRole + 1, title)
                if icon:
                    it.setIcon(0, role_icon(*icon))
                elif key in std:
                    it.setIcon(0, st.standardIcon(std[key]))
                self.nav_items[key] = it
            self.nav.addTopLevelItem(it)
        self.nav.currentItemChanged.connect(lambda cur, _: cur and cur.data(0, Qt.UserRole) and self.show_page(cur.data(0, Qt.UserRole)))
        # wide enough for the longest entry with a five-digit count, so nothing is elided
        fm = self.nav.fontMetrics()
        longest = max(fm.horizontalAdvance(f"{title}  (99,999)") for key, title, _ in NAV if key)
        nav_w = longest + self.nav.iconSize().width() + self.nav.indentation() + 30
        self.nav.setMinimumWidth(max(190, nav_w))

        split = QSplitter()
        split.addWidget(self.nav)
        split.addWidget(self.stack)
        split.setStretchFactor(1, 1)
        split.setSizes([max(210, nav_w), 1000])
        split.setChildrenCollapsible(False)
        self.setCentralWidget(split)
        self.splitter = split

        # ---- docks
        self.details = DetailsPanel()
        self.details.showOnMap.connect(self.show_on_map)
        self.details.openNode.connect(self.open_node)
        self.details.annotationChanged.connect(self.annotate)
        self.details.actionRequested.connect(self.node_action)
        self.details_dock = self._dock("Details", self.details, Qt.RightDockWidgetArea, "details")
        self.details_dock.setMinimumWidth(280)

        act = QWidget()
        al = QVBoxLayout(act)
        al.setContentsMargins(6, 4, 6, 4)
        row = QHBoxLayout()
        self.scan_phase = QLabel("No scan running.")
        self.scan_stats = QLabel("")
        self.scan_stats.setObjectName("muted")
        self.scan_bar = QProgressBar()
        self.scan_bar.setRange(0, 0)
        self.scan_bar.setMaximumWidth(180)
        self.scan_bar.setTextVisible(False)
        self.scan_bar.hide()
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setToolTip("Stop the running scan, capture or inspection; what was found so far is kept")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.hide()
        row.addWidget(self.scan_phase)
        row.addWidget(self.scan_bar)
        row.addWidget(self.scan_stats, 1)
        row.addWidget(self.stop_btn)
        al.addLayout(row)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(20000)
        from PySide6.QtGui import QFontDatabase

        self.log_view.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        al.addWidget(self.log_view, 1)
        self.activity_dock = self._dock("Activity", act, Qt.BottomDockWidgetArea, "activity")
        self.tools = ToolsPanel(self.store, self.scope_check, jobs=self._jobs)
        self.tools_dock = self._dock("Tools", self.tools, Qt.BottomDockWidgetArea, "tools")
        self.tabifyDockWidget(self.activity_dock, self.tools_dock)
        self.activity_dock.raise_()

        self._build_actions()
        self.status_stats = QLabel()
        self.statusBar().addPermanentWidget(self.status_stats)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(700)
        self._refresh_timer.timeout.connect(lambda: self.refresh(keep_details=True))
        self._jobs.changed.connect(self._update_job_chrome)
        self._recovery_timer = QTimer(self)
        self._recovery_timer.setInterval(RECOVERY_INTERVAL_MS)
        self._recovery_timer.timeout.connect(self._recovery_tick)
        if self.recovery_dir:
            self._recovery_timer.start()

        self._restore_window()
        self.set_inventory(Inventory(), None)
        self.nav.setCurrentItem(self.nav_items["overview"])

    # ================================================================ building blocks
    def _add_page(self, key, w):
        self.pages[key] = w
        self.stack.addWidget(w)

    def _dock(self, title, widget, area, name) -> QDockWidget:
        d = QDockWidget(title, self)
        d.setObjectName(f"dock_{name}")
        d.setWidget(widget)
        d.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetClosable | QDockWidget.DockWidgetFloatable)
        self.addDockWidget(area, d)
        return d

    def _act(self, menu, text, slot=None, shortcut=None, tip="", icon=None) -> QAction:
        a = QAction(text, self)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if tip:
            a.setStatusTip(tip)
            a.setToolTip(tip)
        if icon is not None:
            a.setIcon(icon)
        if slot:
            a.triggered.connect(slot)
        if menu is not None:
            menu.addAction(a)
        return a

    def _build_actions(self):
        st = self.style()
        mb = self.menuBar()
        fm = mb.addMenu("&File")
        self.a_new = self._act(fm, "&New project", self.new_project, QKeySequence.New, icon=st.standardIcon(QStyle.SP_FileIcon))
        self.a_open = self._act(fm, "&Open project…", lambda: self.open_project(), QKeySequence.Open, icon=st.standardIcon(QStyle.SP_DialogOpenButton))
        self.recent_menu = fm.addMenu("Open &recent")
        self.recent_menu.aboutToShow.connect(self._fill_recent)
        self.a_save = self._act(fm, "&Save", self.save, QKeySequence.Save, icon=st.standardIcon(QStyle.SP_DialogSaveButton))
        self._act(fm, "Save &as…", self.save_as, QKeySequence.SaveAs)
        self.a_revert = self._act(fm, "Re&vert to saved", self.revert_to_saved, tip="Throw away unsaved changes and reload the project file from disk")
        self._act(fm, "Project &properties…", self.project_properties)
        im = fm.addMenu("&Import")
        self._act(im, "DHCP leases / scopes…", self.import_dhcp, tip="Import a DHCP export (dhcpd.leases, Kea or Windows CSV) to name hosts and mark scopes")
        self._act(im, "VMware vCenter / ESXi…", self.import_vmware, tip="Read-only vSphere discovery: ESXi hosts, VMs, guest IPs/OS, port groups")
        fm.addSeparator()
        ex = fm.addMenu("&Export")
        self._act(ex, "Spreadsheet workbook (.xlsx)…", self.export_xlsx, "Ctrl+E", "The whole inventory, one sheet per list")
        self._act(ex, "CSV files…", self.export_csv)
        ex.addSeparator()
        self._act(ex, "Diagram (.drawio, opens in diagrams.net)…", self.export_drawio, tip="Physical and logical pages, with your layout")
        self._act(ex, "Map as PDF (A3)…", lambda: self.export_map("pdf"))
        self._act(ex, "Map as SVG…", lambda: self.export_map("svg"))
        self._act(ex, "Map as PNG…", lambda: self.export_map("png"))
        self._act(ex, "Interactive HTML map…", self.export_html, tip="A single offline web page with the map; opens in any browser")
        ex.addSeparator()
        self._act(ex, "GraphML (yEd, Gephi)…", lambda: self.export_graph("graphml"))
        self._act(ex, "Graphviz DOT…", lambda: self.export_graph("dot"))
        self.topology.export_menu.addActions(ex.actions()[3:7])
        self.a_print = self._act(fm, "&Print map…", self.print_map, QKeySequence.Print)
        self.topology.export_menu.addAction(self.a_print)
        fm.addSeparator()
        self._act(fm, "E&xit", self.close, QKeySequence.Quit)

        em = mb.addMenu("&Edit")
        self.a_undo = self._act(em, "&Undo", self.undo, "Ctrl+Z", "Undo the last edit: a note, a removal, a Re-arrange")
        self.a_redo = self._act(em, "&Redo", self.redo, "Ctrl+Shift+Z")
        self.a_redo.setShortcuts([QKeySequence("Ctrl+Shift+Z"), QKeySequence("Ctrl+Y")])
        self.a_undo.setEnabled(False)
        self.a_redo.setEnabled(False)
        self.undo_stack.canUndoChanged.connect(self.a_undo.setEnabled)
        self.undo_stack.canRedoChanged.connect(self.a_redo.setEnabled)
        self.undo_stack.undoTextChanged.connect(lambda t: self.a_undo.setText(f"&Undo {t}" if t else "&Undo"))
        self.undo_stack.redoTextChanged.connect(lambda t: self.a_redo.setText(f"&Redo {t}" if t else "&Redo"))
        em.addSeparator()
        self._act(em, "&Find…", self.focus_filter, QKeySequence.Find)
        self._act(em, "Copy selected rows", self._copy_rows)
        em.addSeparator()
        self._act(em, "&SNMP credentials…", self.manage_credentials)
        em.addSeparator()
        self._act(em, "&Preferences…", self.preferences, QKeySequence.Preferences)

        sm = mb.addMenu("&Scan")
        self.a_scan = self._act(sm, "&New scan…", self.new_scan, "Ctrl+R", "Discover and inventory devices", st.standardIcon(QStyle.SP_MediaPlay))
        self.a_rescan = self._act(sm, "&Rescan known devices", self.rescan_all, "F5", "Poll every device in the project again and follow any new links", st.standardIcon(QStyle.SP_BrowserReload))
        self.a_schedule = self._act(sm, "Schedule &automatic rescans…", self.schedule_rescans, tip="Re-poll every device on a repeating interval while NetMap is open")
        self.a_schedule.setCheckable(True)
        self.a_stop = self._act(sm, "&Stop scan", self.stop_scan, "Esc", icon=st.standardIcon(QStyle.SP_MediaStop))
        self.a_stop.setEnabled(False)
        sm.addSeparator()
        self._act(sm, "SNMP &credentials…", self.manage_credentials)

        vm = mb.addMenu("&View")
        for i, (key, title, _) in enumerate(k for k in NAV if k[0]):
            self._act(vm, title, lambda _=False, key=key: self.navigate(key), f"Ctrl+{i + 1}" if i < 9 else None)
        vm.addSeparator()
        vm.addAction(self.details_dock.toggleViewAction())
        vm.addAction(self.activity_dock.toggleViewAction())
        vm.addAction(self.tools_dock.toggleViewAction())
        vm.addSeparator()
        theme = vm.addMenu("Theme")
        grp = QActionGroup(self)
        cur = QSettings().value("ui/theme", "system")
        for key, title in (("system", "Follow Windows"), ("light", "Light"), ("dark", "Dark")):
            a = self._act(theme, title, lambda _=False, key=key: self.set_theme(key))
            a.setCheckable(True)
            a.setChecked(cur == key)
            grp.addAction(a)

        tm = mb.addMenu("&Tools")
        self._act(tm, "Ping / traceroute / DNS / SNMP test", lambda: (self.tools_dock.show(), self.tools_dock.raise_(), self.tools.target.setFocus()))
        self._act(tm, "&Query / search assets…", self.query_console, "Ctrl+Shift+F", "Search the inventory with a query language")
        self._act(tm, "Start &API server…", self.start_api, tip="Serve a read-only REST API of this project on localhost")
        self._act(tm, "&Compare with another scan…", lambda: self.compare())
        self.a_compare_prev = self._act(tm, "Compare with the &previous saved version", self.compare_previous,
                                        tip="Diff this project against the backup made the last time it was saved (name.netmap.bak1)")
        self._act(tm, "Check against an &asset list…", self.reconcile, tip="Compare what was found with a CSV/.xlsx list of devices you were given")
        self._act(tm, "&Inspect servers (SSH / WinRM)…", self.inspect_servers, tip="Collect OS, hardware, software, services and connections from hosts you have login for")
        self._act(tm, "Capture device &configs (SSH)…", self.capture_configs, tip="Log in read-only and save each device's running-config, to read and diff over time")
        self._act(tm, "&Listen for syslog / SNMP traps…", self.listen_events, tip="Watch messages devices send while you are on site")

        hm = mb.addMenu("&Help")
        self._act(hm, "&Quick guide", self.quick_guide, QKeySequence.HelpContents)
        self._act(hm, "Explore the &sample network", self.open_sample, tip="A simulated campus network, to see what NetMap does before scanning")
        self._act(hm, "Check for &updates…", self.check_updates)
        self._act(hm, "Open the log folder", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(self.log_path) or ".")))
        self._act(hm, "&About NetMap", self.about)

        tb = self.addToolBar("Main")
        tb.setObjectName("toolbar_main")
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        tb.setIconSize(QSize(18, 18))
        tb.addAction(self.a_new)
        tb.addAction(self.a_open)
        tb.addAction(self.a_save)
        tb.addSeparator()
        tb.addAction(self.a_scan)
        tb.addAction(self.a_rescan)
        tb.addAction(self.a_stop)
        tb.addSeparator()
        xl = QAction("Export to spreadsheet", self)
        xl.setIcon(st.standardIcon(QStyle.SP_DialogApplyButton))
        xl.triggered.connect(self.export_xlsx)
        tb.addAction(xl)
        tb.addSeparator()
        self.global_find = QLineEdit()
        self.global_find.setPlaceholderText("Find a device, host, IP, MAC…")
        self.global_find.setClearButtonEnabled(True)
        self.global_find.setMaximumWidth(280)
        self.global_find.returnPressed.connect(self.global_search)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)
        tb.addWidget(self.global_find)

    # ================================================================ project
    def set_inventory(self, inv: Inventory, path: Optional[str]):
        self.details.flush()
        self.undo_stack.clear()
        self.inv = inv
        self.path = path
        self.current_node = ""
        self.details.clear()
        self.topology.focus = None
        self.topology.hidden_nodes.clear()
        self.topology.banner.hide()
        self.set_dirty(False)
        self.refresh()

    def project_name(self) -> str:
        if self.inv.project.get("name"):
            return self.inv.project["name"]
        if self.path:
            return os.path.splitext(os.path.basename(self.path))[0]
        return "Untitled project"

    def set_dirty(self, dirty: bool):
        self.dirty = dirty
        self.setWindowModified(dirty)
        self.setWindowTitle(f"{self.project_name()}[*] — NetMap")

    def _flush_pending_edits(self) -> None:
        """Debounced edits (a note being typed, a node just dragged) go into the inventory now."""
        self.details.flush()
        self.topology.flush_positions()

    def busy(self) -> bool:
        """True while any job that reads or writes the inventory is running."""
        return self._jobs.busy()

    def _busy_guard(self, title: str = "Busy") -> bool:
        """Show why an action must wait and return True when it must."""
        if not self._jobs.busy():
            return False
        QMessageBox.information(self, title, self._jobs.wait_message())
        return True

    def maybe_save(self) -> bool:
        self._flush_pending_edits()
        if not self.dirty:
            return True
        if not self.inv.devices and not self.inv.hosts and not self.inv.annotations:
            return True
        r = QMessageBox.question(self, "Save changes?", f"Save changes to “{self.project_name()}”?",
                                 QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel, QMessageBox.Save)
        if r == QMessageBox.Cancel:
            return False
        if r == QMessageBox.Save:
            return self.save()
        return True

    def new_project(self):
        if self._busy_guard():
            return
        if self.maybe_save():
            self.set_inventory(Inventory(), None)
            self.navigate("overview")

    def open_project(self, path: Optional[str] = None):
        if self._busy_guard():
            return
        if not self.maybe_save():
            return
        if not path:
            start = QSettings().value("ui/last_dir", os.path.expanduser("~"))
            path, _ = QFileDialog.getOpenFileName(self, "Open project", start, FILE_FILTER)
            if not path:
                return
        try:
            inv = Inventory.load(path)
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Could not open", f"{path}\n\n{type(e).__name__}: {e}")
            return
        QSettings().setValue("ui/last_dir", os.path.dirname(os.path.abspath(path)))
        self._add_recent(path)
        self.set_inventory(inv, os.path.abspath(path))
        self.statusBar().showMessage(f"Opened {path}", 5000)

    def open_sample(self):
        """The simulated campus that ships with the app. Opened without a path, so saving
        asks where to put it instead of writing into the program folder."""
        if self._busy_guard() or not self.maybe_save():
            return
        from ..util import resource_path

        try:
            inv = Inventory.load(resource_path("data", "sample-campus.netmap"))
        except OSError as e:
            QMessageBox.warning(self, "Sample not found", str(e))
            return
        self.set_inventory(inv, None)
        self.navigate("overview")
        self.statusBar().showMessage("Opened the sample network (simulated). Save it anywhere to keep changes.", 8000)

    def save(self) -> bool:
        if not self.path or not self.path.lower().endswith((".netmap", ".json")):
            return self.save_as()
        return self._write(self.path)

    def save_as(self) -> bool:
        start = self.path or os.path.join(QSettings().value("ui/last_dir", os.path.expanduser("~")), f"{self.project_name()}.netmap")
        path, _ = QFileDialog.getSaveFileName(self, "Save project", start, FILE_FILTER)
        if not path:
            return False
        if not os.path.splitext(path)[1]:
            path += ".netmap"
        ok = self._write(path)
        if ok:
            self.path = os.path.abspath(path)
            self._add_recent(path)
            QSettings().setValue("ui/last_dir", os.path.dirname(self.path))
            self.set_dirty(False)
        return ok

    def _write(self, path: str) -> bool:
        """Save the project to `path`: pending edits first, then a rotating backup of the file
        being overwritten, then the write itself - serialised on a thread while the window
        keeps painting behind a wait cursor. Returns True when the file is on disk."""
        if self._saving:
            return False
        self._flush_pending_edits()
        inv = self.inv
        self._saving = True
        try:
            def work():
                rotate_backups(path)
                with_retry(lambda: inv.save(path))

            run_blocking(self, "Saving the project", work)
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Could not save", f"{path}\n\n{type(e).__name__}: {e}")
            return False
        finally:
            self._saving = False
        if inv is self.inv:
            self.set_dirty(False)
        self._saved_this_session = True
        if self.recovery_dir:
            clear_recovery(self.recovery_dir)
        self.statusBar().showMessage(f"Saved {path}", 4000)
        return True

    def revert_to_saved(self):
        """Throw away unsaved changes and reload the project from its file."""
        if self._busy_guard():
            return
        if not self.path or not os.path.exists(self.path):
            QMessageBox.information(self, "Revert to saved", "This project has not been saved to a file yet.")
            return
        self._flush_pending_edits()
        if self.dirty and QMessageBox.question(self, "Revert to saved",
                                               f"Discard the unsaved changes and reload “{os.path.basename(self.path)}” from disk?") != QMessageBox.Yes:
            return
        try:
            inv = Inventory.load(self.path)
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Could not open", f"{self.path}\n\n{type(e).__name__}: {e}")
            return
        self.set_inventory(inv, self.path)
        self.statusBar().showMessage(f"Reverted to {self.path}", 5000)

    # ---- crash recovery
    def _recovery_tick(self):
        """Every couple of minutes while dirty: a copy of the project into the data folder,
        written on a thread. Cleared by a real save and by a clean close."""
        if not self.recovery_dir or not self.dirty or self._saving or self._closing:
            return
        if not (self.inv.devices or self.inv.hosts or self.inv.annotations):
            return
        if self._recovery_thread is not None and self._recovery_thread.isRunning():
            return
        import json
        from PySide6.QtCore import QThread

        inv = self.inv
        path, _meta = recovery_paths(self.recovery_dir)
        origin, name = self.path, self.project_name()

        class Save(QThread):
            def run(self_):
                try:
                    text = with_retry(lambda: json.dumps(inv.to_dict(), default=list))
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path + ".tmp", "w", encoding="utf-8") as f:
                        f.write(text)
                    os.replace(path + ".tmp", path)
                    write_recovery_meta(os.path.dirname(path), origin, name)
                except Exception:  # noqa: BLE001
                    log.exception("recovery copy failed")

        self._recovery_thread = Save(self)
        self._jobs.add(self._recovery_thread, "the recovery copy", blocking=False)
        self._recovery_thread.start()

    def offer_recovery(self) -> bool:
        """At start-up: if a recovery copy exists that is newer than the file it came from
        (or came from an unsaved project), offer to restore it. True if restored."""
        if not self.recovery_dir:
            return False
        rec = read_recovery(self.recovery_dir)
        if not rec:
            return False
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(rec["saved"]))
        r = QMessageBox.question(self, "Restore unsaved work?",
                                 f"NetMap did not close cleanly. A recovery copy of “{rec['name']}” from {when} has changes "
                                 f"that were never saved{' to ' + rec['origin'] if rec['origin'] else ''}.\n\nRestore it?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if r != QMessageBox.Yes:
            clear_recovery(self.recovery_dir)
            return False
        try:
            inv = Inventory.load(rec["path"])
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Could not restore", f"{rec['path']}\n\n{type(e).__name__}: {e}")
            clear_recovery(self.recovery_dir)
            return False
        origin = rec["origin"] if rec["origin"] and os.path.exists(rec["origin"]) else None
        self.set_inventory(inv, origin)
        self.set_dirty(True)
        self.statusBar().showMessage("Restored the recovery copy - save it to keep it.", 10000)
        return True

    def _add_recent(self, path):
        s = QSettings()
        rec = [p for p in (s.value("ui/recent") or []) if isinstance(p, str) and os.path.abspath(p) != os.path.abspath(path)]
        s.setValue("ui/recent", [os.path.abspath(path)] + rec[:9])

    def _fill_recent(self):
        self.recent_menu.clear()
        rec = [p for p in (QSettings().value("ui/recent") or []) if isinstance(p, str)]
        for p in rec:
            a = self.recent_menu.addAction(p, lambda p=p: self.open_project(p))
            a.setEnabled(os.path.exists(p))
        if not rec:
            self.recent_menu.addAction("(none)").setEnabled(False)

    def project_properties(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Project properties")
        name = QLineEdit(self.inv.project.get("name", ""))
        name.setPlaceholderText(self.project_name())
        desc = QPlainTextEdit(self.inv.project.get("description", ""))
        desc.setPlaceholderText("e.g. Acme head office network, handed over 2026-09-30. Contact: …")
        f = QFormLayout(dlg)
        f.addRow("Name", name)
        f.addRow("Description", desc)
        info = QLabel(f"File: {self.path or '(not saved yet)'}<br>{self.inv.summary()}<br>{len(self.inv.history)} scan(s), "
                      f"{len(self.inv.annotations)} documented item(s)")
        info.setObjectName("muted")
        f.addRow(info)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        f.addRow(bb)
        dlg.resize(460, 0)
        if dlg.exec():
            self.inv.project["name"] = name.text().strip()
            self.inv.project["description"] = desc.toPlainText().strip()
            self.set_dirty(True)
            self.dashboard.set_snapshot(self.snapshot, self.project_name())

    # ================================================================ views
    def refresh(self, keep_details: bool = False, live: bool = False):
        """Rebuild everything derived from the inventory; pages not on screen refresh when shown.

        `live` is a refresh from a scan in progress: the map is not rebuilt under the user
        while they look at it (it would re-lay itself out every few seconds); it catches up
        when the scan ends or when they ask.
        """
        t0 = time.time()
        self.snapshot = Snapshot(self.inv)
        self._stale = set(self.pages)
        cur = self.current_page()
        if cur and not (live and cur == "map" and self.topology.nodes):
            self._load_page(cur)
        elif cur == "map":
            self.topology.info.setText("A scan is running: the map updates when it finishes, or when you come back to this page.")
        self._update_nav_counts()
        self._update_status()
        if self.current_node and not keep_details:
            if self.current_node in self.snapshot.g or self.current_node in self.inv.devices or self.current_node in self.inv.hosts:
                self.details.show_node(self.snapshot, self.current_node, force=True)
            else:
                self.details.clear()
        elif self.current_node and keep_details:
            self.details.snapshot = self.snapshot
        self._refresh_cost = time.time() - t0
        log.debug("refresh took %.2fs", self._refresh_cost)

    def current_page(self) -> str:
        w = self.stack.currentWidget()
        for k, p in self.pages.items():
            if p is w:
                return k
        return ""

    def _load_page(self, key: str):
        s = self.snapshot
        if s is None:
            return
        w = self.pages[key]
        if key == "overview":
            w.set_recent([p for p in (QSettings().value("ui/recent") or []) if isinstance(p, str) and os.path.exists(p)][:6])
            w.set_snapshot(s, self.project_name())
        elif key == "map":
            w.set_data(self.inv, s.g, keep_view=bool(w.nodes))
        else:
            w.set_rows(self._page_rows(key, PAGES[key][1](s)))
        self._stale.discard(key)

    @staticmethod
    def finding_key(page: str, row: dict) -> str:
        """A stable key for a Needs-attention / Compliance row across scans: its category
        and item (the detail text may carry counts that change)."""
        return f"{page}:{row.get('category', '')}|{row.get('item', '')}"

    def _page_rows(self, key: str, rows: list) -> list:
        """Rows for a page after presentation rules: acknowledged findings are marked and,
        unless the page shows them, dropped."""
        if key not in ACK_PAGES:
            return rows
        page = self.pages[key]
        show = page.show_ack.isChecked()
        out = []
        for r in rows:
            ack = self.inv.note(self.finding_key(key, r)).get("acknowledged")
            if ack:
                if not show:
                    continue
                r["_ack"] = True
            out.append(r)
        return out

    def acknowledge(self, page: str, row: dict, on: bool = True):
        """Mark a finding as seen and accepted (kept in the project, hidden by default)."""
        key = self.finding_key(page, row)
        self.inv.annotate(key, acknowledged=time.time() if on else "", acknowledged_item=row.get("item", "") if on else "")
        self.set_dirty(True)
        self._stale.add(page)
        if self.current_page() == page:
            self._load_page(page)

    def show_page(self, key: str):
        w = self.pages.get(key)
        if w is None:
            return
        self.stack.setCurrentWidget(w)
        if key in self._stale:
            self._load_page(key)
        it = self.nav_items.get(key)
        if it is not None and self.nav.currentItem() is not it:
            self.nav.blockSignals(True)
            self.nav.setCurrentItem(it)
            self.nav.blockSignals(False)

    def navigate(self, key: str, filter_text: str = ""):
        self.show_page(key)
        w = self.pages.get(key)
        if isinstance(w, DataPage):
            w.filter.setText(filter_text)
            w._filter_timer.stop()
            w._on_filter(filter_text)

    def _update_nav_counts(self):
        s = self.snapshot
        inv = self.inv
        counts = {
            "devices": len(inv.devices) + len(s.stubs),
            "hosts": sum(1 for ip in inv.hosts if ip not in inv.ip_to_device),
            "subnets": len(inv.subnets),
            "vlans": len(s.vlans),
            "links": len(s.links),
            "interfaces": sum(len(d.interfaces) for d in inv.devices.values()),
            "findings": None,
            "history": len(inv.history),
        }
        for key, it in self.nav_items.items():
            title = it.data(0, Qt.UserRole + 1)
            n = counts.get(key)
            it.setText(0, f"{title}  ({n:,})" if n else title)

    def _update_status(self):
        inv = self.inv
        last = inv.history[-1] if inv.history else None
        txt = f"{len(inv.devices)} devices · {sum(1 for ip in inv.hosts if ip not in inv.ip_to_device)} hosts · {len(inv.subnets)} subnets"
        if last:
            txt += f"   |   last scan {fmt_time(last.get('started'))}"
        self.status_stats.setText(txt)

    # ================================================================ selection
    def select_node(self, node_id: str):
        if not node_id or self.snapshot is None:
            return
        self.current_node = node_id
        self.details.show_node(self.snapshot, node_id)

    def open_node(self, node_id: str):
        if not node_id or self.snapshot is None:
            return
        self.select_node(node_id)
        self.details_dock.show()
        self.details_dock.raise_()
        cur = self.current_page()
        page = {"device": "devices", "host": "hosts", "subnet": "subnets"}.get(self.snapshot.kind(node_id))
        if node_id.startswith("vlan:"):
            page = "vlans"
        w = self.pages.get(cur)
        if isinstance(w, DataPage) and not w.select_ids([node_id]) and page and cur not in ("map", "overview"):
            self.show_page(page)
            p = self.pages[page]
            if not p.select_ids([node_id]):
                p.filter.clear()
                p.select_ids([node_id])

    def trace_path(self, node_id: str):
        """Highlight the network path from the core to this node on the map."""
        from .. import paths

        if self.snapshot is None:
            return
        p = paths.path_to(self.inv, self.snapshot.g, node_id)
        if not p.ok or len(p.hops) < 2:
            self.statusBar().showMessage("No path to trace (it may be the core itself, or not reachable in the collected topology).", 6000)
            return
        self.show_page("map")
        name = self.snapshot.name(node_id)
        if not self.topology.show_path(p.nodes(), f"Path from <b>{self.snapshot.name(p.origin)}</b> to <b>{name}</b> ({len(p.hops)} hops). Right-click ▸ Details on any hop."):
            self.statusBar().showMessage("Could not draw the path on the current view.", 5000)

    def show_on_map(self, node_id: str):
        self.show_page("map")
        if not self.topology.ensure_visible(node_id):
            self.statusBar().showMessage("That item is not on the map.", 4000)

    def global_search(self):
        q = self.global_find.text().strip().lower()
        if not q or self.snapshot is None:
            return
        s = self.snapshot
        best = None
        for n, a in s.g.nodes(data=True):
            hay = " ".join(str(a.get(k, "")) for k in ("label", "ip", "mac", "hostname", "serial", "vendor", "model")).lower() + " " + n.lower()
            if q == n.lower() or q == str(a.get("label", "")).lower() or q == str(a.get("ip", "")).lower():
                best = n
                break
            if best is None and q in hay:
                best = n
        if best is None:
            for d in self.inv.devices.values():
                if any(q == m for m in d.macs) or q in d.serial.lower():
                    best = d.id
                    break
        if best is None:
            self.statusBar().showMessage(f"Nothing matches “{q}”.", 4000)
            return
        self.open_node(best)
        if self.current_page() == "map":
            self.topology.ensure_visible(best)

    def focus_filter(self):
        w = self.stack.currentWidget()
        if isinstance(w, DataPage):
            w.filter.setFocus()
            w.filter.selectAll()
        elif w is self.topology:
            self.topology.search.setFocus()
        else:
            self.global_find.setFocus()

    def _copy_rows(self):
        w = self.stack.currentWidget()
        if isinstance(w, DataPage):
            w.copy_selection()

    # ================================================================ documentation
    def undo(self):
        """Ctrl+Z: a note still being typed lands first, then the last edit is undone."""
        self._flush_pending_edits()
        if self.undo_stack.canUndo():
            self.undo_stack.undo()

    def redo(self):
        self._flush_pending_edits()
        if self.undo_stack.canRedo():
            self.undo_stack.redo()

    def annotate(self, node_id: str, fields: dict):
        before = dict(self.inv.note(node_id))
        after = self.inv.annotate(node_id, **fields)
        if before != after:
            self.set_dirty(True)
            self._refresh_timer.start()
            self.undo_stack.push(AnnotateCommand(self, node_id, before, after))

    # ================================================================ menus / actions
    def node_ip(self, node_id: str) -> str:
        if self.snapshot is not None and node_id in self.snapshot.g:
            ip = self.snapshot.g.nodes[node_id].get("ip")
            if ip:
                return ip
        try:
            ipaddress.ip_address(node_id)
            return node_id
        except ValueError:
            return ""

    def _row_menu(self, row: dict, pos, page: str = ""):
        if not row:
            return
        nid = row.get("_id") or ""
        if row.get("_kind") == "history":
            return
        if page in ACK_PAGES:
            row = dict(row)
            row["_page"] = page
        self.node_menu(nid, pos, extra_row=row)

    def node_menu(self, node_id: str, pos, from_map: bool = False, extra_row: Optional[dict] = None):
        page = (extra_row or {}).get("_page", "")
        if not node_id and not page:
            return
        s = self.snapshot
        kind = s.kind(node_id) if s and node_id else ""
        m = QMenu(self)
        if page:
            if extra_row.get("_ack"):
                m.addAction("Un-acknowledge (show again)", lambda: self.acknowledge(page, extra_row, False))
            else:
                m.addAction("Acknowledge (hide from this list)", lambda: self.acknowledge(page, extra_row, True))
            m.addSeparator()
            if not node_id:
                m.exec(pos)
                return
        m.addAction("Details", lambda: self.open_node(node_id))
        if s and node_id in s.g:
            if not from_map:
                m.addAction("Show on map", lambda: self.show_on_map(node_id))
            fm = m.addMenu("Focus the map here")
            for hops in (1, 2, 3):
                fm.addAction(f"{hops} hop{'s' if hops > 1 else ''}", lambda h=hops: (self.show_page("map"), self.topology.focus_on(node_id, h)))
            m.addAction("Trace path to here", lambda: self.trace_path(node_id))
            if from_map:
                m.addAction("Hide from map", lambda: self.topology.hide_node(node_id))
        other = (extra_row or {}).get("_other")
        if other:
            m.addAction(f"Details of {s.name(other) if s else other}", lambda: self.open_node(other))
        ip = self.node_ip(node_id)
        if ip and kind in ("device", "host"):
            m.addSeparator()
            om = m.addMenu("Open")
            om.addAction(f"https://{ip}", lambda: self.node_action("https", node_id))
            om.addAction(f"http://{ip}", lambda: self.node_action("http", node_id))
            om.addAction("SSH session", lambda: self.node_action("ssh", node_id))
            m.addAction("Ping", lambda: self.node_action("ping", node_id))
            m.addAction("Traceroute", lambda: self.node_action("traceroute", node_id))
        if node_id in self.inv.devices:
            m.addAction("Rescan this device", lambda: self.node_action("rescan", node_id))
            m.addAction("Capture config (SSH)…", lambda: self.capture_configs(node_id))
        if node_id in self.inv.subnets:
            m.addSeparator()
            m.addAction("Find every live address in this subnet", lambda: self.sweep_subnet(node_id))
        m.addSeparator()
        cm = m.addMenu("Copy")
        if ip:
            cm.addAction("Address", lambda: QGuiApplication.clipboard().setText(ip))
        if s:
            cm.addAction("Name", lambda: QGuiApplication.clipboard().setText(s.name(node_id)))
        a = s.g.nodes[node_id] if s and node_id in s.g else {}
        if a.get("mac"):
            cm.addAction("MAC", lambda: QGuiApplication.clipboard().setText(a["mac"]))
        if node_id in self.inv.devices or node_id in self.inv.hosts:
            m.addSeparator()
            m.addAction("Remove from project…", lambda: self.forget(node_id))
        m.exec(pos)

    def node_action(self, action: str, node_id: str):
        ip = self.node_ip(node_id)
        if action in ("http", "https") and ip:
            QDesktopServices.openUrl(QUrl(f"{action}://{ip}/"))
        elif action == "ssh" and ip:
            self._ssh(ip)
        elif action in ("ping", "traceroute") and ip:
            self.tools_dock.show()
            self.tools_dock.raise_()
            self.tools.set_target(ip)
            (self.tools.ping if action == "ping" else self.tools.traceroute)()
        elif action == "rescan":
            self.rescan_device(node_id)

    def _ssh(self, ip: str):
        try:
            if sys.platform == "win32":
                putty = shutil.which("putty") or next((p for p in (r"C:\Program Files\PuTTY\putty.exe", r"C:\Program Files (x86)\PuTTY\putty.exe") if os.path.exists(p)), None)
                if putty:
                    subprocess.Popen([putty, "-ssh", ip])
                else:
                    subprocess.Popen(["cmd", "/c", "start", "", "ssh", ip])
            else:
                term = shutil.which("x-terminal-emulator") or shutil.which("gnome-terminal") or shutil.which("xterm")
                if term:
                    subprocess.Popen([term, "-e", "ssh", ip])
                else:
                    QDesktopServices.openUrl(QUrl(f"ssh://{ip}"))
        except OSError as e:
            QMessageBox.warning(self, "SSH", f"Could not start an SSH client: {e}")

    def forget(self, node_id: str, confirm: bool = True) -> bool:
        """Remove a device or host from the project (undoable). Refused while a scan or other
        job is running: its results would bring the item straight back."""
        if self._busy_guard("Remove from project"):
            return False
        if node_id not in self.inv.devices and node_id not in self.inv.hosts:
            return False
        name = self.snapshot.name(node_id) if self.snapshot else node_id
        if confirm and QMessageBox.question(self, "Remove from project",
                                            f"Remove “{name}” from this project?\n\nIt will come back if a later scan finds it again. Your notes on it are kept.") != QMessageBox.Yes:
            return False
        dev = self.inv.devices.get(node_id)
        host = self.inv.hosts.get(node_id)
        via = self.inv.unreachable.get(node_id)
        self._remove_node(node_id)
        self.set_dirty(True)
        if self.current_node == node_id:
            self.current_node = ""
            self.details.clear()
        self.refresh()
        self.undo_stack.push(ForgetCommand(self, node_id, dev, host, via))
        return True

    def _remove_node(self, node_id: str) -> None:
        inv = self.inv
        if node_id in inv.devices:
            inv.remove_device(node_id)
        if node_id in inv.hosts:
            remove_host = getattr(inv, "remove_host", None)
            if callable(remove_host):
                remove_host(node_id)
            else:
                inv.hosts.pop(node_id, None)
                inv.reindex()
        inv.unreachable.pop(node_id, None)

    def scope_check(self, target: str) -> tuple[bool, str]:
        try:
            a = ipaddress.ip_address(target)
        except ValueError:
            return True, ""
        for n in nets(self.inv.project.get("scan", {}).get("exclude", [])):
            if a in n:
                return False, f"{target} is inside {n}, which this project marks as never to be touched."
        return True, ""

    # ================================================================ scanning
    def manage_credentials(self):
        CredentialsDialog(self.store, self).exec()

    def preferences(self):
        from .prefs import PreferencesDialog

        dlg = PreferencesDialog(self)
        if dlg.exec():
            self.set_theme(dlg.chosen_theme())
            self.statusBar().showMessage("Preferences saved. New scans use these defaults.", 6000)

    def new_scan(self):
        if self._busy_guard("Scan"):
            return
        from .prefs import scan_defaults

        defaults = {**scan_defaults(), **self.inv.project.get("scan", {})}
        dlg = ScanDialog(self.store, defaults, has_data=bool(self.inv.devices), parent=self)
        if not dlg.exec():
            return
        req, remember = dlg.request()
        self.inv.project["scan"] = remember
        self.set_dirty(True)
        self.start_scan(req, "Scan")

    def _defaults_request(self, **over) -> Optional[ScanRequest]:
        d = self.inv.project.get("scan", {})
        saved = self.store.load()
        ids = d.get("credential_ids")
        chosen = [c for c in saved if (ids is None or c.id in ids)] or saved
        creds = [self.store.to_credential(c) for c in chosen]
        if not creds:
            QMessageBox.information(self, "Credentials needed", "Add an SNMP credential first (Scan ▸ SNMP credentials), or start a New scan.")
            return None
        scope = list(d.get("scope", [])) + list(d.get("targets", []))
        req = ScanRequest(
            credentials=creds, scope=scope, exclude=list(d.get("exclude", [])), probe_all=False,
            probe_hosts=d.get("probe_hosts", False), resolve_names=d.get("resolve_names", True), cisco_vlan_fdb=d.get("cisco_vlan_fdb", False),
            max_depth=d.get("max_depth", 6), workers=d.get("workers", 12), timeout=d.get("timeout", 2.0), retries=d.get("retries", 1),
            port=d.get("port", 161), sweep_max_prefix=d.get("sweep_max_prefix", 22), nmap_timeout=d.get("nmap_timeout", 30),
        )
        for k, v in over.items():
            setattr(req, k, v)
        if not req.scope:
            # the project was built before scan settings were saved: its own addresses are the scope
            req.scope = sorted({f"{ip}/32" for ip in req.seeds} | set(self.inv.subnets))
        return req

    def rescan_device(self, node_id: str):
        if node_id not in self.inv.devices or self._busy_guard("Rescan"):
            return
        req = self._defaults_request(seeds=[node_id], refresh=True, refresh_ids=[node_id], max_depth=0, resolve_names=False)
        if req is None:
            return
        if not any(ipaddress.ip_address(node_id) in n for n in nets(req.scope)):
            req.scope.append(f"{node_id}/32")
        self.start_scan(req, f"Rescan of {self.snapshot.name(node_id) if self.snapshot else node_id}")

    def schedule_rescans(self):
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QInputDialog

        if self._sched_timer is not None:
            self._sched_timer.stop()
            self._sched_timer = None
            self.a_schedule.setChecked(False)
            self.statusBar().showMessage("Automatic rescans turned off.", 5000)
            return
        mins, ok = QInputDialog.getInt(self, "Automatic rescans", "Re-poll every device this often (minutes):", 30, 1, 10080)
        if not ok:
            self.a_schedule.setChecked(False)
            return
        self._sched_timer = QTimer(self)
        self._sched_timer.setInterval(mins * 60000)
        self._sched_timer.timeout.connect(self._scheduled_tick)
        self._sched_timer.start()
        self.a_schedule.setChecked(True)
        self.statusBar().showMessage(f"Automatic rescans every {mins} min while NetMap is open.", 8000)

    def _scheduled_tick(self):
        if not self._jobs.busy() and self.inv.devices:
            self.log_view.appendPlainText(f"\n=== Scheduled rescan — {time.strftime('%H:%M:%S')} ===")
            self.rescan_all()

    def rescan_all(self):
        if self._busy_guard("Rescan"):
            return
        if not self.inv.devices:
            self.new_scan()
            return
        req = self._defaults_request(seeds=sorted(self.inv.devices), refresh=True)
        if req is None:
            return
        for ip in self.inv.devices:
            if not any(ipaddress.ip_address(ip) in n for n in nets(req.scope)):
                req.scope.append(f"{ip}/32")
        self.start_scan(req, "Rescan of known devices")

    def sweep_subnet(self, cidr: str):
        if self._busy_guard("Scan"):
            return
        req = self._defaults_request(targets=[cidr], max_depth=0, sweep=False)
        if req is None:
            return
        if not any(ipaddress.ip_network(cidr).subnet_of(n) for n in nets(req.scope) if n.version == 4):
            if QMessageBox.question(self, "Outside the saved ranges", f"{cidr} is not inside the ranges saved for this project. Scan it anyway?") != QMessageBox.Yes:
                return
        self.start_scan(req, f"Scan of {cidr}")

    def start_scan(self, req: ScanRequest, title: str):
        self._scan_title = title
        self._scan_started = time.time()
        self.log_view.appendPlainText(f"\n=== {title} — {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
        if not self.activity_dock.isVisible():
            self.activity_dock.show()
            self.resizeDocks([self.activity_dock], [max(110, min(190, int(self.height() * 0.2)))], Qt.Vertical)
        self.activity_dock.raise_()
        self.logbridge.attach()
        work = self._copy_inventory("Preparing the scan")
        if work is None:
            self.logbridge.detach()
            return
        worker = ScanWorker(work, req, parent=self)
        self.worker = worker
        self._jobs.add(worker, "the scan")
        worker.phase.connect(self._on_phase)
        worker.progress.connect(self._on_progress)
        worker.snapshot.connect(self._on_snapshot)
        # the result is taken from the worker object, so a queued signal and a synchronous
        # take-over after wait() (closing the window) cannot both apply it
        worker.finished_ok.connect(lambda _inv, _rec, w=worker: self._finish_scan(w))
        worker.failed.connect(lambda _err, w=worker: self._finish_scan(w))
        worker.finished.connect(lambda w=worker: self._on_thread_done(w))
        self.scan_bar.show()
        self.stop_btn.show()
        self.a_stop.setEnabled(True)
        self.a_scan.setEnabled(False)
        self.a_rescan.setEnabled(False)
        self.scan_phase.setText(f"<b>{html.escape(title)}</b>: starting…")
        worker.start()

    def _copy_inventory(self, title: str) -> Optional[Inventory]:
        """A deep copy for a worker to use, made on a thread (a 14k-host project takes a
        couple of seconds) while the window keeps painting."""
        inv = self.inv
        try:
            return run_blocking(self, title, lambda: with_retry(lambda: copy_inventory(inv)), self._jobs)
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, title, f"Could not prepare a working copy of the project:\n{type(e).__name__}: {e}")
            return None

    def stop_scan(self):
        """Stop the scan and any capture or inspection; what was collected so far is kept."""
        if self._jobs.busy():
            self.scan_phase.setText("Stopping — keeping what was found so far…")
            self._jobs.stop_all()

    def _finish_scan(self, worker: ScanWorker) -> None:
        """Apply a scan worker's outcome exactly once - from its queued signal in normal use,
        or synchronously after wait() when the window is closing."""
        if worker.consumed or worker.outcome is None:
            return
        worker.consumed = True
        if self._live_builder is not None:
            self._live_builder = None  # a tick still being built is superseded by the result
        kind = worker.outcome[0]
        if kind == "ok":
            self._on_finished(worker.outcome[1], worker.outcome[2])
        else:
            self._on_failed(worker.outcome[1])

    def _merge(self, d_or_inv) -> None:
        """Take scan results while keeping everything the user edited during the scan."""
        new = d_or_inv if isinstance(d_or_inv, Inventory) else Inventory.from_dict(d_or_inv)
        new.annotations = self.inv.annotations
        new.layout = self.inv.layout
        new.project = self.inv.project
        self.inv = new

    def _on_phase(self, name, detail):
        self.scan_phase.setText(f"<b>{html.escape(getattr(self, '_scan_title', 'Scan'))}</b>: {html.escape(name)}" + (f" — {html.escape(detail)}" if detail else ""))

    def _on_progress(self, st: dict):
        bits = [f"{st.get('devices', 0)} devices", f"{st.get('hosts', 0)} hosts"]
        if st.get("queued"):
            bits.append(f"{st['queued']} queued")
        if st.get("probed"):
            bits.append(f"{st['probed']} probed")
        bits.append(fmt_duration(st.get("elapsed", 0)) or "0s")
        self.scan_stats.setText(" · ".join(bits))

    def _on_snapshot(self, d: dict):
        """A live tick from the scan. The heavy part (rebuilding the inventory, the graph and
        the rows of the page on screen) runs on a SnapshotBuilder thread; only swapping the
        results in happens here. Ticks that arrive while one is being built are dropped."""
        if self.worker is None or self._saving:
            return
        if self._live_builder is not None and self._live_builder.isRunning():
            return
        # never spend more than a quarter of the time on the UI part of a refresh
        now = time.time()
        if now - getattr(self, "_last_live", 0.0) < 4 * getattr(self, "_refresh_cost", 0.0):
            return
        self._last_live = now
        cur = self.current_page()
        rows_fn = PAGES[cur][1] if cur in PAGES and cur not in ACK_PAGES else None
        b = SnapshotBuilder(d, self.inv.annotations, self.inv.layout, self.inv.project, cur, rows_fn, parent=self)
        self._live_builder = b
        self._jobs.add(b, "the live refresh", blocking=False)
        b.built.connect(lambda inv, snap, key, rows, b=b: self._on_live_built(b, inv, snap, key, rows))
        b.start()

    def _on_live_built(self, builder, inv: Inventory, snap: Snapshot, key: str, rows) -> None:
        if builder is not self._live_builder:
            return  # superseded (the scan finished meanwhile)
        self._live_builder = None
        if self.worker is None or self.worker.consumed:
            return
        t0 = time.time()
        self._merge(inv)
        self.snapshot = snap
        self._stale = set(self.pages)
        cur = self.current_page()
        w = self.pages.get(cur)
        if cur == key and rows is not None and isinstance(w, DataPage):
            w.set_rows(self._page_rows(key, rows))
            self._stale.discard(key)
        elif cur == "map" and self.topology.nodes:
            self.topology.info.setText("A scan is running: the map updates when it finishes, or when you come back to this page.")
        elif cur:
            self._load_page(cur)
        self._update_nav_counts()
        self._update_status()
        if self.current_node:
            self.details.snapshot = self.snapshot
        self._refresh_cost = time.time() - t0

    def _on_finished(self, inv, record: dict):
        self._merge(inv)
        self.set_dirty(True)
        self.refresh()
        found = record.get("found", {})
        took = fmt_duration(record.get("seconds", 0)) or "0s"
        cancelled = bool(record.get("cancelled"))
        msg = ("Stopped" if cancelled else "Finished") + f" in {took}: {len(found.get('new_devices', []))} new device(s), " \
              f"{found.get('refreshed', 0)} re-polled, {found.get('new_hosts', 0)} new host(s). {self.inv.summary()}."
        self.scan_phase.setText(f"<b>{html.escape(getattr(self, '_scan_title', 'Scan'))}</b>: {html.escape(msg)}")
        self.log_view.appendPlainText(msg)
        self._autosave(cancelled)
        self.statusBar().showMessage(msg, 15000)
        QApplication.alert(self)

    def _autosave(self, cancelled: bool = False) -> None:
        """Write the project after a job: always for a completed one; for a stopped scan only
        when the file was already written this session (a stop is often a "no, not that")."""
        if not self.path or self._closing:
            return
        if cancelled and not self._saved_this_session:
            self.statusBar().showMessage("Stopped scan: not saved automatically (Ctrl+S to keep it).", 8000)
            return
        self._write(self.path)

    def _on_failed(self, err: str):
        self.scan_phase.setText(f"<span style='color:#dc2626'>Scan failed: {html.escape(err)}</span>")
        QMessageBox.warning(self, "Scan failed", f"{err}\n\nDetails are in the log ({self.log_path}).")

    def _on_thread_done(self, worker=None):
        if worker is not None and worker is not self.worker:
            return
        self.logbridge.detach()
        self.worker = None
        self._update_job_chrome()

    def _update_job_chrome(self):
        """Progress bar, Stop button and scan actions follow whether any job is running."""
        busy = self._jobs.busy()
        self.scan_bar.setVisible(busy)
        self.stop_btn.setVisible(busy)
        self.a_stop.setEnabled(busy)
        self.a_scan.setEnabled(not busy)
        self.a_rescan.setEnabled(not busy)

    def _on_jobs_idle(self):
        self._update_job_chrome()
        if self._closing:
            QTimer.singleShot(0, self.close)

    def _on_log(self, created, level, name, msg):
        stamp = time.strftime("%H:%M:%S", time.localtime(created))
        prefix = "" if level == "INFO" else f"{level}: "
        self.log_view.appendPlainText(f"{stamp}  {prefix}{msg}")

    # ================================================================ exports
    def _ask_path(self, title, default_name, filt) -> str:
        return ask_save_path(self, title, default_name, filt, self.path)

    def _done(self, path):
        self.statusBar().showMessage(f"Wrote {path}", 6000)

    def _base(self) -> str:
        return self.project_name().replace(" ", "-")

    def export_xlsx(self, path: str = ""):
        from ..report import export_xlsx

        path = path or self._ask_path("Export spreadsheet workbook", f"{self._base()}.xlsx", "Spreadsheet workbook (*.xlsx)")
        if path:
            inv, g = self.inv, self.snapshot.g
            try:
                run_blocking(self, "Writing the workbook", lambda: export_xlsx(inv, g, path), self._jobs)
            except Exception as e:  # noqa: BLE001
                QMessageBox.critical(self, "Export failed", f"{path}\n\n{type(e).__name__}: {e}")
                return ""
            self._done(path)
        return path

    def export_csv(self, prefix: str = ""):
        from ..graph import export_csv

        if not prefix:
            d = QFileDialog.getExistingDirectory(self, "Folder for CSV files", QSettings().value("ui/export_dir", os.path.expanduser("~")))
            if not d:
                return
            prefix = os.path.join(d, f"{self._base()}-")
        files = export_csv(self.inv, self.snapshot.g, prefix)
        self._done(f"{len(files)} CSV files to {os.path.dirname(prefix)}")
        return files

    def export_drawio(self, path: str = ""):
        from ..diagram import export_drawio

        path = path or self._ask_path("Export diagram", f"{self._base()}.drawio", "Diagram (*.drawio)")
        if path:
            live = {}
            if self.topology.nodes and not self.topology.focus and not self.topology.hidden_nodes:
                live[self.topology.preset] = self.topology.positions()
            export_drawio(self.inv, self.snapshot.g, path, positions_for=live)
            self._done(path)
        return path

    def export_html(self, path: str = ""):
        from ..render import render_html

        path = path or self._ask_path("Export interactive map", f"{self._base()}-map.html", "Web page (*.html)")
        if path:
            render_html(self.snapshot.g, path)
            self._done(path)
        return path

    def export_graph(self, kind: str, path: str = ""):
        from ..graph import export_dot, export_graphml

        ext = {"graphml": "GraphML (*.graphml)", "dot": "Graphviz (*.dot)"}[kind]
        path = path or self._ask_path(f"Export {kind}", f"{self._base()}.{kind}", ext)
        if path:
            (export_graphml if kind == "graphml" else export_dot)(self.snapshot.g, path)
            self._done(path)
        return path

    def _ensure_map(self):
        if "map" in self._stale or not self.topology.nodes:
            self._load_page("map")

    def export_map(self, kind: str, path: str = ""):
        self._ensure_map()
        filt = {"png": "PNG image (*.png)", "svg": "SVG drawing (*.svg)", "pdf": "PDF document (*.pdf)"}[kind]
        path = path or self._ask_path("Export map", f"{self._base()}-{self.topology.preset}.{kind}", filt)
        if not path:
            return ""
        title = f"{self.project_name()} — {self.topology.preset_box.currentText()} — {time.strftime('%Y-%m-%d')}"
        try:
            if kind == "png":
                img = self.topology.render_image(2.0)
                if img.isNull():
                    _, w, h = self.topology.render_size(2.0)
                    raise RuntimeError(f"not enough memory for a {w}x{h} image; export the map as PDF or SVG instead")
                if not img.save(path):
                    raise RuntimeError("the image could not be written (is the folder writable and the extension .png?)")
            elif kind == "svg":
                self.topology.export_svg(path, title)
            else:
                self.topology.export_pdf(path, title)
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "Export failed", f"{path}\n\n{e}")
            self.statusBar().showMessage(f"Export failed: {e}", 8000)
            return ""
        self._done(path)
        return path

    def print_map(self):
        from PySide6.QtPrintSupport import QPrintDialog, QPrinter

        self._ensure_map()
        printer = QPrinter(QPrinter.HighResolution)
        from PySide6.QtGui import QPageLayout

        printer.setPageOrientation(QPageLayout.Landscape)
        if QPrintDialog(printer, self).exec():
            self.topology.print_map(printer)

    # ================================================================ compare / help
    def query_console(self):
        from .querydlg import QueryDialog

        dlg = QueryDialog(self.snapshot, self)
        dlg.openNode.connect(self.open_node)
        dlg.show()

    def start_api(self):
        from PySide6.QtWidgets import QInputDialog
        from .. import api

        if getattr(self, "_api_srv", None) is not None:
            self._api_srv.shutdown()
            self._api_srv = None
            self.statusBar().showMessage("API server stopped.", 5000)
            return
        port, ok = QInputDialog.getInt(self, "API server", "Serve a read-only REST API on 127.0.0.1 port:", 8088, 1, 65535)
        if not ok:
            return
        try:
            import threading
            self._api_srv = api.serve(lambda: self.inv, host="127.0.0.1", port=port)
            threading.Thread(target=self._api_srv.serve_forever, daemon=True).start()
        except OSError as e:
            QMessageBox.warning(self, "API server", f"Could not start on port {port}: {e}")
            self._api_srv = None
            return
        QMessageBox.information(self, "API server",
                               f"Serving this project at http://127.0.0.1:{port}/\n\n"
                               "Try /summary, /devices, or /query?q=hosts where os ~ windows\n\n"
                               "Tools ▸ Start API server again to stop it.")

    def compare_previous(self):
        """Diff against the backup written the last time this project was saved."""
        if not self.path:
            QMessageBox.information(self, "Compare", "Save the project first: the previous version is the backup made when it is saved again.")
            return
        bak = backup_paths(self.path)[0]
        if not os.path.exists(bak):
            QMessageBox.information(self, "Compare", f"No previous version yet. One is kept as {os.path.basename(bak)} each time the project is saved.")
            return
        self.compare(bak)

    def compare(self, path: Optional[str] = None):
        from ..diff import compare

        if not path:
            start = QSettings().value("ui/last_dir", os.path.expanduser("~"))
            path, _ = QFileDialog.getOpenFileName(self, "Compare with an earlier scan", start, FILE_FILTER)
        if not path:
            return
        try:
            other = Inventory.load(path)
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Could not open", f"{path}\n\n{e}")
            return
        d = compare(other, self.inv)
        dlg = CompareDialog(d, os.path.basename(path), self.project_name(), self)
        dlg.openNode.connect(self.open_node)
        dlg.show()

    def listen_events(self):
        from .listendlg import ListenDialog

        dlg = ListenDialog(self.snapshot, self)
        dlg.show()

    def import_vmware(self):
        if self._busy_guard():
            return
        from .vmwaredlg import VmwareDialog, VmwareWorker

        dlg = VmwareDialog(self)
        if not dlg.exec():
            return
        v = dlg.values()
        if not v["host"] or not v["username"]:
            QMessageBox.warning(self, "Details needed", "Enter the vCenter/ESXi host and username.")
            return
        self.activity_dock.show()
        self.activity_dock.raise_()
        self.scan_phase.setText(f"Discovering VMware on {v['host']}…")
        work = self._copy_inventory("Preparing the discovery")
        if work is None:
            return
        w = VmwareWorker(work, v, self)
        self._vmw_worker = w
        self._jobs.add(w, "the VMware discovery")
        self._update_job_chrome()

        def finished(result):
            self._vmw_worker = None
            if self._closing:
                return
            if result.get("cancelled"):
                self.scan_phase.setText("VMware discovery stopped.")
                return
            if result.get("error"):
                self.scan_phase.setText(f"VMware discovery failed: {result['error']}")
                QMessageBox.warning(self, "VMware discovery", result["error"])
                return
            self._merge(w.inv)  # the worker's copy, with what it added, becomes the project
            self.set_dirty(True)
            self.refresh()
            msg = f"VMware: {result.get('esxi_hosts', 0)} ESXi host(s), {result.get('vms', 0)} VM(s) ({result.get('vms_with_ip', 0)} with an IP), {result.get('portgroups', 0)} port groups."
            self.scan_phase.setText(msg)
            self.statusBar().showMessage(msg, 12000)
            self._autosave()

        w.done.connect(finished)
        w.start()

    def import_dhcp(self):
        from .. import dhcp

        if self._busy_guard("Import"):
            return
        start = QSettings().value("ui/last_dir", os.path.expanduser("~"))
        path, _ = QFileDialog.getOpenFileName(self, "Import DHCP leases", start, "DHCP exports (*.csv *.txt *.leases);;All files (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                leases = dhcp.parse_leases(f.read())
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Could not read", f"{path}\n\n{e}")
            return
        if not leases:
            QMessageBox.information(self, "Nothing imported", "No leases were recognised in that file. Supported: ISC/Kea dhcpd and Windows DHCP CSV exports.")
            return
        summary = dhcp.import_leases(self.inv, leases)
        self.set_dirty(True)
        self.refresh()
        QMessageBox.information(self, "DHCP imported",
                               f"{summary['leases']} leases: named {summary['named']} host(s), filled {summary['macs_filled']} MAC(s), "
                               f"added {summary['new_hosts']} host(s), marked {summary['scopes']} subnet(s) as DHCP scopes.")

    def inspect_servers(self):
        if self._busy_guard():
            return
        if not self.inv.hosts:
            QMessageBox.information(self, "No hosts", "Scan the network first; then inspect the hosts found.")
            return
        from .inspectdlg import InspectDialog, InspectWorker

        dlg = InspectDialog(self)
        if not dlg.exec():
            return
        creds = dlg.creds()
        if not creds:
            QMessageBox.warning(self, "Credentials needed", "Enter SSH and/or WinRM credentials.")
            return
        self.activity_dock.show()
        self.activity_dock.raise_()
        self.log_view.appendPlainText(f"\n=== Inspecting servers — {time.strftime('%H:%M:%S')} ===")
        self.scan_phase.setText("Inspecting servers over SSH / WinRM…")
        work = self._copy_inventory("Preparing the inspection")
        if work is None:
            return
        # authenticated inspection stays inside the ranges the project was scanned with
        scan = self.inv.project.get("scan", {})
        scope = nets(list(scan.get("scope", [])) + list(scan.get("targets", []))) or None
        exclude = nets(list(scan.get("exclude", []))) or None
        w = InspectWorker(work, creds, self, scope=scope, exclude=exclude)
        self._insp_worker = w
        self._jobs.add(w, "the server inspection")
        self._update_job_chrome()

        def finished(result):
            self._insp_worker = None
            if self._closing:
                return
            if result.get("error"):
                self.scan_phase.setText(f"Inspection failed: {result['error']}")
                return
            self._merge(w.inv)  # facts were written onto the worker's copy; it becomes the project
            self.set_dirty(True)
            self.refresh()
            for line in _host_key_lines(result, self.inv):
                self.log_view.appendPlainText("  " + line)
            if result.get("cancelled"):
                self.scan_phase.setText("Inspection stopped - hosts inspected so far are kept.")
                return
            msg = f"Inspected {result.get('ok', 0)} host(s): {result.get('linux', 0)} Linux, {result.get('windows', 0)} Windows, {result.get('failed', 0)} failed."
            self.scan_phase.setText(msg)
            self.statusBar().showMessage(msg, 12000)
            self._autosave()

        w.done.connect(finished)
        w.start()

    def capture_configs(self, node_id: str = ""):
        if self._busy_guard():
            return
        if not self.inv.devices:
            QMessageBox.information(self, "No devices", "Scan the network first, then capture configs from the devices found.")
            return
        from .capturedlg import CaptureDialog, CaptureWorker

        dlg = CaptureDialog(len(self.inv.devices), self.snapshot.name(node_id) if node_id else "", self)
        if not dlg.exec():
            return
        v = dlg.values()
        if not v["username"]:
            QMessageBox.warning(self, "Username needed", "Enter the SSH username to log in with.")
            return
        ids = [node_id] if (node_id and v["scope"] == "one") else sorted(self.inv.devices)
        self.activity_dock.show()
        self.activity_dock.raise_()
        self.log_view.appendPlainText(f"\n=== Capturing configs from {len(ids)} device(s) — {time.strftime('%H:%M:%S')} ===")
        self.scan_phase.setText(f"Capturing configs from {len(ids)} device(s)…")
        work = self._copy_inventory("Preparing the capture")
        if work is None:
            return
        w = CaptureWorker(work, ids, v, self)
        self._cap_worker = w
        self._jobs.add(w, "the config capture")
        self._update_job_chrome()
        w.progress.connect(lambda did, ok, msg: self.log_view.appendPlainText(f"  {self.snapshot.name(did)}: {'ok - ' if ok else 'FAILED - '}{msg}"))

        def finished(ok, changed):
            self._cap_worker = None
            if self._closing:
                return
            self.inv.configs = w.inv.configs  # captured revisions were stored on the worker's copy
            self.inv.rev += 1
            self.set_dirty(True)
            self.refresh()
            msg = f"Captured {ok} config(s), {changed} changed."
            self.scan_phase.setText(msg)
            self.statusBar().showMessage(msg, 10000)
            self._autosave()

        w.done.connect(finished)
        w.start()  # the Stop button reaches it through the job registry

    def reconcile(self):
        from .reconciledlg import ReconcileDialog

        dlg = ReconcileDialog(lambda: self.inv, self)
        dlg.openNode.connect(self.open_node)
        dlg.applied.connect(lambda: (self.set_dirty(True), self.refresh()))
        dlg.show()
        dlg._pick()

    def check_updates(self):
        """Ask GitHub for the latest release (only when asked; nothing is sent automatically)."""
        from PySide6.QtCore import QThread, Signal

        class Fetch(QThread):
            done = Signal(str, str)

            def run(self):
                import json
                import urllib.request

                try:
                    req = urllib.request.Request("https://api.github.com/repos/kerbe42/netmap/releases/latest",
                                                 headers={"Accept": "application/vnd.github+json", "User-Agent": f"NetMap/{__version__}"})
                    with urllib.request.urlopen(req, timeout=10) as r:
                        tag = json.load(r).get("tag_name", "")
                    self.done.emit(tag, "")
                except Exception as e:  # noqa: BLE001
                    self.done.emit("", str(e))

        def shown(tag, err):
            if err:
                QMessageBox.information(self, "Check for updates", f"Could not reach GitHub: {err}")
                return
            latest = tag.lstrip("v")

            def key(v):
                return tuple(int(x) for x in v.split(".") if x.isdigit())

            if latest and key(latest) > key(__version__):
                r = QMessageBox.question(self, "Update available", f"NetMap {latest} is available (you have {__version__}). Open the download page?")
                if r == QMessageBox.Yes:
                    QDesktopServices.openUrl(QUrl("https://github.com/kerbe42/netmap/releases/latest"))
            else:
                QMessageBox.information(self, "Check for updates", f"You have the latest version ({__version__}).")

        self._fetch = Fetch(self)
        self._fetch.done.connect(shown)
        self._jobs.add(self._fetch, "the update check", blocking=False)
        self._fetch.start()

    def quick_guide(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("NetMap quick guide")
        tb = QTextBrowser()
        tb.setOpenExternalLinks(True)
        tb.setHtml(GUIDE_HTML)
        lay = QVBoxLayout(dlg)
        lay.addWidget(tb)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(dlg.reject)
        lay.addWidget(bb)
        dlg.resize(720, 640)
        dlg.exec()

    def about(self):
        QMessageBox.about(
            self, "About NetMap",
            f"<h3>NetMap {__version__}</h3><p>Network inventory and topology mapping for the networks you look after.</p>"
            "<p>Reads devices over SNMP (read-only) and builds an inventory and diagrams from their LLDP/CDP, "
            "routing, ARP, MAC-address, VLAN, interface and hardware tables.</p>"
            "<p><a href='https://github.com/kerbe42/netmap'>github.com/kerbe42/netmap</a></p>"
            "<p style='color:gray'>Built with Qt for Python (LGPLv3), pysnmp, networkx and openpyxl. "
            "MAC vendor names from the IEEE OUI registry.</p>",
        )

    def set_theme(self, key: str):
        QSettings().setValue("ui/theme", key)
        apply_theme(QApplication.instance(), key)
        self.refresh(keep_details=False)
        if self.topology.nodes:
            self.topology.rebuild()

    # ================================================================ window
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls() and any(u.toLocalFile().lower().endswith((".netmap", ".json")) for u in e.mimeData().urls()):
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            p = u.toLocalFile()
            if p.lower().endswith((".netmap", ".json")):
                self.open_project(p)
                break

    def _restore_window(self):
        s = QSettings()
        g = s.value("ui/geometry")
        if isinstance(g, QByteArray):
            self.restoreGeometry(g)
        else:
            screen = QGuiApplication.primaryScreen()
            avail = screen.availableGeometry() if screen else None
            w = int(min(1440, avail.width() * 0.92)) if avail else 1400
            h = int(min(900, avail.height() * 0.9)) if avail else 860
            self.resize(w, h)
        st = s.value("ui/state")
        if isinstance(st, QByteArray):
            self.restoreState(st)
        else:
            # first run: the page gets the room. Details scales with the window; the activity
            # log stays out of the way until a scan starts (start_scan shows it).
            self.activity_dock.hide()
            self.tools_dock.hide()
            QTimer.singleShot(0, lambda: self.resizeDocks([self.details_dock], [max(300, min(440, int(self.width() * 0.28)))], Qt.Horizontal))

    def closeEvent(self, e):
        """Stop every worker, wait a bounded time, and only then ask about saving. A worker
        that is still running defers the close: the window says so and closes itself when
        the registry reports idle - Qt never sees a thread destroyed while running."""
        if self._jobs.running():
            if self._jobs.busy() and not self._closing:
                if QMessageBox.question(self, "Work in progress", f"{self._jobs.describe().capitalize()} is still running. Stop it and quit?") != QMessageBox.Yes:
                    e.ignore()
                    return
            self._closing = True
            self._jobs.stop_all()
            if not self._jobs.wait_all(CLOSE_WAIT_MS):
                self.scan_phase.setText("Still stopping — the window closes when the work has ended.")
                self.statusBar().showMessage("Still stopping…")
                e.ignore()
                return
        # the scan's result, if it just ended, is applied here and not inside the message box below
        if self.worker is not None:
            self._finish_scan(self.worker)
            self._on_thread_done(self.worker)
        if not self.maybe_save():
            self._closing = False
            self._update_job_chrome()
            e.ignore()
            return
        self._closing = True
        s = QSettings()
        s.setValue("ui/geometry", self.saveGeometry())
        s.setValue("ui/state", self.saveState())
        if self.recovery_dir:
            clear_recovery(self.recovery_dir)
        e.accept()


GUIDE_HTML = """
<h2>NetMap quick guide</h2>
<p>NetMap builds an inventory and topology diagrams of a network from what its devices report over SNMP.
It only reads: SNMP GET/GETBULK, pings, and (optionally) reverse DNS and Nmap service checks.</p>
<h3>1. Credentials</h3>
<p><b>Scan ▸ SNMP credentials</b>: add the read-only SNMPv2c community or SNMPv3 user for the devices.
Use <i>Test against a device</i> to check one before scanning. Secrets are encrypted with your Windows account and are never
written into project files.</p>
<h3>2. Scan</h3>
<p><b>Scan ▸ New scan</b> (Ctrl+R). Enter the address ranges you are responsible for — every live address in them is checked — and,
optionally, one or two core devices to start from. NetMap follows LLDP/CDP neighbours, routing next-hops and subnet gateways
to further devices, but never outside the ranges you gave (or <i>May also follow into</i>), and never into <i>Never touch</i>.</p>
<p>Tips: if ping is blocked, choose <i>Query every address with SNMP</i>. Tick <i>Ping-sweep every subnet</i> for accurate
address counts. Results appear as the scan runs; <b>Stop</b> keeps everything found so far.</p>
<h3>3. Explore</h3>
<ul>
<li><b>Overview</b> — counts, breakdowns, and where to look first.</li>
<li><b>Topology map</b> — <i>Physical</i> shows cabling from LLDP/CDP; <i>Logical</i> shows routers and the subnets they serve.
Drag nodes to tidy the diagram: positions are saved in the project. Right-click a node to focus on its neighbourhood.</li>
<li><b>Lists</b> — devices, hosts (with the switch port each one is on), subnets with an IP address map, VLANs, links,
interfaces and hardware serials. Filter with words, or <code>column:value</code> such as <code>role:switch vendor:cisco</code>.</li>
<li><b>Needs attention</b> — neighbours nobody could poll, link speed mismatches, VLANs named differently on different switches,
addresses with several MACs, subnets without a gateway, and addresses outside every known subnet.</li>
</ul>
<h3>4. Document</h3>
<p>Select anything and use the <b>Documentation</b> tab in the details panel: name, role, site, owner, asset tag, status, tags and
notes. These are saved in the project and survive every rescan, and they appear in the spreadsheet export.</p>
<h3>5. Keep it current</h3>
<p><b>F5</b> re-polls every known device and follows new links. Right-click a device to rescan just that one, or a subnet to
find every live address in it. <b>Tools ▸ Compare with another scan</b> lists what was added, removed or changed between two
project files.</p>
<h3>6. Share</h3>
<p><b>File ▸ Export</b>: a spreadsheet workbook (.xlsx) of the whole inventory, CSV files, a .drawio diagram (opens in diagrams.net),
the map as PDF/SVG/PNG, or a single interactive HTML page.</p>
"""
