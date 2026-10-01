"""Regression tests for the GUI review findings (offscreen Qt).

Each test names the finding it covers: worker registry / busy(), deterministic scan
finish, drag-then-save, notes flush, backups, forget via the model API, undo, map
selection stability, render cap, credential labels, bar text colour, listen tracking,
faceplate labels, acknowledged findings, reconcile dialog inventory resolution.
"""
import os
import time

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QRect, QRectF, QSettings, Qt, QThread  # noqa: E402
from PySide6.QtWidgets import QApplication, QGraphicsRectItem, QMessageBox  # noqa: E402

from subnetsleuth.model import Inventory  # noqa: E402
from subnetsleuth.util import resource_path  # noqa: E402

SAMPLE = resource_path("data", "sample-campus.sleuth")


@pytest.fixture(scope="module")
def qapp(tmp_path_factory):
    QCoreApplication.setOrganizationName("subnetsleuth-tests")
    QCoreApplication.setApplicationName("SubnetSleuthReviewTests")
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, str(tmp_path_factory.mktemp("settings")))
    app = QApplication.instance() or QApplication([])
    yield app


def _pump(app, ms=50):
    end = time.time() + ms / 1000
    while time.time() < end:
        app.processEvents()
        time.sleep(0.005)


def _wait(app, cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def win(qapp, tmp_path):
    from subnetsleuth.gui.mainwindow import MainWindow

    w = MainWindow(recovery_dir="")
    w.resize(1300, 850)
    w.show()
    w.open_project(SAMPLE)
    w.path = None  # the sample is opened without a path (never write into the program folder)
    _pump(qapp, 30)
    yield w
    w.dirty = False
    w._jobs.stop_all()
    w._jobs.wait_all(5000)
    w.close()
    qapp.processEvents()


class _SlowJob(QThread):
    """A stand-in for a side worker: runs until stopped (plus an optional stubborn delay)."""

    def __init__(self, parent=None, ignore_stop_for=0.0):
        super().__init__(parent)
        self._stop = False
        self.ignore_stop_for = ignore_stop_for

    def stop(self):
        self._stop = True

    def run(self):
        started = time.time()
        while not self._stop or time.time() - started < self.ignore_stop_for:
            time.sleep(0.02)
            if time.time() - started > 20:
                break


def _yes(*_a, **_k):
    return QMessageBox.Yes


# ------------------------------------------------------------------ 1 / 2 / 9: workers, busy(), close
def test_busy_blocks_scan_open_new_and_forget_while_a_side_worker_runs(qapp, win, monkeypatch):
    from subnetsleuth.gui import mainwindow as mw

    shown = []
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: shown.append(a[2])))
    monkeypatch.setattr(mw.ScanDialog, "exec", lambda self: pytest.fail("the scan dialog must not open while busy"))
    job = _SlowJob(win)
    win._jobs.add(job, "the server inspection")
    job.start()
    assert _wait(qapp, job.isRunning, 5)
    assert win.busy()
    hosts_before = len(win.inv.hosts)
    inv_before = win.inv
    win.new_scan()
    win.rescan_all()
    win.open_project(SAMPLE)
    win.new_project()
    host = next(ip for ip in win.inv.hosts if ip not in win.inv.ip_to_device)
    assert win.forget(host, confirm=False) is False
    assert len(win.inv.hosts) == hosts_before and win.inv is inv_before
    assert shown and all("server inspection" in m for m in shown)
    assert win.stop_btn.isVisible() or win.a_stop.isEnabled()
    job.stop()
    assert _wait(qapp, lambda: not win.busy(), 5)
    assert _wait(qapp, lambda: not win.a_stop.isEnabled(), 5)  # chrome follows the registry's finished handler


def test_close_stops_side_workers_and_waits(qapp, win, monkeypatch):
    monkeypatch.setattr(QMessageBox, "question", staticmethod(_yes))
    job = _SlowJob(win)
    win._jobs.add(job, "the config capture")
    job.start()
    assert _wait(qapp, job.isRunning, 5)
    assert win.close()  # stop_all + bounded wait, then the normal close path
    assert not job.isRunning()
    assert not win.isVisible()


def test_close_is_deferred_while_a_worker_ignores_stop_then_completes(qapp, win, monkeypatch):
    from subnetsleuth.gui import mainwindow as mw

    monkeypatch.setattr(QMessageBox, "question", staticmethod(_yes))
    monkeypatch.setattr(mw, "CLOSE_WAIT_MS", 200)
    job = _SlowJob(win, ignore_stop_for=1.2)
    win._jobs.add(job, "the VMware discovery")
    job.start()
    assert _wait(qapp, job.isRunning, 5)
    assert win.close() is False  # ignored: still stopping
    assert win.isVisible()
    assert "stopping" in win.scan_phase.text().lower()
    assert _wait(qapp, lambda: not win.isVisible(), 10), "window did not close itself once the worker ended"
    assert not job.isRunning()


def test_scan_outcome_is_applied_exactly_once_and_cancelled_scans_are_not_autosaved(qapp, win, tmp_path):
    class FakeWorker:
        consumed = False

        def __init__(self, inv, record):
            self.outcome = ("ok", inv, record)

    target = tmp_path / "proj.sleuth"
    win.path = str(target)
    new_inv = win.inv.copy()
    new_inv.hosts.pop(next(iter(new_inv.hosts)))
    fw = FakeWorker(new_inv, {"cancelled": True, "found": {}, "seconds": 1})
    win.worker = fw
    win._finish_scan(fw)
    assert win.inv is new_inv and fw.consumed
    assert not target.exists(), "a cancelled scan must not overwrite/create the project file before any save this session"
    again = win.inv.copy()
    fw.outcome = ("ok", again, {"cancelled": True, "found": {}})
    win._finish_scan(fw)  # second delivery (queued signal after a synchronous take-over) is a no-op
    assert win.inv is new_inv
    win.worker = None
    # once the project has been saved this session, a stopped scan is autosaved too
    assert win._write(str(target))
    fw2 = FakeWorker(again, {"cancelled": True, "found": {}})
    win.worker = fw2
    target.unlink()
    win._finish_scan(fw2)
    win.worker = None
    assert target.exists()


# ------------------------------------------------------------------ 3: live tick off the UI thread
def test_live_tick_builds_snapshot_and_rows_on_a_thread(qapp, win):
    from subnetsleuth.gui.worker import SnapshotBuilder

    win.navigate("hosts")
    _pump(qapp, 30)
    d = win.inv.to_dict()

    class FakeWorker:
        consumed = False

    win.worker = FakeWorker()
    win._last_live = 0.0
    win._refresh_cost = 0.0
    win._on_snapshot(d)
    assert isinstance(win._live_builder, SnapshotBuilder)
    assert _wait(qapp, lambda: win._live_builder is None, 30)
    assert win.pages["hosts"].model.rowCount() > 0
    assert "hosts" not in win._stale and "devices" in win._stale  # only the visible page was rebuilt
    win.worker = None


def test_rows_model_sorts_once_by_kind_and_hosts_default_to_ip(qapp, win):
    from subnetsleuth.gui.table import DataPage, RowsModel
    from subnetsleuth.views import Column

    m = RowsModel([Column("ip", "IP", "ip", 100), Column("n", "N", "int", 50)])
    m.sort(0, Qt.AscendingOrder)
    m.set_rows([{"ip": "10.0.0.10", "n": 2}, {"ip": "10.0.0.2", "n": 10}, {"ip": "9.0.0.1", "n": 1}])
    assert [r["ip"] for r in m.rows] == ["9.0.0.1", "10.0.0.2", "10.0.0.10"]
    m.sort(1, Qt.DescendingOrder)
    assert [r["n"] for r in m.rows] == [10, 2, 1]
    win.navigate("hosts")  # pages load lazily; the default sort is applied with the first rows
    _pump(qapp, 30)
    page = win.pages["hosts"]
    assert isinstance(page, DataPage)
    hdr = page.view.horizontalHeader()
    ip_col = next(i for i, c in enumerate(page.model.columns) if c.key == "ip")
    assert hdr.sortIndicatorSection() == ip_col, (page._restored, page._sorted_once, page.model.sort_state(), QSettings().value("tables/hosts/header") is not None)
    assert not page.proxy.dynamicSortFilter()


# ------------------------------------------------------------------ 4: drag then save
def test_drag_then_immediate_save_keeps_the_position(qapp, win, tmp_path):
    win.navigate("map")
    _pump(qapp, 100)
    nid, item = next(iter(win.topology.nodes.items()))
    item.setPos(item.pos().x() + 123, item.pos().y() + 45)  # a drag: the 400 ms store timer starts
    assert win.topology._save_timer.isActive()
    out = tmp_path / "dragged.sleuth"
    assert win._write(str(out))
    saved = Inventory.load(str(out))
    x, y = saved.layout[win.topology.preset][nid]
    assert (round(item.pos().x(), 1), round(item.pos().y(), 1)) == (x, y)


# ------------------------------------------------------------------ 5: notes flush
def test_pending_note_is_flushed_on_selection_change_and_before_save(qapp, win, tmp_path):
    ids = [ip for ip in win.inv.hosts if ip not in win.inv.ip_to_device][:2]
    a, b = ids
    win.open_node(a)
    _pump(qapp, 20)
    win.details.doc.notes.setPlainText("closet B, patch panel 3")
    assert win.details.doc._timer.isActive()
    win.select_node(b)  # switching items must not lose the note typed half a second ago
    assert win.inv.note(a).get("notes") == "closet B, patch panel 3"
    win.details.doc.notes.setPlainText("rack 2")
    out = tmp_path / "notes.sleuth"
    assert win._write(str(out))
    assert Inventory.load(str(out)).note(b).get("notes") == "rack 2"
    win.details.doc.site.setText("HQ")
    win.details.doc._timer.start()
    win.details.clear()  # clearing the panel flushes too
    assert win.inv.note(b).get("site") == "HQ"


# ------------------------------------------------------------------ 6: backups / revert
def test_saving_rotates_three_backups(qapp, win, tmp_path):
    from subnetsleuth.gui.fileutil import backup_paths

    out = tmp_path / "p.sleuth"
    contents = []
    for i in range(5):
        win.inv.project["description"] = f"version {i}"
        assert win._write(str(out))
        contents.append(out.read_text(encoding="utf-8"))
    b1, b2, b3 = backup_paths(str(out))
    assert all(os.path.exists(p) for p in (b1, b2, b3))
    assert not os.path.exists(f"{out}.bak4")
    assert open(b1, encoding="utf-8").read() == contents[3]
    assert open(b2, encoding="utf-8").read() == contents[2]
    assert open(b3, encoding="utf-8").read() == contents[1]
    # revert to saved reloads the file and drops the dirty edit
    win.path = str(out)
    win.inv.project["description"] = "unsaved"
    win.set_dirty(True)
    win.revert_to_saved() if not win.dirty else None
    import subnetsleuth.gui.mainwindow as mw

    orig = QMessageBox.question
    QMessageBox.question = staticmethod(_yes)
    try:
        win.revert_to_saved()
    finally:
        QMessageBox.question = orig
    assert win.inv.project["description"] == "version 4" and not win.dirty
    assert mw.backup_paths is backup_paths


# ------------------------------------------------------------------ 7 / 20: forget via the model API, undo
def test_forget_uses_remove_host_and_is_undoable(qapp, win):
    calls = []
    inv = win.inv
    host = next(ip for ip in inv.hosts if ip not in inv.ip_to_device)

    def remove_host(ip):
        calls.append(ip)
        inv.hosts.pop(ip, None)
        inv.reindex()

    inv.remove_host = remove_host  # the model API (present on main; a fallback exists when absent)
    assert win.forget(host, confirm=False)
    assert calls == [host] and host not in inv.hosts and win.dirty
    assert win.undo_stack.canUndo()
    win.undo()
    assert host in win.inv.hosts
    win.redo()
    assert host not in win.inv.hosts


def test_forget_device_and_undo_restores_it(qapp, win):
    did = next(iter(win.inv.devices))
    dev = win.inv.devices[did]
    assert win.forget(did, confirm=False)
    assert did not in win.inv.devices and did not in win.inv.ip_to_device
    win.undo()
    assert win.inv.devices[did] is dev and win.inv.ip_to_device[did] == did


def test_undo_of_a_note_edit(qapp, win):
    node = next(ip for ip in win.inv.hosts if ip not in win.inv.ip_to_device and not win.inv.note(ip))
    win.annotate(node, {"notes": "first"})
    assert win.inv.note(node)["notes"] == "first"
    assert win.undo_stack.count() == 1
    win.undo()
    assert "notes" not in win.inv.note(node)
    win.redo()
    assert win.inv.note(node)["notes"] == "first"
    # keystrokes on the same node within a few seconds are one step
    win.annotate(node, {"notes": "first second"})
    assert win.undo_stack.count() == 1
    win.undo()
    assert "notes" not in win.inv.note(node)


def test_relayout_is_undoable(qapp, win):
    win.navigate("map")
    _pump(qapp, 100)
    nid, item = next(iter(win.topology.nodes.items()))
    item.setPos(item.pos().x() + 50, item.pos().y())
    win.topology.flush_positions()
    key = win.topology.preset
    before = dict(win.inv.layout[key])
    win.topology.relayout()
    assert key not in win.inv.layout
    win.undo()
    assert win.inv.layout[key] == before


# ------------------------------------------------------------------ 10: map selection stability, deferred fit
def test_rebuild_keeps_multi_selection_without_flipping_details(qapp, win):
    win.navigate("map")
    _pump(qapp, 100)
    items = list(win.topology.nodes.values())[:3]
    for it in items:
        it.setSelected(True)
    emitted = []
    win.topology.nodeSelected.connect(emitted.append)
    win.topology.rebuild(keep_view=True)
    _pump(qapp, 30)
    assert emitted == []
    assert {i.node_id for i in win.topology.scene.selectedItems()} == {i.node_id for i in items}


def test_path_fit_is_not_overridden_by_the_deferred_whole_map_fit(qapp, win):
    inv = win.inv
    leaf = next(ip for ip, h in inv.hosts.items() if ip not in inv.ip_to_device and any(x.get("via") == "fdb" for x in h.seen_on))
    win.navigate("overview")
    win.topology.nodes.clear()  # force a rebuild with keep_view=False when the map is shown
    win._stale.add("map")
    win.trace_path(leaf)
    zoom_after_path = win.topology.view._zoom
    _pump(qapp, 150)  # the deferred fit from rebuild would run here
    assert win.topology.view._zoom == pytest.approx(zoom_after_path)
    assert sum(1 for it in win.topology.nodes.values() if it.found) >= 2


# ------------------------------------------------------------------ 11: bar text colour
def test_bar_text_is_white_only_when_the_fill_covers_it():
    from subnetsleuth.gui.table import bar_text_color

    r = QRect(0, 0, 100, 20)
    assert bar_text_color(50.0, r, text_width=30) == "text"
    assert bar_text_color(0.0, r, text_width=30) == "text"
    assert bar_text_color(100.0, r, text_width=30) == "white"
    assert bar_text_color(96.0, r, text_width=30) == "white"
    assert bar_text_color(80.0, r, text_width=30) == "text"


# ------------------------------------------------------------------ 12: faceplate
def test_faceplate_keeps_port_n_names_and_disambiguates_uplinks():
    from subnetsleuth.gui.portpanel import is_logical_interface, port_labels

    assert not is_logical_interface("Port 1") and not is_logical_interface("Port24")
    assert is_logical_interface("Po1") and is_logical_interface("Port-channel1") and is_logical_interface("Vlan10") and is_logical_interface("lo0")
    ports = [{"name": f"TwentyFiveGigE1/0/{i}"} for i in range(1, 5)] + [{"name": "TenGigabitEthernet1/1/1", "neighbor": "core"}]
    labels = port_labels(ports)
    assert labels[1:4] == ["2", "3", "4"]
    assert labels[0] == "Twe1/0/1" and labels[4] == "Te1/1/1"
    stack = [{"name": "GigabitEthernet1/0/1"}, {"name": "GigabitEthernet2/0/1"}, {"name": "GigabitEthernet1/0/2"}]
    assert port_labels(stack) == ["1/0/1", "2/0/1", "2"]


def test_faceplate_geometry_matches_its_rows(qapp):
    from subnetsleuth.gui.portpanel import _Faceplate

    fp = _Faceplate()
    fp.set_ports([{"name": f"Port {i}"} for i in range(1, 9)])
    assert fp.rows == 1 and fp._grid_pos(7) == (7, 0)
    assert fp.sizeHint().height() < 2 * (fp.cell + fp.gap) + 24
    fp.set_ports([{"name": f"Gi1/0/{i}"} for i in range(1, 25)])
    assert fp.rows == 2 and fp._grid_pos(1) == (0, 1) and fp._rect(23).right() <= fp.sizeHint().width()


# ------------------------------------------------------------------ 13: capture log per device
def test_capture_progress_reports_each_devices_own_change(qapp, monkeypatch):
    from subnetsleuth.gui import capturedlg

    class Cap:
        ok = True
        text = "x"
        version = ""
        error = ""

    monkeypatch.setattr(capturedlg, "capture_config", lambda *a, **k: Cap())
    results = iter([True, False, False])
    monkeypatch.setattr(capturedlg, "store_config", lambda inv, did, cap: next(results))
    inv = Inventory.load(SAMPLE)
    ids = list(inv.devices)[:3]
    w = capturedlg.CaptureWorker(inv, ids, {"username": "u", "password": "p", "port": 22, "key": None})
    msgs = []
    w.progress.connect(lambda did, ok, msg: msgs.append(msg))
    w.run()
    assert msgs == ["captured (changed)", "captured (unchanged)", "captured (unchanged)"]


# ------------------------------------------------------------------ 14: render cap
def test_render_image_caps_the_long_side(qapp):
    from subnetsleuth.gui.topology import MAX_RENDER_SIDE, TopologyPage

    page = TopologyPage()
    page.scene.addItem(QGraphicsRectItem(QRectF(0, 0, 10, 10)))
    page.scene.addItem(QGraphicsRectItem(QRectF(30000, 12000, 10, 10)))
    scale, w, h = page.render_size(2.0)
    assert max(w, h) <= MAX_RENDER_SIDE and scale < 2.0
    img = page.render_image(2.0)
    assert not img.isNull() and max(img.width(), img.height()) <= MAX_RENDER_SIDE


# ------------------------------------------------------------------ 15: credential label
def test_default_credential_label_has_no_community_characters(qapp):
    from subnetsleuth.gui.credentials import CredentialEditor, CredentialStore

    store = CredentialStore()
    dlg = CredentialEditor(store, None, ordinal=3)
    dlg.v2.setChecked(True)
    dlg.community.setText("s3cretcommunity")
    c = dlg._apply()
    assert c is not None
    assert "s3" not in c.label and "cret" not in c.label
    assert c.label in ("v2c credential 3", "v2c #3") or c.label.startswith("v2c ")
    assert "…" not in c.label


# ------------------------------------------------------------------ 16: tools stale process
def test_stale_process_finished_does_not_null_the_new_run(qapp):
    from subnetsleuth.gui.credentials import CredentialStore
    from subnetsleuth.gui.tools import ToolsPanel

    tp = ToolsPanel(CredentialStore())
    tp._run(["sleep", "5"])
    first = tp.proc
    tp._run(["sleep", "5"])  # replaces (kills) the first
    assert tp.proc is not None and tp.proc is not first
    tp._finished(first)  # a late signal from the old process
    assert tp.proc is not None and tp.b_stop.isEnabled()
    tp.stop()
    assert tp.proc is None


# ------------------------------------------------------------------ 17: query dialog uses the rows model
def test_query_dialog_uses_rows_model(qapp, win):
    from subnetsleuth.gui.querydlg import QueryDialog
    from subnetsleuth.gui.table import RowsModel

    qd = QueryDialog(win.snapshot, win)
    qd.edit.setText("hosts where os ~ windows")
    qd.run()
    assert isinstance(qd.model, RowsModel) and qd.row_count() > 0
    assert qd.table.model() is qd.proxy
    qd.close()


# ------------------------------------------------------------------ 19: labels, dashes, export dir
def test_display_maps_role_keys_and_dashes_zero_durations(qapp):
    from subnetsleuth.gui.table import DASH, display
    from subnetsleuth.views import Column

    assert display(Column("role", "Type"), "workstation") == "Workstation"
    assert display(Column("role", "Type"), "media") == "Media / AV device"
    assert display(Column("role", "Type"), "something-new") == "something-new"
    assert display(Column("seconds", "Duration", "duration"), 0) == DASH
    assert display(Column("seconds", "Duration", "duration"), 90) == "1m 30s"


def test_export_paths_go_through_the_shared_export_dir(qapp, tmp_path):
    from subnetsleuth.gui.fileutil import export_dir

    QSettings().setValue("ui/export_dir", str(tmp_path))
    assert export_dir() == str(tmp_path)
    QSettings().remove("ui/export_dir")
    assert export_dir(str(tmp_path / "x" / "p.sleuth")) == str(tmp_path / "x")


# ------------------------------------------------------------------ 22: acknowledge
def test_acknowledged_findings_are_hidden_until_shown(qapp, win):
    win.navigate("findings")
    _pump(qapp, 30)
    page = win.pages["findings"]
    total = page.model.rowCount()
    assert total > 0
    row = page.model.rows[0]
    win.acknowledge("findings", row, True)
    assert page.model.rowCount() == total - 1
    key = win.finding_key("findings", row)
    assert win.inv.note(key).get("acknowledged") and win.dirty
    page.show_ack.setChecked(True)
    _pump(qapp, 20)
    assert page.model.rowCount() == total
    assert any(r.get("_ack") for r in page.model.rows)
    win.acknowledge("findings", row, False)
    assert not win.inv.note(key)


# ------------------------------------------------------------------ 24: listen dialog tracking
def test_listen_dialog_tracks_new_events_by_seq_or_identity(qapp):
    from collections import deque

    from subnetsleuth.gui.listendlg import ListenDialog

    class Ev:
        def __init__(self, i, seq=None):
            self.i = i
            if seq is not None:
                self.seq = seq

    ld = ListenDialog(None)
    buf = deque(maxlen=5)
    for i in range(3):
        buf.append(Ev(i))
    new = ld._new_events(list(buf))
    assert [e.i for e in new] == [0, 1, 2]
    ld._last_obj = new[-1]
    for i in range(3, 9):  # the deque wraps: absolute indexes would now be wrong
        buf.append(Ev(i))
    new = ld._new_events(list(buf))
    assert [e.i for e in new] == [4, 5, 6, 7, 8]  # everything shown before was evicted
    ld2 = ListenDialog(None)
    evs = [Ev(i, seq=i) for i in range(5)]
    assert len(ld2._new_events(evs)) == 5
    ld2._last_seq = 2
    assert [e.i for e in ld2._new_events(evs)] == [3, 4]


# ------------------------------------------------------------------ 8: reconcile dialog
def test_reconcile_dialog_resolves_the_current_inventory_and_applies_on_reject(qapp, win, tmp_path):
    from subnetsleuth.gui.reconciledlg import ReconcileDialog

    lst = tmp_path / "assets.csv"
    dev = next(iter(win.inv.devices.values()))
    win.inv.annotate(dev.id, site="")  # notes are only copied where the field is still empty
    lst.write_text(f"Hostname,IP Address,Location\n{dev.name},{dev.id},Head office\n", encoding="utf-8")
    dlg = ReconcileDialog(lambda: win.inv, win)
    dlg.load(str(lst))
    dlg._run()
    assert dlg.rec is not None
    dlg.copy_notes.setChecked(True)
    applied = []
    dlg.applied.connect(lambda: applied.append(1))
    old_inv = win.inv
    win.inv = win.inv.copy()  # a scan finished meanwhile: the dialog must write into the new object
    dlg.reject()
    assert applied and win.inv.note(dev.id).get("site") == "Head office"
    assert not old_inv.note(dev.id).get("site")


# ------------------------------------------------------------------ helpers
def test_copy_inventory_matches_inventory_copy(qapp):
    from subnetsleuth.gui.jobs import copy_inventory

    inv = Inventory.load(SAMPLE)
    a = copy_inventory(inv)
    assert a is not inv and a.to_dict() == inv.copy().to_dict()
    a.hosts.clear()
    assert inv.hosts


def test_job_registry_describes_and_stops(qapp):
    from subnetsleuth.gui.jobs import JobRegistry

    reg = JobRegistry()
    assert not reg.busy() and reg.describe() == "a background job"
    j1, j2 = _SlowJob(), _SlowJob()
    reg.add(j1, "the scan")
    reg.add(j2, "the config capture")
    j1.start()
    j2.start()
    assert _wait(qapp, lambda: j1.isRunning() and j2.isRunning(), 5)
    assert reg.busy() and reg.describe() == "the scan and the config capture"
    assert "Wait for" in reg.wait_message()
    reg.stop_all()
    assert reg.wait_all(5000)
    assert _wait(qapp, lambda: len(reg) == 0, 5)
    assert not reg.busy()
