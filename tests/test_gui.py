"""The desktop app, driven headless: every page and export, and real scans through its worker thread."""
import ipaddress
import os
import time

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QSettings  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from netmap import util  # noqa: E402
from netmap.scan import ScanRequest  # noqa: E402
from netmap.snmp import Credential  # noqa: E402

from . import demonet  # noqa: E402
from .conftest import PORT  # noqa: E402


@pytest.fixture(scope="module")
def qapp(tmp_path_factory):
    QCoreApplication.setOrganizationName("netmap-tests")
    QCoreApplication.setApplicationName("NetMapTests")
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, str(tmp_path_factory.mktemp("settings")))
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def loopback(monkeypatch):
    """Let in-process scans reach the snmpsim agents on 127/8 (never allowed in real use)."""
    monkeypatch.setattr(util, "ALWAYS_EXCLUDED", [n for n in util.ALWAYS_EXCLUDED if str(n) != "127.0.0.0/8"])


def _wait(app, cond, timeout=90.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


def _window():
    from netmap.gui.mainwindow import MainWindow

    return MainWindow()


def test_selftest_on_sample_project(qapp, tmp_path):
    from netmap.gui.selftest import run_selftest

    path = tmp_path / "sample.netmap"
    demonet.build_project(str(path))
    win = _window()
    win.open_project(str(path))
    assert len(win.inv.devices) == 11
    assert run_selftest(win, str(tmp_path / "shots"), strict=True) == 0
    assert (tmp_path / "shots" / "30-map-physical.png").stat().st_size > 10000


def test_scan_through_the_worker_thread(qapp, agents, loopback, tmp_path):
    win = _window()
    win.path = str(tmp_path / "scan.netmap")
    req = ScanRequest(seeds=["127.0.0.1"], scope=["127.0.0.0/8"], credentials=[Credential(kind="v2c", community="lab", label="lab")],
                      port=PORT, timeout=1.0, retries=0, workers=4)
    snapshots = []
    win.start_scan(req, "Test scan")
    win.worker.snapshot.connect(lambda d: snapshots.append(len(d["devices"])))
    assert _wait(qapp, lambda: win.worker is None), "scan did not finish"
    assert set(win.inv.devices) == {"127.0.0.1", "127.0.0.2", "127.1.0.2"}
    assert win.inv.history and not win.inv.history[-1]["cancelled"]
    assert win.pages["devices"].model.rowCount() >= 3 or "devices" in win._stale
    assert os.path.exists(win.path)  # a project with a path is saved when a scan finishes
    # notes made while documenting survive a rescan of that device
    win.annotate("127.0.0.2", {"notes": "distribution switch, closet B", "site": "HQ"})
    from netmap.gui.credentials import SavedCredential

    cred = SavedCredential(label="lab")
    win.store.set_secret(cred, "community", "lab")
    win.store.save([cred])
    win.inv.project["scan"] = {"scope": ["127.0.0.0/8"], "port": PORT, "timeout": 1.0, "retries": 0, "credential_ids": [cred.id], "resolve_names": False}
    first_seen = win.inv.devices["127.0.0.2"].first_seen
    polled = win.inv.devices["127.0.0.2"].collected_at
    win.rescan_device("127.0.0.2")
    assert _wait(qapp, lambda: win.worker is None), "rescan did not finish"
    d = win.inv.devices["127.0.0.2"]
    assert d.collected_at > polled and d.first_seen == first_seen
    assert win.inv.history[-1]["found"]["refreshed"] == 1
    assert win.inv.note("127.0.0.2")["notes"] == "distribution switch, closet B"
    win.dirty = False
    win.close()


def test_stop_keeps_what_was_found(qapp, agents, loopback):
    win = _window()
    # 254 silent addresses at 1s each: long enough to stop part way
    req = ScanRequest(targets=["127.9.9.0/24"], probe_all=True, credentials=[Credential(kind="v2c", community="lab", label="lab")],
                      port=PORT, timeout=1.0, retries=0, workers=4, sweep_max_prefix=24)
    win.start_scan(req, "Long scan")
    assert _wait(qapp, lambda: win.worker is not None and win.worker.isRunning(), 10)
    time.sleep(1.5)
    t0 = time.time()
    win.stop_scan()
    assert _wait(qapp, lambda: win.worker is None, 30), "stop did not end the scan"
    assert time.time() - t0 < 15
    assert win.inv.history[-1]["cancelled"] is True
    assert "127.9.9.0/24" in win.inv.subnets
    win.dirty = False
    win.close()


def test_scan_dialog_parses_ranges(qapp):
    from netmap.gui.scandialog import parse_ranges

    nets, bad = parse_ranges("10.1.0.0/24\n10.2.0.5  # one host\n10.3.0.10-10.3.0.13, 10.4.0.1-2\nnonsense")
    assert nets == ["10.1.0.0/24", "10.2.0.5/32", "10.3.0.10/31", "10.3.0.12/31", "10.4.0.1/32", "10.4.0.2/32"]
    assert bad == ["nonsense"]
    covered = sum(ipaddress.ip_network(n).num_addresses for n in nets if n.startswith("10.3."))
    assert covered == 4
