"""Deep scan and the live "Now:" line in the desktop app (offscreen Qt)."""
import os
import time

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QSettings  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

import subnetsleuth.deepscan as ds  # noqa: E402
import subnetsleuth.sweep as sw  # noqa: E402
from subnetsleuth.util import resource_path  # noqa: E402

from .test_deepscan import SAMPLE_XML  # noqa: E402

SAMPLE = resource_path("data", "sample-campus.sleuth")


@pytest.fixture(scope="module")
def qapp(tmp_path_factory):
    QCoreApplication.setOrganizationName("subnetsleuth-tests")
    QCoreApplication.setApplicationName("SubnetSleuthDeepScanTests")
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, str(tmp_path_factory.mktemp("settings")))
    yield QApplication.instance() or QApplication([])


def _wait(app, cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def win(qapp):
    from subnetsleuth.gui.mainwindow import MainWindow

    w = MainWindow(recovery_dir="")
    w.resize(1300, 850)
    w.show()
    w.open_project(SAMPLE)
    w.path = None
    qapp.processEvents()
    yield w
    w.dirty = False
    w._jobs.stop_all()
    w._jobs.wait_all(5000)
    w.close()
    qapp.processEvents()


def test_deep_scan_from_the_window_lands_on_the_details_tab(qapp, win, monkeypatch):
    from subnetsleuth.gui import deepscandlg

    ip = next(h for h in sorted(win.inv.hosts) if h not in win.inv.ip_to_device)

    async def fake_nmap(args, timeout, kind="", target=""):
        import asyncio

        from subnetsleuth import activity

        with activity.working(kind, target):  # as the real runner does
            await asyncio.sleep(1.3)  # long enough for a progress tick
        return sw.NmapRun(SAMPLE_XML.replace("10.20.0.15", ip), "ok")

    monkeypatch.setattr(ds, "_run_nmap", fake_nmap)
    monkeypatch.setattr(ds, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(deepscandlg.DeepScanDialog, "exec", lambda self: True)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.Yes)
    nows = []
    orig = win.show_now
    monkeypatch.setattr(win, "show_now", lambda summary, items: (nows.append(summary), orig(summary, items)))
    win.node_action("deepscan", ip)
    assert win._jobs.busy()
    # the results are merged by the done handler, which runs just after the thread ends
    assert _wait(qapp, lambda: not win._jobs.busy() and win._deep_worker is None, 20), "deep scan did not finish"
    assert any(n.startswith("deep scan " + ip) for n in nows)
    rec = win.inv.deep_scans[ip]
    assert rec["status"] == "ok" and {p["port"] for p in win.inv.hosts[ip].ports} >= {22, 443}
    assert "Deep scan finished" in win.scan_phase.text()
    win.open_node(ip)
    qapp.processEvents()
    titles = [win.details.tabs.tabText(i) for i in range(win.details.tabs.count())]
    assert "Deep scan (2 open)" in titles and "Scripts (4)" in titles


def test_now_line_shows_what_is_in_flight(qapp, win):
    win.scan_now.resize(900, 20)
    win.show_now("ping sweep 10.20.4.0/24, 10.20.5.0/24", ["ping sweep 10.20.4.0/24", "ping sweep 10.20.5.0/24"])
    assert win.scan_now.text().startswith("Now: ping sweep 10.20.4.0/24")
    assert "10.20.5.0/24" in win.scan_now.toolTip()


def test_deep_scan_dialog_reads_addresses(qapp):
    from subnetsleuth.gui.deepscandlg import DeepScanDialog, parse_addresses

    assert parse_addresses("10.0.0.1, 10.0.0.2\n10.0.0.1 nope") == (["10.0.0.1", "10.0.0.2"], ["nope"])
    dlg = DeepScanDialog(["10.0.0.5"])
    ips, opts = dlg.chosen()
    assert ips == ["10.0.0.5"] and opts.scripts and opts.timeout is None
    dlg.limit.setValue(45)
    assert dlg.chosen()[1].timeout == 45 * 60
