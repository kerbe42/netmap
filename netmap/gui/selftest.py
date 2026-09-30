"""`NetMap --selftest [--screenshots DIR] project.netmap`

Opens a project, visits every page, selects things, runs every export and (optionally)
saves a screenshot of each screen. CI runs it against the frozen Windows build, so a
missing Qt plugin, data file or import shows up as a failed build rather than as a
crash on someone's laptop.
"""
from __future__ import annotations

import os
import tempfile
import time
import traceback

from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer
from PySide6.QtWidgets import QApplication


def _pump(ms: int = 60):
    end = time.time() + ms / 1000
    while time.time() < end:
        QCoreApplication.processEvents(QEventLoop.AllEvents, 20)


def run_selftest(win, shots: str | None, strict: bool) -> int:
    lines: list[str] = []
    failures: list[str] = []

    def ok(msg):
        lines.append(f"ok    {msg}")

    def fail(msg):
        failures.append(msg)
        lines.append(f"FAIL  {msg}")

    def shot(name, widget=None):
        if not shots:
            return
        os.makedirs(shots, exist_ok=True)
        _pump(120)
        (widget or win).grab().save(os.path.join(shots, f"{name}.png"))

    try:
        win.resize(1500, 920)
        win.show()
        _pump(300)
        inv = win.inv
        if not inv.devices:
            fail("project has no devices (pass a project file)")
        s = win.snapshot
        shot("01-overview")
        order = ["map", "devices", "hosts", "subnets", "vlans", "links", "dependencies", "interfaces", "hardware", "findings", "compliance", "history"]
        for i, key in enumerate(order, 2):
            win.navigate(key)
            _pump(200)
            if key == "map":
                n = len(win.topology.nodes)
                (ok if n else fail)(f"map shows {n} nodes")
                win.topology.view.fit()
            else:
                rows = win.pages[key].model.rowCount()
                ok(f"{key}: {rows} rows")
            shot(f"{i:02d}-{key}")
        # details for a device with the most interfaces, each tab
        if inv.devices:
            dev = max(inv.devices.values(), key=lambda d: (len(d.neighbors), len(d.interfaces)))
            win.navigate("devices")
            win.open_node(dev.id)
            _pump(200)
            tabs = [win.details.tabs.tabText(i) for i in range(win.details.tabs.count())]
            (ok if len(tabs) >= 3 else fail)(f"device details tabs: {tabs}")
            for i in range(win.details.tabs.count()):
                win.details.tabs.setCurrentIndex(i)
                _pump(60)
            win.details.tabs.setCurrentIndex(0)
            shot("20-device-details")
            win.details.tabs.setCurrentIndex(1)
            shot("21-device-interfaces")
        hosts = [ip for ip in inv.hosts if ip not in inv.ip_to_device]
        if hosts:
            win.navigate("hosts")
            win.open_node(hosts[0])
            _pump(150)
            ok("host details")
        if inv.subnets:
            cidr = max(s.ipam.values(), key=lambda r: r["used"])["cidr"]
            win.navigate("subnets")
            win.open_node(cidr)
            _pump(200)
            shot("22-subnet-ipmap")
            ok(f"subnet details {cidr}")
        # a device with stored configs shows a Config tab with a diff
        insp = next((ip for ip, h in inv.hosts.items() if getattr(h, "system", None)), None)
        if insp:
            win.open_node(insp)
            _pump(200)
            tabs = [win.details.tabs.tabText(i) for i in range(win.details.tabs.count())]
            (ok if "System" in tabs else fail)(f"inspection tabs: {[t for t in tabs if t in ('System','Software','Connections','Dependencies')]}")
            shot("24-host-inspected")
        cfg_dev = next((d for d in inv.configs), None)
        if cfg_dev:
            win.open_node(cfg_dev)
            _pump(200)
            tabs = [win.details.tabs.tabText(i) for i in range(win.details.tabs.count())]
            (ok if "Config" in tabs else fail)(f"config tab present: {('Config' in tabs)}")
            for i in range(win.details.tabs.count()):
                if win.details.tabs.tabText(i) == "Config":
                    win.details.tabs.setCurrentIndex(i)
                    cv = win.details.tabs.currentWidget()
                    if hasattr(cv, "diff") and cv.diff.isEnabled():
                        cv.diff.setChecked(True)
                    _pump(150)
                    shot("23-config-diff")
        # map presets and layouts
        win.navigate("map")
        for preset in ("physical", "logical", "all"):
            win.topology.set_preset(preset)
            _pump(250)
            win.topology.view.fit()
            (ok if win.topology.nodes else fail)(f"map preset {preset}: {len(win.topology.nodes)} nodes, {len(win.topology.edges)} links")
            shot(f"30-map-{preset}")
        win.topology.set_preset("physical")
        win.topology.toggles["hosts"].setChecked(True)
        _pump(250)
        win.topology.view.fit()
        shot("33-map-physical-hosts")
        win.topology.toggles["hosts"].setChecked(False)
        for kind in ("organic", "radial", "layered"):
            i = win.topology.layout_box.findData(kind)
            win.topology.layout_box.setCurrentIndex(i)
            _pump(200)
            ok(f"layout {kind}")
        if inv.devices:
            core = max(inv.devices, key=lambda d: s.g.degree(d) if d in s.g else 0)
            win.topology.focus_on(core, 1)
            _pump(200)
            ok(f"focus on {core}: {len(win.topology.nodes)} nodes")
            shot("34-map-focus")
            win.topology.clear_focus()
        # trace a path to a leaf host and highlight it on the map
        leaf = next((ip for ip, h in inv.hosts.items() if ip not in inv.ip_to_device and any(x.get("via") == "fdb" for x in h.seen_on)), None)
        if leaf:
            win.trace_path(leaf)
            _pump(250)
            lit = sum(1 for it in win.topology.nodes.values() if getattr(it, "found", False))
            (ok if lit >= 2 else fail)(f"trace path lit {lit} hops")
            shot("35-map-path")
            win.topology.clear_focus()
        # exports
        out = tempfile.mkdtemp(prefix="netmap-selftest-")
        checks = [
            ("xlsx", lambda p: win.export_xlsx(p), "inventory.xlsx"),
            ("drawio", lambda p: win.export_drawio(p), "diagram.drawio"),
            ("html", lambda p: win.export_html(p), "map.html"),
            ("png", lambda p: win.export_map("png", p), "map.png"),
            ("svg", lambda p: win.export_map("svg", p), "map.svg"),
            ("pdf", lambda p: win.export_map("pdf", p), "map.pdf"),
            ("graphml", lambda p: win.export_graph("graphml", p), "map.graphml"),
            ("dot", lambda p: win.export_graph("dot", p), "map.dot"),
        ]
        for name, fn, fname in checks:
            p = os.path.join(out, fname)
            try:
                fn(p)
                size = os.path.getsize(p) if os.path.exists(p) else 0
                (ok if size > 200 else fail)(f"export {name}: {size} bytes")
            except Exception as e:  # noqa: BLE001
                fail(f"export {name}: {type(e).__name__}: {e}")
        files = win.export_csv(os.path.join(out, "inv-"))
        (ok if files and all(os.path.getsize(f) > 0 for f in files) else fail)(f"export csv: {len(files or [])} files")
        # save / reopen round trip, with a note
        first = next(iter(inv.devices), None)
        if first:
            win.annotate(first, {"notes": "selftest note", "site": "Lab", "tags": ["core"]})
        proj = os.path.join(out, "roundtrip.netmap")
        win._write(proj)
        win.open_project(proj)
        _pump(200)
        (ok if (not first or win.inv.note(first).get("notes") == "selftest note") else fail)("save and reopen keeps notes")
        # dialogs render
        from .credentials import CredentialsDialog
        from .scandialog import ScanDialog

        dlg = ScanDialog(win.store, win.inv.project.get("scan", {}), has_data=True, parent=win)
        dlg.targets.setPlainText("10.20.0.0/24\n10.30.0.10-40\n")
        dlg.exclude.setText("10.20.0.128/25")
        dlg.show()
        _pump(150)
        shot("40-scan-dialog", dlg)
        req, remember = dlg.request()
        (ok if req.targets and req.exclude else fail)(f"scan dialog builds a request: targets={req.targets}")
        dlg.close()
        # asset-list check against a small list written from the project itself (plus one ghost)
        from .reconciledlg import ReconcileDialog

        lst = os.path.join(out, "assets.csv")
        with open(lst, "w", encoding="utf-8") as f:
            f.write("Hostname,IP Address,Serial Number,Location\n")
            for d in list(win.inv.devices.values())[:4]:
                f.write(f"{d.name},{d.id},{d.serial},Head office\n")
            f.write("decommissioned-sw,10.254.254.254,FOC0000GONE,Basement\n")
        rd = ReconcileDialog(win.inv, win)
        rd.load(lst)
        rd._run()
        rd.show()
        _pump(150)
        (ok if rd.rec and len(rd.rec.missing) == 1 else fail)(f"asset list check: {len(rd.rec.found) if rd.rec else 0} found, {len(rd.rec.missing) if rd.rec else '?'} missing")
        shot("42-asset-check", rd)
        rd.reject()
        # DHCP import enriches hosts
        from .. import dhcp as _dhcp
        _lz = _dhcp.parse_leases("IPAddress,HostName,ClientId,AddressState\n10.10.0.201,DHCP-TEST-PC,00-50-56-01-02-03,Active\n")
        _before = len(win.inv.hosts)
        _sum = _dhcp.import_leases(win.inv, _lz)
        (ok if _sum["leases"] == 1 and "10.10.0.201" in win.inv.hosts else fail)(f"dhcp import: {_sum}")
        # syslog/trap listener binds high ports and receives a datagram
        import socket as _sock, time as _time
        from .listendlg import ListenDialog
        ld = ListenDialog(win.snapshot, win)
        ld.syslog_port.setValue(15514); ld.trap_port.setValue(16162); ld.toggle()
        listening = ld.collector is not None
        if listening:
            _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM); _s.sendto(b"<190>selftest syslog", ("127.0.0.1", 15514)); _s.close()
            _end = _time.time() + 3
            while _time.time() < _end and not ld.collector.events: _pump(100)
            _pump(800)
        (ok if listening and ld.collector and len(ld.collector.events) >= 1 else fail)(f"syslog listener received {len(ld.collector.events) if ld.collector else 0}")
        shot("43-listen", ld)
        ld.stop(); ld.close()
        # query console
        from .querydlg import QueryDialog
        qd = QueryDialog(win.snapshot, win)
        qd.edit.setText("hosts where os ~ windows and confidence = high")
        qd.run()
        _pump(150)
        (ok if qd.table.rowCount() > 0 else fail)(f"query console returned {qd.table.rowCount()} rows")
        shot("44-query", qd)
        qd.close()
        # switch front-panel view
        sw = next((d for d, dev in inv.devices.items() if dev.role in ("switch", "l3switch") and len(dev.interfaces) >= 4), None)
        if sw:
            win.open_node(sw)
            _pump(150)
            tabs = [win.details.tabs.tabText(i) for i in range(win.details.tabs.count())]
            (ok if "Ports panel" in tabs else fail)("ports panel tab present")
            for i in range(win.details.tabs.count()):
                if win.details.tabs.tabText(i) == "Ports panel":
                    win.details.tabs.setCurrentIndex(i)
            _pump(150)
            shot("25-ports-panel")
        cd = CredentialsDialog(win.store, win)
        cd.show()
        _pump(100)
        shot("41-credentials", cd)
        cd.close()
        # theme switch
        win.set_theme("dark")
        _pump(200)
        win.navigate("map")
        _pump(200)
        win.topology.view.fit()
        shot("50-map-dark")
        win.navigate("overview")
        _pump(150)
        shot("51-overview-dark")
        win.set_theme("light")
        _pump(100)
    except Exception:  # noqa: BLE001
        fail("unexpected error:\n" + traceback.format_exc())
    text = "\n".join(lines) + f"\n\n{'FAILED' if failures else 'PASSED'}: {len(failures)} failure(s)\n"
    try:
        print(text)
    except Exception:  # noqa: BLE001
        pass
    if shots:
        os.makedirs(shots, exist_ok=True)
        with open(os.path.join(shots, "selftest.txt"), "w", encoding="utf-8") as f:
            f.write(text)
    win.dirty = False
    win.close()
    QApplication.instance().processEvents()
    return 1 if failures and strict else (1 if failures else 0)
