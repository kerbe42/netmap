"""Render the demo video: the desktop app driven offscreen through a live scan and a tour.

    QT_QPA_PLATFORM=offscreen python tools/make_demo_video.py OUTDIR

Writes captioned frames to OUTDIR/frames/ and an ffmpeg concat list, OUTDIR/frames.txt, that
gives each frame its on-screen time. Encode it with

    ffmpeg -f concat -safe 0 -i OUTDIR/frames.txt -vf "fps=30,format=yuv420p" \\
           -c:v libx264 -crf 22 -movflags +faststart demo.mp4

Nothing leaves the machine. The live scan crawls the simulated campus from tests/demonet.py
(the same one behind Help > Explore the sample network): the app's real scan pipeline runs,
and only the SNMP answers come from the simulator, slowed to a believable pace. It is a
seed-only scan, so there is no ping sweep and no DNS. The tour uses the bundled sample project.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEventLoop, QRect, QSettings, Qt  # noqa: E402
from PySide6.QtGui import QColor, QFont, QImage, QPainter  # noqa: E402
from PySide6.QtWidgets import QApplication, QTabWidget  # noqa: E402

W, H = 1600, 900  # 16:9, as the site plays it
SAMPLE = os.path.join(ROOT, "subnetsleuth", "data", "sample-campus.sleuth")


def pump(ms: int = 60) -> None:
    end = time.time() + ms / 1000
    while time.time() < end:
        QCoreApplication.processEvents(QEventLoop.AllEvents, 20)


class Film:
    """Frames with their on-screen durations, captioned along the bottom."""

    def __init__(self, out: str):
        self.dir = os.path.join(out, "frames")
        os.makedirs(self.dir, exist_ok=True)
        self.list_path = os.path.join(out, "frames.txt")
        self.entries: list[tuple[str, float]] = []

    def add(self, img: QImage, seconds: float, caption: str = "") -> None:
        img = img.convertToFormat(QImage.Format_RGB32).scaled(W, H, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
        if caption:
            p = QPainter(img)
            p.setRenderHint(QPainter.Antialiasing)
            band = QRect(0, H - 74, W, 74)
            p.fillRect(band, QColor(10, 14, 22, 215))
            f = QFont("DejaVu Sans")
            f.setPixelSize(23)
            f.setWeight(QFont.DemiBold)
            p.setFont(f)
            p.setPen(QColor(245, 247, 250))
            p.drawText(band.adjusted(36, 0, -36, 0), Qt.AlignVCenter | Qt.AlignLeft | Qt.TextWordWrap, caption)
            p.end()
        path = os.path.join(self.dir, f"f{len(self.entries):05d}.png")
        img.save(path)
        self.entries.append((path, seconds))

    def write(self) -> float:
        with open(self.list_path, "w", encoding="utf-8") as f:
            for path, secs in self.entries:
                f.write(f"file '{path}'\nduration {secs:.3f}\n")
            f.write(f"file '{self.entries[-1][0]}'\n")  # the concat demuxer drops the last duration otherwise
        return sum(s for _, s in self.entries)


def card(title: str, lines: list[str]) -> QImage:
    from subnetsleuth.gui.icons import app_pixmap

    img = QImage(W, H, QImage.Format_RGB32)
    img.fill(QColor(15, 23, 36))
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.drawPixmap(W // 2 - 64, 190, app_pixmap(128))
    f = QFont("DejaVu Sans")
    f.setPixelSize(64)
    f.setWeight(QFont.Bold)
    p.setFont(f)
    p.setPen(QColor(245, 247, 250))
    p.drawText(QRect(0, 350, W, 90), Qt.AlignCenter, title)
    f.setPixelSize(28)
    f.setWeight(QFont.Normal)
    p.setFont(f)
    p.setPen(QColor(180, 192, 210))
    for i, line in enumerate(lines):
        p.drawText(QRect(0, 460 + i * 48, W, 44), Qt.AlignCenter, line)
    p.end()
    return img


def over(win, dlg) -> QImage:
    """A dialog drawn over the dimmed window, as it appears on screen."""
    base = win.grab().toImage().convertToFormat(QImage.Format_RGB32)
    p = QPainter(base)
    p.fillRect(base.rect(), QColor(0, 0, 0, 110))
    d = dlg.grab().toImage()
    p.drawImage((base.width() - d.width()) // 2, max(40, (base.height() - d.height()) // 2 - 30), d)
    p.end()
    return base


def tab(win, prefix: str) -> None:
    tabs: QTabWidget = win.details.tabs
    for i in range(tabs.count()):
        if tabs.tabText(i).startswith(prefix):
            tabs.setCurrentIndex(i)
    pump(150)


def slow_campus_scan():
    """run_scan for the GUI worker, with the simulated campus answering SNMP at LAN pace."""
    from subnetsleuth.scan import run_scan
    from tests import demonet
    from tests.fake_snmp import FakeSession

    devs, _ptr = demonet.build()
    tables = {ip: d.values() for ip, d in devs.items()}

    class Session(FakeSession):
        async def get(self, *oids):
            await asyncio.sleep(0.04)
            return await super().get(*oids)

        async def walk(self, base):
            await asyncio.sleep(0.06)
            return await super().walk(base)

        async def walk_map(self, base):
            await asyncio.sleep(0.06)
            return await super().walk_map(base)

    async def prober(engine, ip, creds, timeout, retries, port=161):
        await asyncio.sleep(0.25)
        t = tables.get(ip)
        if t is None:
            await asyncio.sleep(0.35)  # no SNMP agent there: the request times out
            return None, None
        from subnetsleuth import oids as O

        s = Session(ip, t, creds[0])
        return s, await s.get(O.SYS_DESCR, O.SYS_OBJECTID, O.SYS_NAME, O.SYS_SERVICES)

    async def scan(inv, req, events=None, engine=None, prober_=None):
        return await run_scan(inv, req, events, engine=object(), prober=prober)

    return scan


def main(out: str) -> int:
    import tempfile

    QCoreApplication.setOrganizationName("subnetsleuth-demo")
    QCoreApplication.setApplicationName("SubnetSleuthDemo")
    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, tempfile.mkdtemp(prefix="subnetsleuth-demo-"))
    app = QApplication.instance() or QApplication([])
    from subnetsleuth.gui import worker as worker_mod
    from subnetsleuth.gui.mainwindow import MainWindow
    from subnetsleuth.gui.scandialog import ScanDialog
    from subnetsleuth.scan import ScanRequest
    from subnetsleuth.snmp import Credential

    film = Film(out)
    film.add(card("SubnetSleuth", ["Inventory and map a network you inherit", "Windows desktop app and command line"]), 3.5)

    win = MainWindow(recovery_dir="")
    win.resize(W, H)
    win.show()
    pump(300)

    # ---- the scan dialog: ranges of any size, with an estimate for the big one
    dlg = ScanDialog(win.store, {"targets": ["10.10.0.0/16", "10.20.0.0/24", "10.30.0.0/24"], "seeds": ["10.99.0.2"],
                                 "port_scan": True, "identify": True, "resolve_names": True}, parent=win)
    dlg.resize(760, 640)
    dlg.show()
    pump(200)
    film.add(over(win, dlg), 4.0, "Enter the ranges you look after, any size: a /16 is swept in full, with a time estimate")
    dlg.findChild(QTabWidget).setCurrentIndex(2)
    pump(150)
    film.add(over(win, dlg), 4.0, "Read-only by design, and nothing outside your ranges is ever contacted")
    dlg.close()

    # ---- a live scan of the simulated campus, the Now line showing what is in flight
    worker_mod.run_scan = slow_campus_scan()
    win.navigate("devices")
    req = ScanRequest(seeds=["10.99.0.2"], scope=["10.0.0.0/8"], workers=4, timeout=1.0, retries=0,
                      credentials=[Credential(kind="v3", user="subnetsleuth-ro", auth="SHA", priv="AES", label="hq-snmpv3")])
    win.start_scan(req, "Scan of the sample campus")
    caption = "A live scan of the sample campus (3x speed): the Now line shows what it is working on"
    started = time.time()
    while win.worker is not None and time.time() - started < 90:
        pump(330)
        film.add(win.grab().toImage(), 0.11, caption)
    pump(800)
    film.add(win.grab().toImage(), 3.0, "Found by following the network's own neighbour, MAC and routing tables")

    # the tour: more room for the pages without the scan log
    win.activity_dock.hide()

    # ---- the tour, on the full sample project
    win.dirty = False
    win.open_project(SAMPLE)
    win.path = None
    win.navigate("overview")
    pump(500)
    film.add(win.grab().toImage(), 4.0, "At a glance: devices by role and vendor, hosts, subnets, what needs attention")
    win.navigate("map")
    win.details_dock.hide()  # the map gets the whole width
    pump(300)
    win.topology.set_preset("physical")
    pump(300)
    win.topology.view.fit()
    pump(200)
    film.add(win.grab().toImage(), 4.0, "The physical topology, from LLDP/CDP neighbours, MAC tables and routes")
    win.topology.set_preset("logical")
    pump(300)
    win.topology.view.fit()
    pump(200)
    film.add(win.grab().toImage(), 3.5, "The logical view: subnets, gateways and the routers between them")
    win.details_dock.show()
    pump(100)
    win.resizeDocks([win.details_dock], [720], Qt.Horizontal)
    inv = win.inv
    sw = next((d for d, dev in inv.devices.items() if dev.role in ("switch", "l3switch") and len(dev.interfaces) >= 24), None)
    if sw:
        win.navigate("devices")
        win.open_node(sw)
        pump(200)
        film.add(win.grab().toImage(), 3.5, "Every device: model, serial, software, interfaces, neighbours, ARP, routes")
        tab(win, "Ports panel")
        film.add(win.grab().toImage(), 3.5, "A switch faceplate: each port's state, VLAN, speed and what is plugged in")
    host = next((ip for ip, h in inv.hosts.items() if ip not in inv.ip_to_device and h.evidence and h.confidence == "high"), None)
    if host:
        win.navigate("hosts")
        win.open_node(host)
        tab(win, "Why")
        film.add(win.grab().toImage(), 3.5, "Every host typed and named, with the evidence behind each guess")
    cidr = max(win.snapshot.ipam.values(), key=lambda r: r["used"])["cidr"]
    win.navigate("subnets")
    win.open_node(cidr)
    pump(200)
    film.add(win.grab().toImage(), 3.5, "Each subnet's address map: what is used, what is free, what is on it")
    leaf = next((ip for ip, h in inv.hosts.items() if ip not in inv.ip_to_device and any(x.get("via") == "fdb" for x in h.seen_on)), None)
    if leaf:
        win.navigate("map")
        win.details_dock.hide()
        win.topology.set_preset("physical")
        pump(300)
        win.trace_path(leaf)
        pump(400)
        win.topology.view.fit()
        pump(200)
        film.add(win.grab().toImage(), 3.5, "Trace the path to any address, switch by switch and hop by hop")
        win.topology.clear_focus()
        win.details_dock.show()
        pump(100)
        win.resizeDocks([win.details_dock], [720], Qt.Horizontal)
    deep = next(iter(inv.deep_scans), None)
    if deep:
        from subnetsleuth.gui.deepscandlg import DeepScanDialog

        win.navigate("hosts")
        win.open_node(deep)
        pump(200)
        dd = DeepScanDialog([deep], win)
        dd.show()
        pump(150)
        film.add(over(win, dd), 3.5, "Deep scan any address: every TCP port, versions, OS and safe Nmap scripts")
        dd.close()
        tab(win, "Deep scan")
        film.add(win.grab().toImage(), 4.0, "Kept in the project: each port's product and version, OS guesses, the path")
        tab(win, "Scripts")
        film.add(win.grab().toImage(), 3.0, "...and what the scripts read: certificates, page titles, SSH host keys")
    win.navigate("findings")
    pump(250)
    film.add(win.grab().toImage(), 3.5, "Needs attention: the findings worth acting on, each linked to its device")
    win.navigate("compliance")
    pump(250)
    film.add(win.grab().toImage(), 3.0, "Configuration checks against hardening standards, and end-of-life hardware")
    film.add(card("SubnetSleuth", ["Free download for Windows, with a command line for Windows and Linux",
                                   "github.com/kerbe42/subnetsleuth"]), 4.5)
    total = film.write()
    print(f"{len(film.entries)} frames, {total:.1f} s -> {film.list_path}")
    win.dirty = False
    win.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "demo-video"))
