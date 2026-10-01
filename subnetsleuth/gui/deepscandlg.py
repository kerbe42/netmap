"""Deep scan: the options dialog and the background worker. Read-only - see deepscan.py."""
from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Optional

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from .. import activity
from ..deepscan import DeepScanOptions, deep_scan_into
from ..sweep import find_nmap, is_admin
from .prefs import nmap_timeout_spin


def parse_addresses(text: str) -> tuple[list[str], list[str]]:
    """IP addresses from free text (spaces, commas, new lines). Returns (valid, not understood)."""
    good, bad = [], []
    for item in (x for x in re.split(r"[,\s;]+", text) if x):
        try:
            good.append(str(ipaddress.ip_address(item)))
        except ValueError:
            bad.append(item)
    return list(dict.fromkeys(good)), bad


class DeepScanDialog(QDialog):
    def __init__(self, addresses: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Deep scan with Nmap")
        admin = is_admin()
        need = "" if admin else "  (needs SubnetSleuth run as Administrator)"
        self.addresses = QLineEdit(" ".join(addresses))
        self.addresses.setPlaceholderText("e.g. 10.20.0.15  (several: separate with spaces)")
        self.udp = QCheckBox("Common UDP services too: DNS, DHCP, NTP, NetBIOS, SNMP, IKE, syslog, IPMI, SSDP, mDNS, BACnet" + need)
        self.scripts = QCheckBox("Run Nmap's safe information scripts (certificates, web page titles, SSH host keys, SMB/RDP names)")
        self.scripts.setChecked(True)
        self.os_detect = QCheckBox("Detect the operating system" + need)
        self.os_detect.setChecked(admin)
        self.trace = QCheckBox("Traceroute (the routers in between)" + need)
        self.trace.setChecked(admin)
        for w in (self.udp, self.os_detect, self.trace):
            w.setEnabled(admin)
        self.limit = nmap_timeout_spin(0)
        self.limit.setToolTip("Stop the deep scan of one address after this long. A filtered host can take 10-30 minutes.")
        form = QFormLayout()
        form.addRow("Address(es)", self.addresses)
        form.addRow("Time limit per address", self.limit)
        note = QLabel("Every TCP port (all 65,535), full service-version detection and the options below. Read-only: "
                      "nothing is changed on the target. Takes a few minutes per address, longer when ports are filtered; "
                      "the Activity panel shows the stage it is at, and Stop keeps whatever has finished.")
        note.setWordWrap(True)
        note.setObjectName("muted")
        self.problem = QLabel("")
        self.problem.setStyleSheet("color:#dc2626")
        self.bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.bb.button(QDialogButtonBox.Ok).setText("Deep scan")
        self.bb.accepted.connect(self.accept)
        self.bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        for w in (self.udp, self.scripts, self.os_detect, self.trace, note, self.problem, self.bb):
            lay.addWidget(w)
        self.addresses.textChanged.connect(self._check)
        if not find_nmap():
            self.problem.setText("Nmap is not installed. Install it from nmap.org, then try again.")
        self._check()
        self.resize(560, 0)

    def _check(self):
        good, bad = parse_addresses(self.addresses.text())
        ok = bool(good) and not bad and bool(find_nmap())
        if bad:
            self.problem.setText("Not an IP address: " + ", ".join(bad[:5]))
        elif find_nmap():
            self.problem.setText("")
        self.bb.button(QDialogButtonBox.Ok).setEnabled(ok)

    def chosen(self) -> tuple[list[str], DeepScanOptions]:
        minutes = self.limit.value()
        opts = DeepScanOptions(udp=self.udp.isChecked(), scripts=self.scripts.isChecked(), os_detect=self.os_detect.isChecked(),
                               traceroute=self.trace.isChecked(), timeout=minutes * 60 if minutes else None)
        return parse_addresses(self.addresses.text())[0], opts


class DeepScanWorker(QThread):
    progress = Signal(str, list)  # one-line summary of what is in flight, every item
    done = Signal(dict)

    def __init__(self, inv, ips: list[str], opts: DeepScanOptions, exclude: Optional[list] = None, parent=None):
        super().__init__(parent)
        self.inv = inv  # a copy of the project: results are merged on the UI thread when done
        self.ips = ips
        self.opts = opts
        self.exclude = exclude
        self.act = activity.Activity()
        self._loop = None
        self._task = None
        self._stop_requested = False
        self.result: Optional[dict] = None

    def stop(self):
        """Cancel: nmap is stopped, addresses already finished are kept."""
        self._stop_requested = True
        loop, task = self._loop, self._task
        if loop is not None and task is not None:
            loop.call_soon_threadsafe(task.cancel)

    def run(self):
        async def ticker():
            while True:
                await asyncio.sleep(1.0)
                self.progress.emit(self.act.summary(), [f"{i.kind} {i.describe()}" for i in self.act.now()])

        async def main():
            self._loop = asyncio.get_running_loop()
            self._task = asyncio.ensure_future(deep_scan_into(self.inv, self.ips, self.opts, exclude=self.exclude, act=self.act))
            if self._stop_requested:
                self._task.cancel()
            tick = asyncio.ensure_future(ticker())
            try:
                return await self._task
            finally:
                tick.cancel()

        try:
            result = asyncio.run(main())
        except asyncio.CancelledError:
            result = {"cancelled": True, "scanned": sum(1 for ip in self.ips if ip in self.inv.deep_scans), "refused": []}
        except Exception as e:  # noqa: BLE001
            result = {"error": f"{type(e).__name__}: {e}"}
        self.result = result
        self.done.emit(result)
