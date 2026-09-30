"""Quick checks against one address: ping, traceroute, reverse/forward DNS, SNMP system group."""
from __future__ import annotations

import html
import shutil
import socket
import sys

from PySide6.QtCore import QProcess, QThread, Signal
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget


def _console_encoding() -> str:
    if sys.platform == "win32":
        try:
            import ctypes

            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:  # noqa: BLE001
            return "cp437"
    return "utf-8"


def ping_command(target: str) -> list[str]:
    return ["ping", "-n", "4", target] if sys.platform == "win32" else ["ping", "-c", "4", target]


def trace_command(target: str) -> list[str]:
    if sys.platform == "win32":
        return ["tracert", "-d", "-w", "1000", "-h", "30", target]
    if shutil.which("traceroute"):
        return ["traceroute", "-n", "-w", "1", "-q", "1", target]
    return ["tracepath", "-n", target]


class _DnsThread(QThread):
    done = Signal(str)

    def __init__(self, target, parent=None):
        super().__init__(parent)
        self.target = target

    def run(self):
        out = []
        try:
            socket.inet_aton(self.target)
            is_ip = True
        except OSError:
            is_ip = False
        if is_ip:
            try:
                name, aliases, _ = socket.gethostbyaddr(self.target)
                out.append(f"PTR  {self.target} → {name}" + (f"  (aliases: {', '.join(aliases)})" if aliases else ""))
                try:
                    fwd = socket.gethostbyname_ex(name)[2]
                    ok = self.target in fwd
                    out.append(f"A    {name} → {', '.join(fwd)}" + ("" if ok else "   ← does not point back: stale or mismatched DNS"))
                except OSError as e:
                    out.append(f"A    {name}: {e}")
            except OSError as e:
                out.append(f"PTR  {self.target}: no reverse record ({e})")
        else:
            try:
                name, aliases, addrs = socket.gethostbyname_ex(self.target)
                out.append(f"A    {self.target} → {', '.join(addrs)}" + (f"  (canonical {name})" if name != self.target else ""))
            except OSError as e:
                out.append(f"A    {self.target}: {e}")
        self.done.emit("\n".join(out))


class ToolsPanel(QWidget):
    """A target box, four buttons, and the output of whatever ran last."""

    def __init__(self, cred_store, scope_check=None, parent=None):
        super().__init__(parent)
        self.store = cred_store
        self.scope_check = scope_check  # callable(ip) -> (allowed: bool, why: str)
        self.proc: QProcess | None = None
        self.target = QLineEdit()
        self.target.setPlaceholderText("address or name")
        self.target.returnPressed.connect(self.ping)
        self.b_ping = QPushButton("Ping")
        self.b_ping.clicked.connect(self.ping)
        self.b_trace = QPushButton("Traceroute")
        self.b_trace.clicked.connect(self.traceroute)
        self.b_dns = QPushButton("DNS")
        self.b_dns.clicked.connect(self.dns)
        self.b_snmp = QPushButton("SNMP test")
        self.b_snmp.setToolTip("Query the SNMP system group with each saved credential in turn")
        self.b_snmp.clicked.connect(self.snmp)
        self.b_stop = QPushButton("Stop")
        self.b_stop.clicked.connect(self.stop)
        self.b_stop.setEnabled(False)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumBlockCount(5000)
        self.out.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        top = QHBoxLayout()
        top.addWidget(QLabel("Target"))
        top.addWidget(self.target, 1)
        for b in (self.b_ping, self.b_trace, self.b_dns, self.b_snmp, self.b_stop):
            top.addWidget(b)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.addLayout(top)
        lay.addWidget(self.out, 1)

    def set_target(self, t: str):
        self.target.setText(t)

    def _t(self) -> str:
        return self.target.text().strip()

    def _allowed(self, t: str) -> bool:
        if not t:
            return False
        if self.scope_check:
            ok, why = self.scope_check(t)
            if not ok:
                self.out.appendPlainText(f"Not sent: {why}\n")
                return False
        return True

    def _run(self, cmd: list[str]):
        if self.proc is not None:
            self.stop()
        self.out.appendPlainText(f"$ {' '.join(cmd)}")
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        enc = _console_encoding()
        self.proc.readyReadStandardOutput.connect(lambda: self._append(bytes(self.proc.readAllStandardOutput()).decode(enc, "replace")))
        self.proc.finished.connect(self._finished)
        self.proc.errorOccurred.connect(lambda e: self.out.appendPlainText(f"could not run {cmd[0]}: {self.proc.errorString() if self.proc else e}"))
        self.b_stop.setEnabled(True)
        self.proc.start(cmd[0], cmd[1:])

    def _append(self, text: str):
        self.out.moveCursor(self.out.textCursor().MoveOperation.End)
        self.out.insertPlainText(text.replace("\r\n", "\n"))
        self.out.ensureCursorVisible()

    def _finished(self, *_):
        self.b_stop.setEnabled(False)
        self.out.appendPlainText("")
        self.proc = None

    def stop(self):
        if self.proc is not None:
            self.proc.kill()
            self.proc.waitForFinished(1000)
            self.proc = None
        self.b_stop.setEnabled(False)

    def ping(self):
        t = self._t()
        if self._allowed(t):
            self._run(ping_command(t))

    def traceroute(self):
        t = self._t()
        if self._allowed(t):
            self._run(trace_command(t))

    def dns(self):
        t = self._t()
        if not t:
            return
        self.out.appendPlainText(f"$ dns {t}")
        th = _DnsThread(t, self)
        th.done.connect(lambda text: self.out.appendPlainText(text + "\n"))
        th.start()
        self._dns_thread = th

    def snmp(self):
        t = self._t()
        if not self._allowed(t):
            return
        from .credentials import SnmpTestThread, describe_sysinfo

        saved = self.store.load()
        creds = [self.store.to_credential(c) for c in saved]
        if not creds:
            self.out.appendPlainText("No saved credentials: add one under Scan ▸ Credentials first.\n")
            return
        self.out.appendPlainText(f"$ snmp {t}  (trying {len(creds)} credential(s): {', '.join(c.label for c in creds)})")
        self.b_snmp.setEnabled(False)
        th = SnmpTestThread(t, creds, parent=self)

        def done(label, info, err):
            self.b_snmp.setEnabled(True)
            if err:
                self.out.appendPlainText(f"error: {err}\n")
            elif label is None:
                self.out.appendPlainText("no answer with any saved credential\n")
            else:
                self.out.appendPlainText(f"answered with “{label}”\n{describe_sysinfo(info)}\n")

        th.done.connect(done)
        th.start()
        self._snmp_thread = th
