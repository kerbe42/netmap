"""Listen for syslog messages and SNMP traps the network's devices send.

While you are on site you can point devices at your machine (or they may already be
configured to) and watch what they report - link flaps, auth failures, config changes,
OSPF/BGP events. This is a passive receiver: it binds UDP sockets and records what
arrives, keyed by source, and never sends anything.

Real devices send syslog to UDP/514 and traps to UDP/162, which need elevated privileges
to bind. When those are taken or blocked, the collector can listen on high ports instead
and reports which it managed to open.
"""
from __future__ import annotations

import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

SYSLOG_SEVERITY = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
SYSLOG_FACILITY = ["kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
                   "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
                   "local3", "local4", "local5", "local6", "local7"]


@dataclass
class Event:
    time: float
    source: str
    kind: str  # syslog | trap
    severity: str = ""
    facility: str = ""
    message: str = ""


def parse_syslog(data: bytes, source: str) -> Event:
    """Decode an RFC3164/5424 syslog datagram enough to show it: priority -> facility and
    severity, then the human message (the timestamp/host header is stripped when present)."""
    text = data.decode("utf-8", "replace").strip()
    facility = severity = ""
    msg = text
    if text.startswith("<") and ">" in text:
        try:
            pri = int(text[1:text.index(">")])
            facility = SYSLOG_FACILITY[pri >> 3] if (pri >> 3) < len(SYSLOG_FACILITY) else str(pri >> 3)
            severity = SYSLOG_SEVERITY[pri & 7]
        except (ValueError, IndexError):
            pass
        msg = text[text.index(">") + 1:]
    # RFC5424: "1 timestamp host app procid msgid ..." - drop the version+header if present
    if msg[:2] == "1 ":
        parts = msg.split(" ", 6)
        if len(parts) >= 7:
            msg = parts[6]
    else:
        # RFC3164: "Mmm dd hh:mm:ss host tag: message" - strip a leading month/day/time + host
        import re

        m = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+\S+\s+(.*)$", msg)
        if m:
            msg = m.group(1)
    return Event(time=time.time(), source=source, kind="syslog", severity=severity, facility=facility, message=msg.strip())


def parse_trap(data: bytes, source: str) -> Event:
    """SNMP trap: best-effort. Pull the v1/v2c community string from the BER if we can, so the
    event carries some context; a full varbind decode is not attempted here."""
    community = ""
    try:
        # SEQUENCE { version INTEGER, community OCTET STRING, ... } - find the community
        if data and data[0] == 0x30:
            i = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
            if data[i] == 0x02:  # version INTEGER
                vlen = data[i + 1]
                j = i + 2 + vlen
                if data[j] == 0x04:  # community OCTET STRING
                    clen = data[j + 1]
                    community = data[j + 2:j + 2 + clen].decode("ascii", "replace")
    except (IndexError, ValueError):
        pass
    note = f"SNMP trap ({len(data)} bytes)" + (f", community '{community}'" if community else "")
    return Event(time=time.time(), source=source, kind="trap", severity="notice", message=note)


class EventCollector:
    """Binds the syslog and trap UDP sockets and collects events into a bounded buffer."""

    def __init__(self, syslog_port: int = 514, trap_port: int = 162, maxlen: int = 5000, on_event: Optional[Callable] = None):
        self.syslog_port = syslog_port
        self.trap_port = trap_port
        self.events: deque = deque(maxlen=maxlen)
        self.on_event = on_event
        self._threads: list[threading.Thread] = []
        self._socks: list[socket.socket] = []
        self._running = False
        self.errors: list[str] = []
        self.listening: list[str] = []

    def start(self) -> list[str]:
        self._running = True
        for port, kind, parser in ((self.syslog_port, "syslog", parse_syslog), (self.trap_port, "trap", parse_trap)):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                s.settimeout(0.5)
            except OSError as e:
                self.errors.append(f"{kind} UDP/{port}: {e}")
                continue
            self._socks.append(s)
            self.listening.append(f"{kind} UDP/{port}")
            t = threading.Thread(target=self._loop, args=(s, parser), daemon=True)
            t.start()
            self._threads.append(t)
        return self.listening

    def _loop(self, sock, parser):
        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            ev = parser(data, addr[0])
            self.events.append(ev)
            if self.on_event:
                try:
                    self.on_event(ev)
                except Exception:  # noqa: BLE001
                    pass

    def stop(self):
        self._running = False
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._socks.clear()
