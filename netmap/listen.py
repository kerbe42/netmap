"""Listen for syslog messages and SNMP traps the network's devices send.

While you are on site you can point devices at your machine (or they may already be
configured to) and watch what they report - link flaps, auth failures, config changes,
OSPF/BGP events. This is a passive receiver: it binds UDP sockets and records what
arrives, keyed by source, and never sends anything.

Real devices send syslog to UDP/514 and traps to UDP/162, which need elevated privileges
to bind. When those are taken or blocked, the collector can listen on high ports instead
and reports which it managed to open. On Windows the sockets are opened with
``SO_EXCLUSIVEADDRUSE`` so binding over a port another collector already holds fails
loudly instead of silently splitting the traffic.

Traps are decoded (SNMPv1 and v2c, via pysnmp/pyasn1) to the trap name and its variable
bindings - ``linkDown ifIndex=3 ifDescr=Gi1/0/2`` - so the viewer shows what happened, not a
byte count. The community string a device sends is a credential; it is never written into
the event text (only whether it was one of the factory defaults, which is worth knowing).

Every :class:`Event` carries a monotonically increasing ``seq`` so a viewer that polls the
bounded ``events`` deque can tell which entries are new after old ones have rolled off.
"""
from __future__ import annotations

import itertools
import re
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

SYSLOG_SEVERITY = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
SYSLOG_FACILITY = ["kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
                   "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2",
                   "local3", "local4", "local5", "local6", "local7"]

DEFAULT_COMMUNITIES = frozenset({"public", "private"})

# well-known trap OIDs (SNMPv2-MIB / IF-MIB) -> name
TRAP_NAMES = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    "1.3.6.1.4.1.9.9.43.2.0.1": "ciscoConfigManEvent",
    "1.3.6.1.4.1.9.9.41.2.0.1": "clogMessageGenerated",
    "1.3.6.1.4.1.9.9.187.0.1": "cbgpFsmStateChange",
    "1.3.6.1.2.1.14.16.2.2": "ospfNbrStateChange",
    "1.3.6.1.2.1.15.7.1": "bgpEstablished",
    "1.3.6.1.2.1.15.7.2": "bgpBackwardTransition",
    "1.3.6.1.4.1.9.9.46.2.0.1": "vtpConfigRevNumberError",
    "1.3.6.1.4.1.9.9.147.2.0.1": "ciscoEnvMonShutdownNotification",
}
_V1_GENERIC = ["coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss"]
# well-known varbind OID prefixes -> short name (the trailing instance is kept as the value's context)
VARBIND_NAMES = {
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1": "ifName",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.6.3.1.1.4.1": "snmpTrapOID",
    "1.3.6.1.6.3.1.1.4.3": "snmpTrapEnterprise",
    "1.3.6.1.6.3.18.1.3": "snmpTrapAddress",
    "1.3.6.1.4.1.9.9.43.1.1.6.1.3": "ccmHistoryEventCommandSource",
    "1.3.6.1.4.1.9.9.43.1.1.6.1.4": "ccmHistoryEventConfigSource",
    "1.3.6.1.4.1.9.9.43.1.1.6.1.5": "ccmHistoryEventConfigDestination",
    "1.3.6.1.4.1.9.9.41.1.2.3.1.2": "clogHistFacility",
    "1.3.6.1.4.1.9.9.41.1.2.3.1.3": "clogHistSeverity",
    "1.3.6.1.4.1.9.9.41.1.2.3.1.5": "clogHistMsgText",
}
_IF_STATUS = {1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
_SKIP_VARBINDS = {"sysUpTime", "snmpTrapOID", "snmpTrapEnterprise"}

_seq = itertools.count(1)
_seq_lock = threading.Lock()


def next_seq() -> int:
    with _seq_lock:
        return next(_seq)


@dataclass
class Event:
    time: float
    source: str
    kind: str  # syslog | trap
    severity: str = ""
    facility: str = ""
    message: str = ""
    seq: int = 0  # monotonically increasing across all events this process records
    details: dict = field(default_factory=dict)  # trap: {version, trap_oid, trap, varbinds:[{oid,name,value}]}


def _skip_sd(text: str) -> str:
    """Skip RFC 5424 STRUCTURED-DATA ("-" or one or more [..] elements, with \\] escapes) and
    return what follows it (the MSG), without its leading space."""
    if text.startswith("-"):
        return text[1:].lstrip(" ")
    i = 0
    n = len(text)
    while i < n and text[i] == "[":
        j = i + 1
        while j < n:
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == "]":
                break
            j += 1
        i = j + 1
    return text[i:].lstrip(" ")


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
    # RFC5424: "1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]"
    if msg[:2] == "1 ":
        parts = msg.split(" ", 6)
        if len(parts) >= 7:
            msg = _skip_sd(parts[6])
        else:
            msg = ""
        msg = msg.lstrip("﻿")  # a UTF-8 BOM may start the MSG
    else:
        # RFC3164: "Mmm dd hh:mm:ss host tag: message" - strip a leading month/day/time + host
        m = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+\S+\s+(.*)$", msg)
        if m:
            msg = m.group(1)
    return Event(time=time.time(), source=source, kind="syslog", severity=severity, facility=facility,
                 message=msg.strip(), seq=next_seq())


def _community(data: bytes) -> str:
    """The v1/v2c community string out of the raw BER (a small, dependency-free read)."""
    try:
        if data and data[0] == 0x30:
            i = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
            if data[i] == 0x02:  # version INTEGER
                j = i + 2 + data[i + 1]
                if data[j] == 0x04:  # community OCTET STRING
                    clen = data[j + 1]
                    if clen < 0x80:
                        return data[j + 2:j + 2 + clen].decode("ascii", "replace")
    except (IndexError, ValueError):
        pass
    return ""


def _varbind_name(oid: str) -> tuple[str, str]:
    """(short name, instance suffix) for a varbind OID; ('', '') if unknown."""
    for prefix, name in VARBIND_NAMES.items():
        if oid == prefix or oid.startswith(prefix + "."):
            return name, oid[len(prefix) + 1:]
    return "", ""


def _render_value(name: str, val) -> str:
    try:
        if name in ("ifAdminStatus", "ifOperStatus"):
            return _IF_STATUS.get(int(val), str(int(val)))
        s = val.prettyPrint()
    except Exception:  # noqa: BLE001
        s = str(val)
    return s


def decode_trap(data: bytes) -> Optional[dict]:
    """Decode an SNMPv1/v2c trap message with pysnmp. Returns
    ``{"version", "trap_oid", "trap", "varbinds": [{"oid", "name", "value"}], "text"}`` or None
    when the bytes are not a decodable trap. The community string is not included."""
    try:
        from pyasn1.codec.ber import decoder
        from pysnmp.proto import api

        version = int(api.decodeMessageVersion(data))
        pmod = api.PROTOCOL_MODULES[version]
        msg, _rest = decoder.decode(data, asn1Spec=pmod.Message())
        pdu = pmod.apiMessage.get_pdu(msg)
    except Exception:  # noqa: BLE001 - not SNMP, or v3 (encrypted; not decodable without keys)
        return None

    trap_oid = ""
    varbinds: list[dict] = []
    try:
        if version == api.SNMP_VERSION_1 and pdu.isSameTypeWith(pmod.TrapPDU()):
            generic = int(pmod.apiTrapPDU.get_generic_trap(pdu))
            if generic < len(_V1_GENERIC):
                trap_oid = f"1.3.6.1.6.3.1.1.5.{generic + 1}"
            else:
                enterprise = pmod.apiTrapPDU.get_enterprise(pdu).prettyPrint()
                trap_oid = f"{enterprise}.0.{int(pmod.apiTrapPDU.get_specific_trap(pdu))}"
            raw_vbs = pmod.apiTrapPDU.get_varbinds(pdu)
        else:
            raw_vbs = pmod.apiPDU.get_varbinds(pdu)
    except Exception:  # noqa: BLE001
        return None

    for oid, val in raw_vbs:
        o = oid.prettyPrint()
        name, inst = _varbind_name(o)
        if name == "snmpTrapOID":
            trap_oid = val.prettyPrint()
            continue
        if name in _SKIP_VARBINDS:
            continue
        varbinds.append({"oid": o, "name": name, "instance": inst, "value": _render_value(name, val)})

    trap = TRAP_NAMES.get(trap_oid, "")
    if not trap and trap_oid:
        # enterprise-specific: "<enterprise>.0.<n>" -> the enterprise-relative name is unknown
        trap = f"trap {trap_oid}"
    parts = [trap or "SNMP notification"]
    for vb in varbinds[:8]:
        label = vb["name"] or vb["oid"]
        parts.append(f"{label}={vb['value']}")
    return {"version": {0: "v1", 1: "v2c"}.get(version, str(version)), "trap_oid": trap_oid, "trap": trap,
            "varbinds": varbinds, "text": " ".join(parts)}


def parse_trap(data: bytes, source: str) -> Event:
    """SNMP trap -> Event. The PDU is decoded to a name and its variable bindings when it is
    v1/v2c; the community string is never recorded (only whether it is a factory default)."""
    decoded = decode_trap(data)
    community = _community(data)
    details: dict = {}
    if decoded:
        text = decoded.pop("text")
        details = decoded
    else:
        text = f"SNMP trap ({len(data)} bytes; not decodable - SNMPv3 or malformed)"
    if community and community.lower() in DEFAULT_COMMUNITIES:
        text += f" [sent with the default community '{community}']"
        details["default_community"] = community
    sev = "warning" if details.get("trap") in ("linkDown", "authenticationFailure", "coldStart", "warmStart") else "notice"
    return Event(time=time.time(), source=source, kind="trap", severity=sev, message=text, seq=next_seq(), details=details)


class EventCollector:
    """Binds the syslog and trap UDP sockets and collects events into a bounded buffer.

    ``bind_addr`` chooses the interface to listen on; the default ``0.0.0.0`` (every
    interface) is kept for compatibility - pass the address of the interface facing the
    network being documented to keep the listener off any other network the machine is on.
    """

    def __init__(self, syslog_port: int = 514, trap_port: int = 162, maxlen: int = 5000,
                 on_event: Optional[Callable] = None, bind_addr: str = "0.0.0.0"):
        self.syslog_port = syslog_port
        self.trap_port = trap_port
        self.bind_addr = bind_addr
        self.events: deque = deque(maxlen=maxlen)
        self.on_event = on_event
        self._threads: list[threading.Thread] = []
        self._socks: list[socket.socket] = []
        self._running = False
        self.errors: list[str] = []
        self.listening: list[str] = []

    @staticmethod
    def _open(bind_addr: str, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if sys.platform == "win32":
            # exclusive: fail if another process holds the port instead of sharing it
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", 0xFFFFFFFB), 1)
        else:
            # lets a restart rebind while the old socket is closing; UDP does not share delivery
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_addr, port))
        s.settimeout(0.5)
        return s

    def start(self) -> list[str]:
        self._running = True
        for port, kind, parser in ((self.syslog_port, "syslog", parse_syslog), (self.trap_port, "trap", parse_trap)):
            try:
                s = self._open(self.bind_addr, port)
            except OSError as e:
                self.errors.append(f"{kind} UDP/{port}: {e}")
                continue
            self._socks.append(s)
            where = f"{kind} UDP/{port}" if self.bind_addr in ("", "0.0.0.0") else f"{kind} {self.bind_addr}:{port}"
            self.listening.append(where)
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
