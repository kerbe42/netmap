"""Syslog/trap parsing and the UDP event collector (loopback)."""
import socket
import time

from subnetsleuth.listen import EventCollector, parse_syslog, parse_trap


def test_parse_syslog_rfc3164():
    ev = parse_syslog(b"<189>Sep 28 10:00:00 core-sw-01 %LINK-3-UPDOWN: Interface Gi1/0/2, changed state to down", "10.0.0.2")
    assert ev.severity == "notice" and ev.facility == "local7"
    assert "LINK-3-UPDOWN" in ev.message and ev.message.startswith("%LINK")
    assert ev.source == "10.0.0.2" and ev.kind == "syslog"


def test_parse_syslog_severity():
    assert parse_syslog(b"<0>kernel panic", "x").severity == "emergency"
    assert parse_syslog(b"plain message no pri", "x").message == "plain message no pri"


def test_parse_trap_community():
    # SEQUENCE(0x30) len; INTEGER version 1; OCTET STRING community "public"
    pkt = bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x04, 0x06]) + b"public" + b"\xa2\x00"
    ev = parse_trap(pkt, "10.0.0.9")
    assert ev.kind == "trap" and "public" in ev.message


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def test_collector_receives_on_high_ports():
    syslog_port, trap_port = _free_udp_port(), _free_udp_port()
    while trap_port == syslog_port:
        trap_port = _free_udp_port()
    c = EventCollector(syslog_port=syslog_port, trap_port=trap_port, on_event=None)
    listening = c.start()
    try:
        assert any("syslog" in x for x in listening), c.errors
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"<190>test message from a switch", ("127.0.0.1", syslog_port))
        s.close()
        end = time.time() + 3
        while time.time() < end and not c.events:
            time.sleep(0.05)
        assert c.events and c.events[-1].message == "test message from a switch"
    finally:
        c.stop()
