"""Config capture logic, tested with a fake SSH channel (no real device)."""
import time

from subnetsleuth.capture import Capture, capture_config, clean_config, commands_for, diff_configs, store_config
from subnetsleuth.model import Inventory


class FakeChannel:
    """Behaves like a paramiko shell channel: replays canned output for each command sent."""

    def __init__(self, responses: dict, banner="\r\nswitch> "):
        self.responses = responses
        self.buf = banner.encode()
        self.closed = False

    def send(self, data):
        cmd = data.strip()
        # echo the command, then its canned output, then a prompt
        self.buf += data.encode() if isinstance(data, str) else data
        self.buf += ("\n" + self.responses.get(cmd, "") + "\nswitch# ").encode()
        return len(data)

    def recv_ready(self):
        return bool(self.buf)

    def recv(self, n):
        chunk, self.buf = self.buf[:n], self.buf[n:]
        return chunk

    def close(self):
        self.closed = True


RUNNING = "!\nhostname core-sw-01\n!\ninterface Vlan10\n ip address 10.10.0.2 255.255.252.0\n!\nend"


def fake_transport(responses):
    def make(ip, user, pw, port, timeout):
        ch = FakeChannel(responses)
        return ch, ch
    return make


def test_commands_for_vendor():
    assert commands_for("ios-xe")[1] == "show running-config"
    assert commands_for("junos")[1].startswith("show configuration")
    assert commands_for("", "Fortinet")[1] == "show full-configuration"
    assert commands_for("", "unknown-vendor") == commands_for("")  # default


def test_capture_and_store(tmp_path):
    resp = {"terminal length 0": "", "show version": "Cisco IOS-XE Software, Version 17.9.4a", "show running-config": RUNNING}
    cap = capture_config("10.0.0.2", "admin", "pw", os_family="ios-xe", transport=fake_transport(resp))
    assert cap.ok, cap.error
    assert "hostname core-sw-01" in cap.text and "17.9.4a" in cap.version
    # command echoes and the version section are not in the stored config
    assert "show running-config" not in cap.text and "show version" not in cap.text

    inv = Inventory()
    assert store_config(inv, "10.0.0.2", cap) is True      # first capture = change
    assert store_config(inv, "10.0.0.2", cap) is False     # identical = no change
    assert len(inv.configs["10.0.0.2"]) == 1
    # a changed config appends a new revision
    cap2 = Capture(ok=True, text=cap.text.replace("core-sw-01", "core-sw-01-renamed"))
    assert store_config(inv, "10.0.0.2", cap2) is True
    assert len(inv.configs["10.0.0.2"]) == 2
    d = diff_configs(inv.configs["10.0.0.2"][0]["text"], inv.configs["10.0.0.2"][1]["text"])
    assert "-hostname core-sw-01" in d and "+hostname core-sw-01-renamed" in d
    # survives a project round-trip
    p = tmp_path / "p.sleuth"
    inv.save(str(p))
    assert Inventory.load(str(p)).configs["10.0.0.2"][1]["text"] == cap2.text


def test_capture_login_failure():
    def boom(ip, user, pw, port, timeout):
        raise OSError("Authentication failed")
    cap = capture_config("10.0.0.2", "admin", "bad", transport=boom)
    assert not cap.ok and "Authentication failed" in cap.error


def test_clean_config_strips_noise():
    raw = "Building configuration...\r\nCurrent configuration : 2000 bytes\r\n!\nhostname x\r\n! Last configuration change at 10:00\nend\r\n"
    c = clean_config(raw)
    assert "Building configuration" not in c and "Current configuration" not in c and "Last configuration change" not in c
    assert "hostname x" in c and c.endswith("\n")
