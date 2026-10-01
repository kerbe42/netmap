"""Review follow-ups for the discovery/collector modules: read-only guarantees, scope, host-key
trust, secret redaction, probe concurrency, profiler over-matching, and the new parsers.

Everything runs offline: pure functions, fakes, injected probes/transports and loopback only.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from subnetsleuth import api, capture, dhcp, discover, hostinfo, listen, profile, sshtrust, vmware
from subnetsleuth import probes_extra as px
from subnetsleuth.model import Host, Inventory

from tests.test_probes_extra import build_bacnet_iam, build_modbus_id_response
from tests.test_vmware import FakeSI, fake_host, fake_vm


def _run(coro):
    return asyncio.run(coro)


# =========================================================================== #
# 1. capture: no configuration commands, prompt-aware reading, pagers
# =========================================================================== #
def test_vendor_cmds_contain_no_configuration_commands():
    for key, cmds in capture.VENDOR_CMDS.items():
        for cmd in cmds:
            for line in cmd.splitlines():
                assert not line.strip().lower().startswith(("config", "configure")), (key, line)
                assert not capture.is_config_command(line), (key, line)
    assert not capture.is_config_command(capture.DEFAULT_CMDS[0])
    assert capture.is_config_command("config system console")
    assert capture.is_config_command("configure terminal")


class RecordingChannel:
    """Shell channel fake that records what it is sent and replays canned output."""

    def __init__(self, responses, banner="\r\nfw01 # ", more_after=None):
        self.responses = responses
        self.buf = banner.encode()
        self.sent: list[str] = []
        self.more_after = more_after  # (command, first_part, rest): page the output of `command`
        self._pending = b""

    def send(self, data):
        self.sent.append(data)
        cmd = data.strip()
        if data == " ":  # pager continuation
            self.buf += self._pending
            self._pending = b""
            return 1
        if self.more_after and cmd == self.more_after[0]:
            _c, first, rest = self.more_after
            self.buf += data.encode() + b"\n" + first.encode() + b"\n--More--"
            self._pending = b"\r" + rest.encode() + b"\nfw01 # "
            return len(data)
        self.buf += data.encode() + ("\n" + self.responses.get(cmd, "") + "\nfw01 # ").encode()
        return len(data)

    def recv_ready(self):
        return bool(self.buf)

    def recv(self, n):
        chunk, self.buf = self.buf[:n], self.buf[n:]
        return chunk

    def close(self):
        pass


def test_fortios_capture_sends_only_show_get_and_answers_pager():
    ch = RecordingChannel(
        {"get system status": "Version: FortiGate-60F v7.2.5,build1517"},
        more_after=("show full-configuration", "config system global\n    set hostname \"fw01\"", "end\nconfig system admin\nend"),
    )
    cap = capture.capture_config("10.0.0.1", "ro", "pw", os_family="fortios", transport=lambda *a: (ch, ch))
    assert cap.ok, cap.error
    sent_cmds = [s.strip() for s in ch.sent if s.strip()]
    assert sent_cmds == ["get system status", "show full-configuration"]
    assert not any(capture.is_config_command(s) for s in ch.sent)
    assert " " in ch.sent  # the --More-- prompt was answered with a space, not reconfigured away
    assert 'set hostname "fw01"' in cap.text and "config system admin" in cap.text
    assert "--More--" not in cap.text


class PausingChannel:
    """IOS-style: echoes the command, prints 'Building configuration...', pauses longer than the
    idle threshold, then prints the config and the prompt."""

    def __init__(self, pause):
        self.buf = b"\r\ncore-sw-01>"
        self.stage = []
        self.pause = pause

    def send(self, data):
        cmd = data.strip()
        now = time.time()
        if cmd == "show running-config":
            self.buf += data.encode() + b"\nBuilding configuration...\n\n"
            self.stage.append((now + self.pause, b"!\nhostname core-sw-01\n!\ninterface Vlan10\n ip address 10.1.0.1 255.255.255.0\nend\ncore-sw-01#"))
        else:
            self.buf += data.encode() + b"\n" + (b"Cisco IOS Software, Version 15.2" if cmd == "show version" else b"") + b"\ncore-sw-01#"
        return len(data)

    def _flush(self):
        now = time.time()
        for t, data in list(self.stage):
            if now >= t:
                self.buf += data
                self.stage.remove((t, data))

    def recv_ready(self):
        self._flush()
        return bool(self.buf)

    def recv(self, n):
        chunk, self.buf = self.buf[:n], self.buf[n:]
        return chunk

    def close(self):
        pass


def test_learn_prompt_and_wait_through_a_pause():
    rx = capture.learn_prompt("Welcome\r\ncore-sw-01>")
    assert rx and rx.search("core-sw-01#") and rx.search("core-sw-01> ") and not rx.search("hostname core-sw-01")
    assert capture.learn_prompt("[admin@MikroTik] > ").search("[admin@MikroTik] >")
    assert capture.learn_prompt("") is None
    ch = PausingChannel(pause=0.9)
    raw = capture._read_shell(ch, ["terminal length 0", "show version", "show running-config"], prompt_idle=0.3, total=10)
    assert "interface Vlan10" in raw  # the idle-based reader (0.3 s) would have given up during the 0.9 s pause


def test_read_shell_refuses_config_commands():
    ch = RecordingChannel({})
    with pytest.raises(ValueError):
        capture._read_shell(ch, ["configure terminal"], prompt_idle=0.1)
    assert ch.sent == []


# =========================================================================== #
# 6. secret redaction
# =========================================================================== #
IOS_CFG = """hostname core-sw-01
enable secret 5 $1$abcd$XYZ123
username admin privilege 15 secret 9 $9$abcdefgh
username backup password 7 094F471A1A0A
service password-encryption
snmp-server community c0mmun1ty RO ACL-SNMP
snmp-server host 10.0.0.9 version 2c trapcomm
snmp-server user monitor grp v3 auth sha AuthPass1 priv aes 128 PrivPass1
tacacs server T1
 key 7 0512180F1E5A
radius-server key 0 RadiusSecret
ntp authentication-key 1 md5 15321A0D0E1F 7
interface Vlan10
 ip ospf message-digest-key 1 md5 7 0508331B
 standby 1 authentication md5 key-string 7 070C285F4D06
crypto isakmp key MyPSK address 1.2.3.4
 pre-shared-key local 6 ABCDEF
router bgp 65000
 neighbor 10.0.0.2 password 7 05080F1C2243
password min-length 8
end"""

JUNOS_CFG = '''set system root-authentication encrypted-password "$6$rounds$hash"
set snmp community public authorization read-only
set security ike policy P pre-shared-key ascii-text "$9$secret"
set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key "$9$ospfkey"
set system radius-server 10.0.0.5 secret "$9$radsecret"
set system services ssh root-login deny'''

FORTI_CFG = '''config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2abcdef
    next
end
config system snmp community
    edit 1
        set name "commsecret"
    next
end
config vpn ipsec phase1-interface
    edit "to-hq"
        set psksecret ENC Zm9vYmFy
        set type static
    next
end
config wireless-controller vap
    edit "corp"
        set passphrase ENC wpa123
    next
end'''


@pytest.mark.parametrize("text,secrets,kept", [
    (IOS_CFG, ["$1$abcd$XYZ123", "$9$abcdefgh", "094F471A1A0A", "c0mmun1ty", "trapcomm", "AuthPass1", "PrivPass1",
               "0512180F1E5A", "RadiusSecret", "15321A0D0E1F", "0508331B", "070C285F4D06", "MyPSK", "ABCDEF", "05080F1C2243"],
     ["hostname core-sw-01", "service password-encryption", "password min-length 8", "RO ACL-SNMP", "address 1.2.3.4",
      "priv aes 128", "standby 1 authentication md5 key-string 7"]),
    (JUNOS_CFG, ["$6$rounds$hash", "public", "$9$secret", "$9$ospfkey", "$9$radsecret"],
     ["authorization read-only", "root-login deny", 'pre-shared-key ascii-text "<redacted>"']),
    (FORTI_CFG, ["SH2abcdef", "commsecret", "Zm9vYmFy", "wpa123"],
     ['set accprofile "super_admin"', "set type static", 'set name "<redacted>"']),
])
def test_redact_secrets_vendor_snippets(text, secrets, kept):
    out, n = capture.redact_secrets(text)
    assert n == len(secrets), out
    for s in secrets:
        assert s not in out, s
    for k in kept:
        assert k in out, k
    assert len(out.splitlines()) == len(text.splitlines())  # structure intact so diffs line up


def test_redact_private_key_block_and_store_marker():
    pem = "crypto pki certificate chain X\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabcd\n-----END RSA PRIVATE KEY-----\nend"
    out, n = capture.redact_secrets(pem)
    assert "MIIEowIBAAKCAQEA" not in out and "-----BEGIN RSA PRIVATE KEY-----" in out and n == 2
    inv = Inventory()
    cap = capture.Capture(ok=True, text="hostname x\nsnmp-server community s3cret RO\n", version="v")
    assert capture.store_config(inv, "10.0.0.2", cap) is True
    entry = inv.configs["10.0.0.2"][-1]
    assert "s3cret" not in entry["text"] and "<redacted>" in entry["text"] and entry["redacted"] is True
    # a rotated community alone is not a config change; a real change still is
    cap2 = capture.Capture(ok=True, text="hostname x\nsnmp-server community other RO\n")
    assert capture.store_config(inv, "10.0.0.2", cap2) is False
    cap3 = capture.Capture(ok=True, text="hostname y\nsnmp-server community other RO\n")
    assert capture.store_config(inv, "10.0.0.2", cap3) is True
    plain = Inventory()
    capture.store_config(plain, "d", capture.Capture(ok=True, text="hostname x\n"))
    assert plain.configs["d"][-1]["redacted"] is False


# =========================================================================== #
# 7. SSH host keys: trust on first use, reject on change
# =========================================================================== #
paramiko = pytest.importorskip("paramiko")


class FakeSSHClient:
    def __init__(self):
        self._host_keys = paramiko.HostKeys()
        self._system_host_keys = paramiko.HostKeys()
        self._host_keys_filename = None
        self.saved = []

    def save_host_keys(self, path):
        self.saved.append(path)
        self._host_keys.save(path)

    def load_system_host_keys(self):
        pass

    def load_host_keys(self, path):
        self._host_keys.load(path)
        self._host_keys_filename = path

    def set_missing_host_key_policy(self, p):
        self.policy = p


def test_tofu_policy_adds_first_key_and_rejects_a_changed_one(tmp_path, monkeypatch):
    store = tmp_path / "known_hosts"
    monkeypatch.setenv("SUBNETSLEUTH_KNOWN_HOSTS", str(store))
    assert sshtrust.known_hosts_path() == str(store)
    k1 = paramiko.RSAKey.generate(1024)
    k2 = paramiko.RSAKey.generate(1024)
    client = sshtrust.prepare_client(FakeSSHClient())
    client.policy.missing_host_key(client, "10.0.0.5", k1)  # first sight: recorded
    assert store.exists() and client._host_keys.lookup("10.0.0.5")["ssh-rsa"] == k1
    # a fresh client loads the store; a different key of another type for the same host is a change
    client2 = sshtrust.prepare_client(FakeSSHClient())
    assert client2._host_keys.lookup("10.0.0.5")["ssh-rsa"] == k1
    ecdsa = paramiko.ECDSAKey.generate()
    with pytest.raises(sshtrust.HostKeyChanged) as ei:
        client2.policy.missing_host_key(client2, "10.0.0.5", ecdsa)
    assert "host key changed for 10.0.0.5" in str(ei.value) and str(store) in str(ei.value)
    # paramiko's own mismatch exception (same type, different key) is described the same way
    bad = paramiko.BadHostKeyException("10.0.0.5", k2, k1)
    assert "host key changed for 10.0.0.5" in sshtrust.describe_error(bad)
    assert sshtrust.describe_error(OSError("timeout")) is None
    # an unrelated host is still accepted on first sight
    client2.policy.missing_host_key(client2, "10.0.0.6", k2)
    assert client2._host_keys.lookup("10.0.0.6")


def test_capture_and_inspect_report_host_key_changed(monkeypatch):
    def changed(*a, **k):
        raise sshtrust.HostKeyChanged("10.0.0.2", "ssh-ed25519", "SHA256:abc")

    cap = capture.capture_config("10.0.0.2", "ro", "pw", transport=changed)
    assert not cap.ok and cap.host_key_changed and "host key changed for 10.0.0.2" in cap.error
    monkeypatch.setattr(hostinfo, "_paramiko_run", changed)
    facts = hostinfo.inspect_ssh("10.0.0.2", "ro", "pw")
    assert not facts["ok"] and facts.get("host_key_changed") is True and "host key changed" in facts["error"]


def test_paramiko_clients_no_longer_auto_add():
    import inspect

    for src in (inspect.getsource(capture._paramiko_transport), inspect.getsource(hostinfo._paramiko_run)):
        assert "AutoAddPolicy" not in src and "prepare_client" in src


# =========================================================================== #
# 2 + 13. inspect_hosts: scope, appliance roles, port gating; WinRM transport
# =========================================================================== #
def _fake_ssh_ok(ip, **kw):
    return {"ok": True, "source": "ssh", "system": {"os": "Linux", "hostname": ip}, "software": [],
            "services": [], "connections": [], "error": ""}


def _fake_winrm_ok(ip, **kw):
    return {"ok": True, "source": "winrm", "system": {"os": "Windows"}, "software": [], "services": [], "connections": [], "error": ""}


def test_inspect_hosts_respects_scope_and_exclude():
    inv = Inventory()
    for ip in ("10.0.0.5", "10.0.0.6", "10.0.1.5", "192.168.9.9"):
        inv.hosts[ip] = Host(ip=ip, os_family="linux")
    tried = []

    def ssh(ip, **kw):
        tried.append(ip)
        return _fake_ssh_ok(ip)

    creds = {"linux": {"username": "ro", "password": "p"}}
    counts = _run(hostinfo.inspect_hosts(inv, creds, ssh_inspector=ssh,
                                         scope=[ipaddress.ip_network("10.0.0.0/23")],
                                         exclude=[ipaddress.ip_network("10.0.0.6/32")]))
    assert sorted(tried) == ["10.0.0.5", "10.0.1.5"] and counts["ok"] == 2
    tried.clear()
    _run(hostinfo.inspect_hosts(inv, creds, hosts=["192.168.9.9", "10.0.0.5"], ssh_inspector=ssh,
                                scope=[ipaddress.ip_network("10.0.0.0/8")]))
    assert tried == ["10.0.0.5"]  # an explicit host list is filtered too


def test_inspect_hosts_skips_appliances_and_hosts_without_the_service_port():
    inv = Inventory()
    inv.hosts["10.0.0.20"] = Host(ip="10.0.0.20", role="plc")                       # never
    inv.hosts["10.0.0.21"] = Host(ip="10.0.0.21", role="camera", os_family="linux")  # never, even with a family
    inv.hosts["10.0.0.22"] = Host(ip="10.0.0.22", ports=[{"port": 80}, {"port": 443}])  # scanned: no 22/5985
    inv.hosts["10.0.0.23"] = Host(ip="10.0.0.23", ports=[{"port": 22}])              # scanned: ssh
    inv.hosts["10.0.0.24"] = Host(ip="10.0.0.24", ports=[{"port": 5986}])            # scanned: winrm
    inv.hosts["10.0.0.25"] = Host(ip="10.0.0.25")                                    # unknown ports -> port_check
    tried = []

    def ssh(ip, **kw):
        tried.append(("ssh", ip))
        return {**_fake_ssh_ok(ip), "ok": False, "error": "refused"}

    def winrm(ip, **kw):
        tried.append(("winrm", ip))
        return _fake_winrm_ok(ip)

    checks = []

    def port_check(ip, port, timeout):
        checks.append((ip, port))
        return port == 22  # 10.0.0.25 answers on 22 only

    creds = {"linux": {"username": "ro"}, "windows": {"username": "ro", "password": "p"}}
    counts = _run(hostinfo.inspect_hosts(inv, creds, ssh_inspector=ssh, winrm_inspector=winrm, port_check=port_check))
    assert ("ssh", "10.0.0.20") not in tried and ("winrm", "10.0.0.20") not in tried
    assert not any(ip == "10.0.0.21" for _k, ip in tried)
    assert not any(ip == "10.0.0.22" for _k, ip in tried)
    assert ("ssh", "10.0.0.23") in tried and ("winrm", "10.0.0.23") not in tried
    assert ("winrm", "10.0.0.24") in tried and ("ssh", "10.0.0.24") not in tried
    assert ("ssh", "10.0.0.25") in tried and ("winrm", "10.0.0.25") not in tried
    assert all(ip == "10.0.0.25" for ip, _p in checks)  # the TCP check only runs where ports are unknown
    assert counts["skipped"] == 1 and counts["inspected"] == 3  # .22 skipped; .20/.21 never targets
    # explicit host list: appliances are still refused
    counts = _run(hostinfo.inspect_hosts(inv, creds, hosts=["10.0.0.20"], ssh_inspector=ssh, winrm_inspector=winrm))
    assert counts["inspected"] == 0 and counts["skipped"] == 1
    assert "media" in hostinfo.SKIP_ROLES and "bmc" in hostinfo.SKIP_ROLES and "printer" in hostinfo.SKIP_ROLES


def test_winrm_refuses_basic_over_plain_http_and_defaults_ports():
    with pytest.raises(ValueError):
        hostinfo._winrm_run_ps("10.0.0.10", "u", "p", "basic", 5, port=5985, use_ssl=False)
    facts = hostinfo.inspect_winrm("10.0.0.10", "u", "p", transport="basic")
    assert not facts["ok"] and "plain HTTP" in facts["error"]
    import inspect

    sig = inspect.signature(hostinfo.inspect_winrm)
    assert sig.parameters["transport"].default == "ntlm"
    assert (hostinfo.WINRM_HTTP_PORT, hostinfo.WINRM_HTTPS_PORT) == (5985, 5986)
    endpoints = []

    class FakeSession:
        def __init__(self, url, auth, **kw):
            endpoints.append((url, kw))
            self.protocol = SimpleNamespace(transport=SimpleNamespace())

    fake_winrm = SimpleNamespace(Session=FakeSession)
    sys.modules["winrm"], saved = fake_winrm, sys.modules.get("winrm")
    try:
        hostinfo._winrm_run_ps("10.0.0.10", "u", "p", "ntlm", 5, port=5986, use_ssl=True)
        hostinfo._winrm_run_ps("10.0.0.10", "u", "p", "ntlm", 5)
    finally:
        if saved is not None:
            sys.modules["winrm"] = saved
        else:
            del sys.modules["winrm"]
    assert endpoints[0][0] == "https://10.0.0.10:5986/wsman" and endpoints[0][1]["server_cert_validation"] == "validate"
    assert endpoints[1][0] == "http://10.0.0.10:5985/wsman" and endpoints[1][1]["transport"] == "ntlm"


# =========================================================================== #
# 3 + 12. discover: UPnP LOCATION scope, HTTP/SSH/TLS parsing
# =========================================================================== #
def test_upnp_location_is_only_fetched_from_the_probed_address(monkeypatch):
    import http.client

    def boom(*a, **k):
        raise AssertionError("must not connect")

    monkeypatch.setattr(http.client, "HTTPConnection", boom)
    monkeypatch.setattr(http.client, "HTTPSConnection", boom)
    assert discover._fetch_upnp_description("http://10.9.9.9:49152/desc.xml", ip="10.0.0.5") == {}
    assert discover._fetch_upnp_description("http://evil.example/desc.xml", ip="10.0.0.5") == {}
    # same address: the fetch is attempted (and our stub blows up, proving it was reached)
    with pytest.raises(AssertionError):
        discover._fetch_upnp_description("http://10.0.0.5:49152/desc.xml", ip="10.0.0.5")


def test_parse_http_head_ignores_non_ascii_digits():
    assert discover.parse_http_head(b"HTTP/1.1 \xd9\xa2\xd9\xa0\xd9\xa0 OK\r\nServer: x\r\n\r\n")["status"] is None
    assert discover.parse_http_head("HTTP/1.1 ٢٠٠ OK\r\n\r\n")["status"] is None
    assert discover.parse_http_head(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"iDRAC\"\r\n\r\n")["status"] == 401


def test_ssh_ident_tolerates_pre_banner_lines_and_maps_bsd():
    data = b"Welcome to the jungle\r\nAuthorized use only\r\nSSH-2.0-OpenSSH_9.6 FreeBSD-20240806\r\n"
    assert discover._ssh_ident_line(data) == "SSH-2.0-OpenSSH_9.6 FreeBSD-20240806"
    assert discover._ssh_ident_line(b"\r\n" * 9 + b"SSH-2.0-x") == ""  # too many lines: give up

    class S:
        def __init__(self, chunks):
            self.chunks = list(chunks)

        def recv(self, n):
            return self.chunks.pop(0) if self.chunks else b""

    got = discover._read_ssh_ident(S([b"banner line\r\n", b"SSH-2.0-dropbear_2022.83\r\n", b"never read"]))
    assert discover._ssh_ident_line(got) == "SSH-2.0-dropbear_2022.83"
    fams = {tok: fam for tok, fam, _l in discover._SSH_OS}
    assert fams["freebsd"] == "bsd" and fams["openbsd"] == "bsd" and fams["ubuntu"] == "linux"
    assert profile._NMAP_FAMILY["freebsd"] == "bsd" and profile._NMAP_FAMILY["vmware esxi"] == "esxi"


def test_decode_der_cert_with_cryptography_no_private_hooks():
    import datetime
    import inspect

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nas01.corp.local"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Synology Inc.")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("nas01.corp.local"), x509.IPAddress(ipaddress.ip_address("10.0.0.7"))]), critical=False)
            .sign(key, hashes.SHA256()))
    d = discover.decode_der_cert(cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))
    cf = discover.cert_fields(d)
    assert cf["cert_cn"] == "nas01.corp.local" and cf["cert_issuer"] == "nas01.corp.local"
    assert set(cf["cert_san"]) == {"nas01.corp.local", "10.0.0.7"} and cf["cert_expires"].endswith("GMT")
    assert discover.cert_subject_org(d) == "Synology Inc."
    assert discover.decode_der_cert(b"not a cert") is None and discover.decode_der_cert(None) is None
    src = inspect.getsource(discover)
    assert "_test_decode_cert" not in src and "NamedTemporaryFile" not in src


# =========================================================================== #
# 4. probe executor: every result is recorded even when probes are slow
# =========================================================================== #
def _sleeping(name, delay, seen):
    def probe(ip):
        time.sleep(delay)
        seen.append((name, ip))
        return {name: True, "ip": ip}
    return probe


def test_identify_hosts_records_all_results_with_slow_probes():
    inv = Inventory()
    ips = [f"10.0.0.{i + 1}" for i in range(24)]
    for ip in ips:
        inv.touch_host(ip, "sweep")
    seen: list = []
    probes = {n: _sleeping(n, 0.25, seen) for n in ("netbios", "mdns", "ssdp", "http", "ssh")}
    # 24 hosts x 5 probes on 8 workers, 0.25 s each: with per-host bounding 8 hosts fanned 40
    # probes into an 8-thread pool (5 rounds = 1.25 s) while each probe's wait_for(timeout+1
    # = 1.05 s) had already started counting, so the later rounds were discarded. Per-probe
    # bounding records every one of the 120 results.
    n = _run(discover.identify_hosts(inv, workers=8, timeout=0.05, probes=probes))
    assert n == 24
    assert len(seen) == 120
    for ip in ips:
        assert set(inv.hosts[ip].probes) == {"netbios", "mdns", "ssdp", "http", "ssh"}, ip


def test_probe_extra_records_all_results_with_slow_probes():
    inv = Inventory()
    ips = [f"10.1.0.{i + 1}" for i in range(18)]
    for ip in ips:
        inv.touch_host(ip, "sweep")
    seen: list = []
    probes = {n: _sleeping(n, 0.2, seen) for n in ("wsd", "ipmi", "modbus", "bacnet", "enip", "dns", "ntp")}
    n = _run(px.probe_extra(inv, workers=6, timeout=0.05, probes=probes))
    assert n == 18 and len(seen) == 126
    assert all(len(inv.hosts[ip].probes) == 7 for ip in ips)


# =========================================================================== #
# 12 + 14. probes_extra: Modbus ADU, BACnet forwarded I-Am / ReadProperty, NTP readvar
# =========================================================================== #
class FakeModbusSocket:
    """Serves the canned reply in small chunks and records requests (unit ids)."""

    def __init__(self, replies):
        self.replies = replies  # unit -> bytes
        self.requests: list[int] = []
        self.pending = b""

    def sendall(self, data):
        unit = data[6]
        self.requests.append(unit)
        self.pending = self.replies.get(unit, b"")

    def recv(self, n):
        chunk, self.pending = self.pending[:min(n, 5)], self.pending[min(n, 5):]  # 5 bytes at a time
        return chunk


def test_modbus_reads_the_full_adu_and_tries_unit_ff_then_01():
    full = build_modbus_id_response(unit=0x01)
    sock = FakeModbusSocket({0xFF: b"", 0x01: full})
    got = px._modbus_exchange(sock, 0xFF, 1)
    assert got == b""  # unit 0xFF answered nothing
    got = px._modbus_exchange(sock, 0x01, 2)
    assert got == full  # header (7) + length-1 more bytes, assembled from 5-byte chunks
    res = px.parse_modbus_id(got)
    assert res["vendor"] == "Schneider Electric" and res["product"] == "Modicon M340"
    assert sock.requests == [0xFF, 0x01]
    # the request is the read-only Read Device Identification (function 0x2B / MEI 0x0E) and nothing else
    req = px._build_modbus_request(unit=0xFF)
    assert req[7] == 0x2B and req[8] == 0x0E and len(req) == 11


def test_bacnet_forwarded_npdu_and_device_object_check():
    iam = build_bacnet_iam(instance=1234, vendor_id=25)
    body = iam[4:]
    fwd = bytes([0x81, 0x04]) + struct.pack(">H", 4 + 6 + len(body)) + bytes([10, 0, 0, 9, 0xBA, 0xC0]) + body
    r = px.parse_bacnet(fwd)
    assert r and r["device_id"] == 1234 and r["vendor_id"] == 25
    # an object id that is not a device (analog-input, type 0) is not an I-Am we trust
    ai = bytearray(iam)
    struct.pack_into(">I", ai, 4 + 2 + 2 + 1, (0 << 22) | 1234)
    assert px.parse_bacnet(bytes(ai)) is None


def test_bacnet_readproperty_is_read_only_and_parses_character_strings():
    req = px._build_bacnet_readprop(1234, px.BACNET_PROPS["name"], invoke_id=3)
    assert req[:2] == b"\x81\x0a"
    apdu = req[6:]
    assert apdu[0] == 0x00 and apdu[2] == 3 and apdu[3] == 0x0C  # confirmed request, invoke 3, service ReadProperty
    assert apdu[4] == 0x0C and struct.unpack(">I", apdu[5:9])[0] == (8 << 22) | 1234 and apdu[9:11] == bytes([0x19, 77])
    # Complex-ACK: 0x30, invoke, service, ctx0 objid, ctx1 prop, opening 3, charstring, closing 3
    text = b"\x00" + "AHU-1 Controller".encode()
    ack = bytes([0x81, 0x0A, 0, 0, 0x01, 0x00, 0x30, 3, 0x0C, 0x0C]) + struct.pack(">I", (8 << 22) | 1234) + bytes([0x19, 77, 0x3E])
    ack += bytes([0x75, len(text)]) + text + bytes([0x3F])
    ack = ack[:2] + struct.pack(">H", len(ack)) + ack[4:]
    assert px.parse_bacnet_readprop(ack) == "AHU-1 Controller"
    assert px.parse_bacnet_readprop(b"\x81\x0a\x00\x08\x01\x00\x10\x00") is None  # an I-Am, not an ACK
    # profile uses the read names
    h = Host(ip="10.0.0.40", probes={"bacnet": {"bacnet": True, "device_id": 1234, "vendor_id": 25, "name": "AHU-1", "vendor": "Trane", "model": "UC600"}})
    p = profile.profile_host(h)
    assert p.role == "bms" and p.vendor == "Trane" and p.model == "UC600"


def test_ntp_readvar_request_and_parse():
    req = px._build_ntp_readvar()
    assert len(req) == 12 and req[0] & 0x07 == 6 and req[1] & 0x1F == 2 and req[1] & 0x80 == 0  # mode 6, READVAR, request
    payload = b'version="ntpd 4.2.8p15@1.3728-o", processor="x86_64", system="Linux/5.15.0", leap=0, stratum=2, refid=10.0.0.1'
    resp = struct.pack(">BBHHHHH", 0x16, 0x82, 1, 0, 0, 0, len(payload)) + payload
    var = px.parse_ntp_readvar(resp)
    assert var["version"] == "ntpd 4.2.8p15@1.3728-o" and var["system"] == "Linux/5.15.0" and var["stratum"] == "2"
    assert px.parse_ntp_readvar(b"\x1c" + b"\x00" * 47) == {}  # a mode-4 time reply is not a control response


def test_probe_modules_send_only_read_requests():
    """Every request builder in the probe modules is a read: Modbus function 43/14, BACnet
    Who-Is/ReadProperty, EtherNet/IP ListIdentity, IPMI Get Channel Auth Capabilities, NTP client/readvar."""
    assert px._build_modbus_request()[7] == 0x2B
    assert px._build_bacnet_whois()[6:8] == b"\x10\x08"
    assert struct.unpack("<H", px._build_enip_list_identity()[:2])[0] == 0x0063
    ipmi = px._build_ipmi_request()
    assert ipmi[4 + 9 + 1 + 3 + 2] == 0x38  # cmd byte
    # BACnet: Who-Is (unconfirmed 0x08) and ReadProperty (confirmed 0x0C) only - never WriteProperty (0x0F)
    assert px._build_bacnet_readprop(1, 77)[6 + 3] == 0x0C
    ntp = px._build_ntp_readvar()
    assert ntp[1] & 0x1F == 2  # READVAR, not a WRITEVAR (3) or config (8)


# =========================================================================== #
# 5. profile: over-matching negatives
# =========================================================================== #
def _http_host(**fields):
    e = {"port": 443, "tls": True, "server": None, "title": None, "realm": None, "cert_cn": None, "cert_org": None,
         "cert_san": [], "cert_issuer": None, "cert_expires": None}
    e.update(fields)
    return Host(ip="10.0.0.9", probes={"http": {"443": e}})


@pytest.mark.parametrize("fields,not_vendor", [
    ({"title": "Praxis Portal - Login"}, "Axis"),
    ({"title": "Pilot dashboard"}, "HPE"),
    ({"title": "Unified Comms Portal"}, "Ubiquiti"),
    ({"cert_cn": "boavista.corp.local"}, ""),
    ({"cert_san": ["apcupsd.corp.local", "eatonville.corp.local"]}, "APC"),
    ({"title": "iisnet blog"}, "Microsoft"),
])
def test_banner_needles_do_not_match_inside_words_or_free_text(fields, not_vendor):
    p = profile.profile_host(_http_host(**fields))
    if not_vendor:
        assert p.vendor != not_vendor
    assert p.role not in ("camera", "bmc", "wireless", "ups")
    assert not any("in banner/cert" in e["observed"] for e in p.evidence), p.evidence


def test_banner_needles_match_real_vendor_fields():
    assert profile.profile_host(_http_host(server="AXIS Network Camera")).role == "camera"
    p = profile.profile_host(_http_host(server="HPE-iLO-Server/1.30"))
    assert p.role == "bmc" and p.vendor == "HPE"
    p = profile.profile_host(_http_host(title="iDRAC9 - Login", cert_org="Dell Inc."))
    assert p.role == "bmc" and p.vendor == "Dell"
    p = profile.profile_host(_http_host(server="Microsoft-IIS/10.0"))
    assert p.vendor == "Microsoft" and p.os_family == "windows"
    p = profile.profile_host(_http_host(cert_issuer="UniFi OS", cert_org="Ubiquiti Inc."))
    assert p.role == "wireless"
    p = profile.profile_host(_http_host(title="VMware ESXi7 Welcome", cert_org="VMware, Inc."))
    assert p.role == "hypervisor" and p.os_family == "esxi"
    # SSDP: strict needles only in server/manufacturer, never in a user-set friendly name
    h = Host(ip="10.0.0.9", probes={"ssdp": {"server": "Linux/4.9 UPnP/1.0", "friendly_name": "Apcalypse TV", "manufacturer": None, "model": None, "device_type": "urn:schemas-upnp-org:device:MediaRenderer:1"}})
    p = profile.profile_host(h)
    assert p.role == "media" and p.vendor != "APC"


def test_hostname_votes_once_per_distinct_name_and_tokens_are_anchored():
    h = Host(ip="10.0.0.9", names={"dns": "jonas-pc.corp.local", "netbios": "JONAS-PC", "mdns": "jonas-pc.local"})
    p = profile.profile_host(h)
    assert p.role != "nas" and not any("NAS-style" in e["observed"] for e in p.evidence)
    h = Host(ip="10.0.0.9", names={"dns": "nas01.corp.local", "netbios": "NAS01", "mdns": "nas01.local"})
    p = profile.profile_host(h)
    votes = [e for e in p.evidence if "NAS-style" in e["observed"]]
    assert len(votes) == 1 and p.role == "nas"  # three sources, one distinct name, one vote
    for name, wrong in (("annexus-pc", "switch"), ("gatewayside-laptop", "router"), ("adc-wifiles", "wireless"), ("dcfc-pc", "windows")):
        assert profile.profile_host(Host(ip="10.0.0.9", names={"dns": name})).role != wrong, name
    assert profile.profile_host(Host(ip="10.0.0.9", names={"dns": "core-nexus-01"})).role == "switch"
    assert profile.profile_host(Host(ip="10.0.0.9", names={"dns": "corp-gateway"})).role == "router"
    assert profile.profile_host(Host(ip="10.0.0.9", names={"dns": "ad-dc-01"})).role == "windows"
    assert profile.profile_host(Host(ip="10.0.0.9", names={"dns": "esxi-02"})).role == "hypervisor"


def test_netbios_without_adapter_mac_is_weak_and_ssh_banner_family_wins():
    samba = Host(ip="10.0.0.9", probes={"netbios": {"hostname": "FILES", "domain": "WORKGROUP", "mac": None, "is_dc": False},
                                         "ssh": {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "software": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "os": "Ubuntu", "os_family": "linux"}})
    p = profile.profile_host(samba)
    assert p.os_family == "linux" and p.role != "windows"
    nb_votes = [e for e in p.evidence if e["source"] == "NetBIOS"]
    assert nb_votes and "Samba" in nb_votes[0]["observed"]
    real = Host(ip="10.0.0.9", probes={"netbios": {"hostname": "PC1", "domain": "CORP", "mac": "3c:52:82:1a:2b:3c", "is_dc": False}})
    p = profile.profile_host(real)
    assert p.os_family == "windows" and p.role == "windows" and p.confidence == "high"
    # windows box that also runs OpenSSH keeps windows
    both = Host(ip="10.0.0.9", probes={"netbios": {"hostname": "PC1", "mac": "3c:52:82:1a:2b:3c", "is_dc": False},
                                        "ssh": {"banner": "SSH-2.0-OpenSSH_for_Windows_8.1", "software": "OpenSSH_for_Windows_8.1", "os": "Windows (OpenSSH)", "os_family": "windows"}})
    assert profile.profile_host(both).os_family == "windows"


def test_media_role_bmc_role_and_windows_workstation_not_webserver():
    tv = Host(ip="10.0.0.9", probes={"mdns": {"hostname": "living-room.local", "services": ["_airplay._tcp", "_raop._tcp"], "model": "AppleTV6,2", "vendor": "Apple"}})
    p = profile.profile_host(tv)
    assert p.role == "media" and p.functions == [] and "media" in profile._APPLIANCE_ROLES and profile.ROLE_OS["media"] == "embedded"
    cast = Host(ip="10.0.0.9", probes={"mdns": {"hostname": "cc.local", "services": ["_googlecast._tcp"], "model": None, "vendor": "Google"}})
    assert profile.profile_host(cast).role == "media"
    assert profile.ROLE_LABELS_EXTRA["media"]
    ilo = Host(ip="10.0.0.9", ports=[{"port": 443}, {"port": 80}], probes={"ipmi": {"ipmi": True, "version": "2.0"}})
    assert profile.profile_host(ilo).role == "bmc"
    # a NetBIOS-confirmed Windows 10 workstation with port 80 stays a Windows host
    ws = Host(ip="10.0.0.9", ports=[{"port": 80}, {"port": 135}, {"port": 445}, {"port": 3389}], os="Windows 10 Pro", os_family="windows",
              probes={"netbios": {"hostname": "PC1", "mac": "3c:52:82:1a:2b:3c", "is_dc": False}})
    assert profile.profile_host(ws).role == "windows"
    srv = Host(ip="10.0.0.9", ports=[{"port": 80}, {"port": 443}, {"port": 445}], os="Windows Server 2022", os_family="windows",
               probes={"netbios": {"hostname": "WEB1", "mac": "3c:52:82:1a:2b:3c", "is_dc": False}})
    assert profile.profile_host(srv).role == "webserver"
    lin = Host(ip="10.0.0.9", ports=[{"port": 80}, {"port": 22}], os_family="linux")
    assert profile.profile_host(lin).role == "webserver"
    assert profile.ROLE_FROM_FAMILY["bsd"] == "server" and profile.ROLE_FROM_FAMILY["esxi"] == "hypervisor"
    # an unknown role degrades gracefully in the library's own lookups
    assert profile.ROLE_OS.get("something-new", "") == "" and "something-new" not in profile._APPLIANCE_ROLES


# =========================================================================== #
# 8. vmware
# =========================================================================== #
def test_vmware_verifies_tls_by_default_and_folds_hosts_correctly():
    import inspect

    assert inspect.signature(vmware.connect).parameters["insecure"].default is False
    assert inspect.signature(vmware.discover).parameters["insecure"].default is False
    inv = Inventory()
    inv.touch_host("10.0.0.50", "dns")
    inv.hosts["10.0.0.50"].hostname = "curated-name"
    inv.hosts["10.0.0.50"].os = "Curated OS"
    vm = fake_vm(name="web01", hostname="web01.corp.local", ips=("10.0.0.50", "172.16.5.50"))
    si = FakeSI([fake_host(name="esx-01", mgmt_ip="10.0.0.10")], [vm])
    summary = vmware.discover(inv, "vc", "ro", "pw", si=si)
    assert "error" not in summary and summary["vms_with_ip"] == 1
    esx = inv.hosts["10.0.0.10"]
    assert esx.role == "hypervisor" and esx.os_family == "esxi"
    h1, h2 = inv.hosts["10.0.0.50"], inv.hosts["172.16.5.50"]
    assert h1.hostname == "curated-name" and h1.os == "Curated OS"  # fill-if-empty, never clobbered
    assert h1.names["vmware"] == "web01.corp.local"
    assert h2.role == "vm" and h2.hostname == "web01.corp.local" and h2.os == "Ubuntu Linux (64-bit)"  # multi-homed: both addresses
    assert h2.system["all_ips"] == ["10.0.0.50", "172.16.5.50"] and h2.system["hypervisor"] == "esx-01"


# =========================================================================== #
# 9. api
# =========================================================================== #
def _serve(inv, token="", allowed_origins=()):
    srv = api.serve(inv, host="127.0.0.1", port=0, token=token, allowed_origins=allowed_origins)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, dict(r.headers), json.load(r)


def test_api_token_header_only_and_no_wildcard_cors():
    inv = Inventory()
    inv.touch_host("10.0.0.5", "sweep")
    srv, base = _serve(inv, token="s3cret")
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(base + "/summary?token=s3cret")
        assert ei.value.code == 401
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(base + "/summary", {"Authorization": "Bearer wrong"})
        assert ei.value.code == 401
        status, headers, body = _get(base + "/summary", {"Authorization": "Bearer s3cret", "Origin": "http://evil.example"})
        assert status == 200 and body["hosts"] == 1
        assert "Access-Control-Allow-Origin" not in headers
    finally:
        srv.shutdown()
    assert api.token_ok({"Authorization": "Bearer abc"}, "abc") and not api.token_ok({"Authorization": "abc"}, "abc")
    assert not api.token_ok({}, "abc") and api.token_ok({}, "")
    srv, base = _serve(inv, allowed_origins=["http://localhost:3000"])
    try:
        _s, headers, _b = _get(base + "/summary", {"Origin": "http://localhost:3000"})
        assert headers["Access-Control-Allow-Origin"] == "http://localhost:3000" and headers.get("Vary") == "Origin"
        _s, headers, _b = _get(base + "/summary", {"Origin": "http://other:3000"})
        assert "Access-Control-Allow-Origin" not in headers
    finally:
        srv.shutdown()


def test_api_is_get_only():
    handler = api.make_handler(lambda: None)
    assert not any(m.startswith("do_") and m != "do_GET" for m in dir(handler))


# =========================================================================== #
# 10. listen
# =========================================================================== #
def _v2c_trap(community="public", trap="1.3.6.1.6.3.1.1.5.3", extra=()):
    from pyasn1.codec.ber import encoder
    from pysnmp.proto.api import v2c

    pdu = v2c.TrapPDU()
    v2c.apiTrapPDU.set_defaults(pdu)
    vbs = [(v2c.ObjectIdentifier("1.3.6.1.2.1.1.3.0"), v2c.TimeTicks(12345)),
           (v2c.ObjectIdentifier("1.3.6.1.6.3.1.1.4.1.0"), v2c.ObjectIdentifier(trap))]
    for oid, val in extra:
        vbs.append((v2c.ObjectIdentifier(oid), val))
    v2c.apiTrapPDU.set_varbinds(pdu, vbs)
    msg = v2c.Message()
    v2c.apiMessage.set_defaults(msg)
    v2c.apiMessage.set_community(msg, community)
    v2c.apiMessage.set_pdu(msg, pdu)
    return encoder.encode(msg)


def test_trap_decoded_and_community_never_recorded():
    from pysnmp.proto.api import v2c

    data = _v2c_trap("Sup3rS3cretComm", extra=[("1.3.6.1.2.1.2.2.1.1.3", v2c.Integer(3)),
                                                ("1.3.6.1.2.1.2.2.1.2.3", v2c.OctetString("Gi1/0/2")),
                                                ("1.3.6.1.2.1.2.2.1.8.3", v2c.Integer(2))])
    ev = listen.parse_trap(data, "10.0.0.2")
    assert ev.kind == "trap" and ev.message.startswith("linkDown ifIndex=3 ifDescr=Gi1/0/2 ifOperStatus=down"), ev.message
    assert "Sup3rS3cretComm" not in ev.message and "Sup3rS3cretComm" not in json.dumps(ev.details)
    assert ev.details["trap"] == "linkDown" and ev.details["version"] == "v2c" and ev.severity == "warning"
    # a factory-default community is flagged (it is not a secret, and worth knowing)
    ev2 = listen.parse_trap(_v2c_trap("public", trap="1.3.6.1.6.3.1.1.5.4"), "10.0.0.2")
    assert ev2.message.startswith("linkUp") and "default community 'public'" in ev2.message
    # an enterprise trap keeps its OID; an undecodable datagram degrades to a byte count
    ev3 = listen.parse_trap(_v2c_trap("x", trap="1.3.6.1.4.1.9.9.43.2.0.1"), "10.0.0.2")
    assert ev3.message.startswith("ciscoConfigManEvent")
    ev4 = listen.parse_trap(b"\x30\x03\x02\x01\x03", "10.0.0.2")
    assert "not decodable" in ev4.message


def test_v1_trap_decoded():
    from pyasn1.codec.ber import encoder
    from pysnmp.proto.api import v1

    pdu = v1.TrapPDU()
    v1.apiTrapPDU.set_defaults(pdu)
    v1.apiTrapPDU.set_enterprise(pdu, "1.3.6.1.4.1.9")
    v1.apiTrapPDU.set_generic_trap(pdu, 2)
    v1.apiTrapPDU.set_varbinds(pdu, [(v1.ObjectIdentifier("1.3.6.1.2.1.2.2.1.1.5"), v1.Integer(5))])
    msg = v1.Message()
    v1.apiMessage.set_defaults(msg)
    v1.apiMessage.set_community(msg, "secretcomm")
    v1.apiMessage.set_pdu(msg, pdu)
    ev = listen.parse_trap(encoder.encode(msg), "10.0.0.3")
    assert ev.message.startswith("linkDown ifIndex=5") and "secretcomm" not in ev.message and ev.details["version"] == "v1"


def test_syslog_rfc5424_structured_data_and_seq():
    raw = b'<165>1 2026-09-30T10:00:00Z core-sw-01 app 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"][x@1 a="b"] \xef\xbb\xbfInterface Gi1/0/2 is down'
    ev = listen.parse_syslog(raw, "10.0.0.2")
    assert ev.message == "Interface Gi1/0/2 is down" and ev.facility == "local4" and ev.severity == "notice"
    ev2 = listen.parse_syslog(b"<165>1 2026-09-30T10:00:00Z host app - - - plain message", "x")
    assert ev2.message == "plain message"
    assert listen.parse_syslog(b"<165>1 2026-09-30T10:00:00Z host app - - -", "x").message == ""
    ev3 = listen.parse_syslog(b"<13>hello", "x")
    assert ev3.seq > ev2.seq > ev.seq > 0


def test_collector_bind_addr_and_exclusive_on_windows(monkeypatch):
    c = listen.EventCollector(syslog_port=15141, trap_port=16201, bind_addr="127.0.0.1")
    try:
        listening = c.start()
        assert "syslog 127.0.0.1:15141" in listening
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"<190>hi", ("127.0.0.1", 15141))
        s.close()
        end = time.time() + 3
        while time.time() < end and not c.events:
            time.sleep(0.05)
        assert c.events and c.events[-1].message == "hi" and c.events[-1].seq > 0
    finally:
        c.stop()
    opts = []

    class FakeSock:
        def __init__(self, *a):
            pass

        def setsockopt(self, level, opt, val):
            opts.append(opt)

        def bind(self, addr):
            pass

        def settimeout(self, t):
            pass

    monkeypatch.setattr(listen.socket, "socket", FakeSock)
    monkeypatch.setattr(listen.sys, "platform", "win32")
    listen.EventCollector._open("0.0.0.0", 162)
    assert opts == [getattr(socket, "SO_EXCLUSIVEADDRUSE", 0xFFFFFFFB)] and socket.SO_REUSEADDR not in opts


# =========================================================================== #
# 11. dhcp
# =========================================================================== #
WIN_CSV = """IPAddress,ScopeId,HostName,ClientId,AddressState,LeaseExpiryTime
10.10.0.60,10.10.0.0,SALES-LT-7.corp.local,3c-52-82-1a-2b-3c,Active,2026-09-29 08:00
10.10.0.61,10.10.0.0,PRINTER1,aa-bb-cc-11-22-33,InactiveReservation,
10.10.0.62,10.10.0.0,,aa-bb-cc-11-22-34,ActiveReservation,
10.10.0.63,10.10.0.0,NEWPC,aa-bb-cc-11-22-35,Offered,2026-09-29 08:00
10.10.0.64,10.10.0.0,,aa-bb-cc-11-22-36,Declined,
"""

ISC_JOURNAL = """
lease 10.10.0.50 {
  binding state active;
  hardware ethernet 00:50:56:aa:bb:cc;
  client-hostname "old-owner";
}
lease 10.10.0.50 {
  starts 4 2026/09/28 10:00:00;
  ends 4 2026/09/28 22:00:00;
  binding state active;
  next binding state free;
  hardware ethernet 00:50:56:dd:ee:ff;
  client-hostname "new-owner";
}
lease 10.10.0.51 {
  binding state free;
  hardware ethernet 00:50:56:dd:ee:01;
}
lease 10.10.0.52 {
  binding state expired;
  hardware ethernet 00:50:56:dd:ee:02;
  client-hostname "gone-pc";
}
"""

NETSH = """
Changed the current scope context to 10.10.0.0 scope.

Type : N - NONE, D - DNS Only, B - Both, U - Unregistered, R - Routed
==============================================================================================
IP Address      - Subnet Mask    - Unique ID           - Lease Expires        -Type -Name
==============================================================================================

10.10.0.60      - 255.255.255.0  - 3c-52-82-1a-2b-3c   - 9/29/2026 8:00:00 AM   -D-  SALES-LT-7.corp.local
10.10.0.61      - 255.255.255.0  - aa-bb-cc-11-22-33   - NEVER EXPIRES          -N-  printer1
10.10.0.62      - 255.255.255.0  - 00-11-22-33-44-55   - INACTIVE               -D-  old-pc

No of Clients(version 4): 3 in the Scope : 10.10.0.0.
"""

WIN_XML = """<?xml version="1.0"?>
<DHCPServer xmlns="http://schemas.microsoft.com/dhcp/2011/08"><IPv4><Scopes><Scope>
<ScopeId>10.10.0.0</ScopeId><SubnetMask>255.255.255.0</SubnetMask>
<Leases>
<Lease><IPAddress>10.10.0.60</IPAddress><ScopeId>10.10.0.0</ScopeId><ClientId>3c-52-82-1a-2b-3c</ClientId><HostName>SALES-LT-7.corp.local</HostName><AddressState>Active</AddressState><LeaseExpiryTime>2026-09-29T08:00:00</LeaseExpiryTime></Lease>
<Lease><IPAddress>10.10.0.61</IPAddress><ScopeId>10.10.0.0</ScopeId><ClientId>aa-bb-cc-11-22-33</ClientId><HostName>x</HostName><AddressState>InactiveReservation</AddressState></Lease>
</Leases>
<Reservations><Reservation><IPAddress>10.10.0.70</IPAddress><ClientId>aa-bb-cc-00-00-70</ClientId><Name>core-printer</Name></Reservation></Reservations>
</Scope></Scopes></IPv4></DHCPServer>"""

KEA_JSON = json.dumps([{"result": 0, "text": "3 IPv4 lease(s) found.", "arguments": {"leases": [
    {"ip-address": "10.10.0.80", "hw-address": "00:50:56:00:00:80", "hostname": "kea-pc.", "state": 0, "cltt": 1790000000, "valid-lft": 3600, "subnet-id": 1},
    {"ip-address": "10.10.0.81", "hw-address": "00:50:56:00:00:81", "hostname": "", "state": 2, "cltt": 1790000000, "valid-lft": 3600, "subnet-id": 1},
    {"ip-address": "10.10.0.82", "hw-address": "00:50:56:00:00:82", "hostname": "", "state": 1, "cltt": 1790000000, "valid-lft": 3600, "subnet-id": 1},
]}}])


def test_windows_states_inactive_offered_declined():
    ls = {lz.ip: lz for lz in dhcp.parse_leases(WIN_CSV)}
    assert ls["10.10.0.60"].state == "active"
    assert ls["10.10.0.61"].state == "inactive"      # not "active" although the word contains it
    assert ls["10.10.0.62"].state == "reserved"
    assert ls["10.10.0.63"].state == "offered"
    assert ls["10.10.0.64"].state == "declined"
    inv = Inventory()
    inv.add_subnet("10.10.0.0/24", "test")
    summary = dhcp.import_leases(inv, list(ls.values()))
    assert set(inv.hosts) == {"10.10.0.60", "10.10.0.62"}  # inactive/offered/declined create no phantom hosts
    assert summary["new_hosts"] == 2 and summary["skipped"] == 3


def test_isc_last_block_wins_and_expired_only_updates_existing():
    ls = {lz.ip: lz for lz in dhcp.parse_isc_leases(ISC_JOURNAL)}
    assert len(ls) == 3
    assert ls["10.10.0.50"].hostname == "new-owner" and ls["10.10.0.50"].mac == "00:50:56:dd:ee:ff" and ls["10.10.0.50"].state == "active"
    assert ls["10.10.0.52"].state == "expired"
    inv = Inventory()
    inv.add_subnet("10.10.0.0/24", "test")
    inv.touch_host("10.10.0.52", "arp")  # already seen on the network: the expired lease may name it
    dhcp.import_leases(inv, list(ls.values()))
    assert "10.10.0.51" not in inv.hosts
    assert inv.hosts["10.10.0.52"].probes["dhcp"]["state"] == "expired" and inv.hosts["10.10.0.52"].mac == "00:50:56:dd:ee:02"
    assert inv.hosts["10.10.0.52"].hostname == ""  # an expired lease's name is a hint, not the host's name
    assert inv.hosts["10.10.0.50"].hostname == "new-owner"


def test_netsh_export_xml_and_kea_json_parsers():
    assert dhcp.detect_format(NETSH) == "netsh"
    ls = {lz.ip: lz for lz in dhcp.parse_leases(NETSH)}
    assert ls["10.10.0.60"].hostname == "SALES-LT-7" and ls["10.10.0.60"].mac == "3c:52:82:1a:2b:3c" and ls["10.10.0.60"].state == "active"
    assert ls["10.10.0.61"].state == "reserved" and ls["10.10.0.62"].state == "inactive" and ls["10.10.0.60"].scope == "10.10.0.0"
    assert dhcp.detect_format(WIN_XML) == "windows-xml"
    ls = {lz.ip: lz for lz in dhcp.parse_leases(WIN_XML)}
    assert ls["10.10.0.60"].hostname == "SALES-LT-7" and ls["10.10.0.60"].state == "active" and ls["10.10.0.60"].expires.startswith("2026")
    assert ls["10.10.0.61"].state == "inactive"
    assert ls["10.10.0.70"].state == "reserved" and ls["10.10.0.70"].hostname == "core-printer" and ls["10.10.0.70"].scope == "10.10.0.0"
    assert dhcp.detect_format(KEA_JSON) == "kea-json"
    ls = {lz.ip: lz for lz in dhcp.parse_leases(KEA_JSON)}
    assert ls["10.10.0.80"].hostname == "kea-pc" and ls["10.10.0.80"].state == "active" and ls["10.10.0.80"].expires
    assert ls["10.10.0.81"].state == "expired" and ls["10.10.0.82"].state == "declined"


def test_unrecognised_format_is_a_clear_error():
    with pytest.raises(dhcp.DhcpFormatError) as ei:
        dhcp.parse_leases("this is a shopping list\nmilk\neggs\n")
    assert "unrecognised DHCP export format" in str(ei.value) and "Kea" in str(ei.value)
    assert isinstance(ei.value, ValueError)  # callers catching ValueError keep working
    with pytest.raises(dhcp.DhcpFormatError):
        dhcp.parse_leases("{\"result\": 0}")
