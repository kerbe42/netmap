"""Agentless host deep-inspection, tested with injected runners (no real network)."""
import asyncio
import json

from netmap.hostinfo import (
    apply_facts,
    inspect_hosts,
    inspect_ssh,
    inspect_winrm,
    parse_netstat,
    parse_packages,
    parse_ss,
    parse_systemd_services,
    parse_win_connections,
    parse_win_software,
    parse_win_system,
)
from netmap.model import Host, Inventory

# --------------------------------------------------------------------------- #
# canned Linux command output
# --------------------------------------------------------------------------- #
OS_RELEASE = (
    'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
    'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
)
MEMINFO = "MemTotal:       16384000 kB\nMemFree:  1000000 kB\n"
CPUINFO = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2670 v3\ncache size\t: 30720 KB\n"
UPTIME = "123456.78 987654.32\n"
WHO = "justin   pts/0   2026-09-30 09:00 (10.0.0.9)\nroot     tty1    2026-09-30 08:00\njustin   pts/1   2026-09-30 09:05 (10.0.0.9)\n"
DPKG = "openssh-server\t1:8.9p1-3\nnginx\t1.18.0-6ubuntu14\nbash\t5.1-6ubuntu1\n"
SERVICES = (
    "ssh.service      loaded active running OpenSSH server daemon\n"
    "nginx.service    loaded active running A high performance web server\n"
)
SS_OUT = """Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*          users:(("sshd",pid=800,fd=3))
tcp   ESTAB  0      0      10.0.0.5:22         10.0.0.9:51000     users:(("sshd",pid=1234,fd=4))
tcp   ESTAB  0      0      10.0.0.5:443        203.0.113.7:52000  users:(("nginx",pid=999,fd=6))
udp   ESTAB  0      0      10.0.0.5:68         10.0.0.1:67        users:(("dhclient",pid=500,fd=7))
"""
NETSTAT_OUT = """Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 10.0.0.5:22             10.0.0.9:51000          ESTABLISHED 1234/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      999/nginx
udp        0      0 10.0.0.5:68             10.0.0.1:67             ESTABLISHED 500/dhclient
"""


def linux_run(overrides=None):
    """Build an injectable run(cmd)->stdout from canned output keyed by command."""
    from netmap.hostinfo import SSH_CMDS

    table = {
        SSH_CMDS["uname"]: "Linux 5.15.0-91-generic\n",
        SSH_CMDS["os_release"]: OS_RELEASE,
        SSH_CMDS["hostname"]: "web-01\n",
        SSH_CMDS["nproc"]: "8\n",
        SSH_CMDS["meminfo"]: MEMINFO,
        SSH_CMDS["cpuinfo"]: CPUINFO,
        SSH_CMDS["product"]: "PowerEdge R640\n",
        SSH_CMDS["vendor"]: "Dell Inc.\n",
        SSH_CMDS["serial"]: "ABC1234\n",
        SSH_CMDS["uptime"]: UPTIME,
        SSH_CMDS["who"]: WHO,
        SSH_CMDS["dpkg"]: DPKG,
        SSH_CMDS["services"]: SERVICES,
        SSH_CMDS["ss"]: SS_OUT,
    }
    if overrides:
        table.update(overrides)

    def run(cmd):
        return table.get(cmd, "")

    return run


# --------------------------------------------------------------------------- #
# Linux parser units
# --------------------------------------------------------------------------- #
def test_parse_packages():
    pkgs = parse_packages(DPKG)
    assert {"name": "nginx", "version": "1.18.0-6ubuntu14"} in pkgs
    assert len(pkgs) == 3


def test_parse_systemd_services():
    svcs = parse_systemd_services(SERVICES)
    names = {s["name"] for s in svcs}
    assert names == {"ssh.service", "nginx.service"}
    assert all(s["state"] == "running" for s in svcs)


def test_parse_ss_connections():
    conns = parse_ss(SS_OUT)
    # listening-only (0.0.0.0:*) dropped; three real connections kept
    assert len(conns) == 3
    ssh = next(c for c in conns if c["lport"] == "22")
    assert ssh["proto"] == "tcp" and ssh["state"] == "ESTAB"
    assert ssh["raddr"] == "10.0.0.9" and ssh["rport"] == "51000"
    assert ssh["process"] == "sshd"
    web = next(c for c in conns if c["raddr"] == "203.0.113.7")
    assert web["rport"] == "52000" and web["process"] == "nginx"


def test_parse_netstat_fallback():
    conns = parse_netstat(NETSTAT_OUT)
    assert len(conns) == 2  # LISTEN dropped
    ssh = next(c for c in conns if c["proto"] == "tcp")
    assert ssh["raddr"] == "10.0.0.9" and ssh["process"] == "sshd"
    assert any(c["proto"] == "udp" and c["process"] == "dhclient" for c in conns)


# --------------------------------------------------------------------------- #
# Linux collector via injected run
# --------------------------------------------------------------------------- #
def test_inspect_ssh_injected():
    facts = inspect_ssh("10.0.0.5", "admin", run=linux_run())
    assert facts["ok"] and facts["source"] == "ssh"
    sysf = facts["system"]
    assert sysf["os"] == "Ubuntu 22.04.3 LTS"
    assert sysf["kernel"] == "Linux 5.15.0-91-generic"
    assert sysf["cores"] == 8
    assert sysf["memory_mb"] == 16000  # 16384000 kB / 1024
    assert sysf["cpu"].startswith("Intel(R) Xeon")
    assert sysf["serial"] == "ABC1234"
    assert sysf["manufacturer"] == "Dell Inc." and sysf["product"] == "PowerEdge R640"
    assert sysf["uptime_s"] == 123456
    assert sysf["logged_on"] == ["justin", "root"]
    assert {"name": "openssh-server", "version": "1:8.9p1-3"} in facts["software"]
    assert {"name": "ssh.service", "state": "running"} in facts["services"]
    conn = next(c for c in facts["connections"] if c["raddr"] == "10.0.0.9")
    assert conn["rport"] == "51000" and conn["process"] == "sshd"


def test_inspect_ssh_rpm_and_netstat_fallback():
    # no dpkg, no ss: falls back to rpm and netstat
    from netmap.hostinfo import SSH_CMDS

    facts = inspect_ssh("10.0.0.6", "admin", run=linux_run(overrides={
        SSH_CMDS["dpkg"]: "",
        SSH_CMDS["rpm"]: "httpd\t2.4.57\nopenssh-server\t8.7p1\n",
        SSH_CMDS["ss"]: "",
        SSH_CMDS["netstat"]: NETSTAT_OUT,
    }))
    assert {"name": "httpd", "version": "2.4.57"} in facts["software"]
    assert any(c["process"] == "sshd" for c in facts["connections"])


def test_inspect_ssh_never_raises_on_bad_runner():
    def boom(cmd):
        raise RuntimeError("connection reset")

    facts = inspect_ssh("10.0.0.7", "admin", run=boom)
    # per-command errors are swallowed; the collector still returns ok with empty data
    assert facts["ok"] and facts["source"] == "ssh"
    assert facts["software"] == [] and facts["connections"] == []


# --------------------------------------------------------------------------- #
# Windows parsers via injected run_ps
# --------------------------------------------------------------------------- #
WIN_SYSTEM = json.dumps({
    "os": "Microsoft Windows Server 2019 Standard", "version": "10.0.17763",
    "hostname": "DC01", "domain": "corp.local", "manufacturer": "VMware, Inc.",
    "product": "VMware Virtual Platform", "serial": "VMware-56 4d",
    "cpu": "Intel(R) Xeon(R) Gold 6248", "cores": 4, "memory_mb": 8192,
    "uptime_s": 360000, "logged_on": "CORP\\administrator",
})
WIN_SOFTWARE = json.dumps([
    {"name": "Google Chrome", "version": "120.0.6099.109"},
    {"name": "7-Zip 23.01", "version": "23.01"},
])
WIN_SERVICES = json.dumps([{"name": "Dnscache", "state": "Running"}])
WIN_CONNS = json.dumps([
    {"LocalAddress": "10.0.0.10", "LocalPort": 3389, "RemoteAddress": "10.0.0.99",
     "RemotePort": 55000, "State": "Established", "OwningProcess": 1000, "ProcessName": "svchost"},
    {"LocalAddress": "0.0.0.0", "LocalPort": 445, "RemoteAddress": "0.0.0.0",
     "RemotePort": 0, "State": "Listen", "OwningProcess": 4, "ProcessName": "System"},
])


def test_parse_win_system():
    s = parse_win_system(WIN_SYSTEM)
    assert s["os"].startswith("Microsoft Windows Server 2019")
    assert s["kernel"] == "10.0.17763"
    assert s["cores"] == 4 and s["memory_mb"] == 8192
    assert s["manufacturer"] == "VMware, Inc." and s["product"] == "VMware Virtual Platform"
    assert s["logged_on"] == ["CORP\\administrator"]
    assert s["hostname"] == "DC01"


def test_parse_win_software_and_connections():
    sw = parse_win_software(WIN_SOFTWARE)
    assert {"name": "Google Chrome", "version": "120.0.6099.109"} in sw
    conns = parse_win_connections(WIN_CONNS)
    assert len(conns) == 1  # the Listen/0.0.0.0 entry is dropped
    assert conns[0]["raddr"] == "10.0.0.99" and conns[0]["rport"] == "55000"
    assert conns[0]["process"] == "svchost" and conns[0]["proto"] == "tcp"


def test_parse_win_software_single_object():
    # ConvertTo-Json emits a bare object (not a list) for a single item
    one = json.dumps({"name": "Notepad++", "version": "8.6"})
    assert parse_win_software(one) == [{"name": "Notepad++", "version": "8.6"}]


def test_inspect_winrm_injected():
    def run_ps(script):
        from netmap.hostinfo import PS_CONNECTIONS, PS_SERVICES, PS_SOFTWARE, PS_SYSTEM
        return {PS_SYSTEM: WIN_SYSTEM, PS_SOFTWARE: WIN_SOFTWARE,
                PS_SERVICES: WIN_SERVICES, PS_CONNECTIONS: WIN_CONNS}[script]

    facts = inspect_winrm("10.0.0.10", "corp\\admin", "pw", run_ps=run_ps)
    assert facts["ok"] and facts["source"] == "winrm"
    assert facts["system"]["os"].startswith("Microsoft Windows Server 2019")
    assert {"name": "Dnscache", "state": "Running"} in facts["services"]
    assert len(facts["connections"]) == 1


def test_inspect_winrm_auth_failure():
    def run_ps(script):
        raise RuntimeError("the specified credentials were rejected")

    facts = inspect_winrm("10.0.0.10", "u", "bad", run_ps=run_ps)
    assert facts["ok"] is False and "rejected" in facts["error"]
    assert facts["system"] == {}


# --------------------------------------------------------------------------- #
# apply_facts
# --------------------------------------------------------------------------- #
def test_apply_facts_fills_host():
    host = Host(ip="10.0.0.5")
    facts = inspect_ssh("10.0.0.5", "admin", run=linux_run())
    apply_facts(host, facts)
    assert host.inspect_source == "ssh"
    assert "ssh" in host.sources
    assert host.inspected_at > 0
    assert host.os == "Ubuntu 22.04.3 LTS"
    assert host.hostname == "web-01"
    assert host.vendor == "Dell Inc."
    assert host.system["cores"] == 8
    assert host.software and host.services and host.connections


def test_apply_facts_does_not_clobber_curated():
    host = Host(ip="10.0.0.5", hostname="curated-name", os="Custom OS", vendor="Acme")
    apply_facts(host, inspect_ssh("10.0.0.5", "admin", run=linux_run()))
    assert host.hostname == "curated-name" and host.os == "Custom OS" and host.vendor == "Acme"
    assert host.system["cores"] == 8  # facts still applied


# --------------------------------------------------------------------------- #
# orchestrator with injected inspectors (no sockets)
# --------------------------------------------------------------------------- #
def test_inspect_hosts_routing():
    inv = Inventory()
    inv.hosts["10.0.0.5"] = Host(ip="10.0.0.5", os_family="linux")
    inv.hosts["10.0.0.10"] = Host(ip="10.0.0.10", os_family="windows")

    def fake_ssh(ip, **kw):
        return {"ok": True, "source": "ssh", "system": {"os": "Linux", "hostname": "lin"},
                "software": [], "services": [], "connections": [], "error": ""}

    def fake_winrm(ip, **kw):
        return {"ok": True, "source": "winrm", "system": {"os": "Windows", "hostname": "win"},
                "software": [], "services": [], "connections": [], "error": ""}

    creds = {"linux": {"username": "root", "password": "p"},
             "windows": {"username": "adm", "password": "p"}}
    counts = asyncio.run(inspect_hosts(inv, creds, ssh_inspector=fake_ssh, winrm_inspector=fake_winrm))
    assert counts == {"inspected": 2, "ok": 2, "linux": 1, "windows": 1, "failed": 0}
    assert inv.hosts["10.0.0.5"].inspect_source == "ssh"
    assert inv.hosts["10.0.0.10"].inspect_source == "winrm"
    assert inv.hosts["10.0.0.10"].os == "Windows"


def test_inspect_hosts_unknown_falls_back_to_winrm():
    inv = Inventory()
    inv.hosts["10.0.0.20"] = Host(ip="10.0.0.20")  # os_family unknown

    def fail_ssh(ip, **kw):
        return {"ok": False, "source": "ssh", "system": {}, "software": [],
                "services": [], "connections": [], "error": "timeout"}

    def ok_winrm(ip, **kw):
        return {"ok": True, "source": "winrm", "system": {}, "software": [],
                "services": [], "connections": [], "error": ""}

    creds = {"linux": {"username": "root", "password": "p"},
             "windows": {"username": "adm", "password": "p"}}
    counts = asyncio.run(inspect_hosts(inv, creds, ssh_inspector=fail_ssh, winrm_inspector=ok_winrm))
    assert counts == {"inspected": 1, "ok": 1, "linux": 0, "windows": 1, "failed": 0}


def test_inspect_hosts_skips_snmp_devices_and_counts_failures():
    inv = Inventory()
    inv.hosts["10.0.0.5"] = Host(ip="10.0.0.5", os_family="linux")
    inv.hosts["10.0.0.1"] = Host(ip="10.0.0.1", os_family="linux")
    inv.ip_to_device["10.0.0.1"] = "10.0.0.1"  # already an SNMP device -> skipped

    def fail_ssh(ip, **kw):
        return {"ok": False, "source": "ssh", "system": {}, "software": [],
                "services": [], "connections": [], "error": "refused"}

    counts = asyncio.run(inspect_hosts(inv, {"linux": {"username": "root"}}, ssh_inspector=fail_ssh))
    assert counts == {"inspected": 1, "ok": 0, "linux": 0, "windows": 0, "failed": 1}
