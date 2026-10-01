"""Deep scan, live activity and uncapped entered ranges."""
import asyncio
import ipaddress as ia
import time

import pytest

import netmap.deepscan as ds
import netmap.sweep as sw
from netmap import activity
from netmap.cli import build_parser
from netmap.model import Device, Inventory

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.98">
<taskbegin task="SYN Stealth Scan" time="1"/>
<taskend task="SYN Stealth Scan" time="2"/>
<host starttime="1" endtime="2"><status state="up" reason="user-set"/>
<address addr="10.20.0.15" addrtype="ipv4"/>
<address addr="00:50:56:AA:BB:CC" addrtype="mac" vendor="VMware"/>
<hostnames><hostname name="fs01.corp.local" type="PTR"/></hostnames>
<ports><extraports state="filtered" count="65532"><extrareasons reason="no-response" count="65532"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.10" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe></service><script id="ssh-hostkey" output="&#xa;  256 aa:bb (ECDSA)&#xa;  256 cc:dd (ED25519)"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/><script id="ssl-cert" output="Subject: commonName=fs01.corp.local&#xa;Not valid after:  2027-01-01T00:00:00"/><script id="http-title" output="Files"/></port>
<port protocol="tcp" portid="8080"><state state="closed" reason="reset"/><service name="http-proxy" method="table" conf="3"/></port>
</ports>
<os><osmatch name="Linux 5.0 - 5.14" accuracy="96"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="96"/></osmatch><osmatch name="Linux 4.15" accuracy="90"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="90"/></osmatch></os>
<uptime seconds="864000" lastboot="Mon Sep 21 10:00:00 2026"/>
<distance value="2"/>
<hostscript><script id="clock-skew" output="0s"/></hostscript>
<trace port="443" proto="tcp"><hop ttl="1" ipaddr="10.10.0.1" rtt="0.50" host="core-rtr"/><hop ttl="2" ipaddr="10.20.0.15" rtt="0.90"/></trace>
</host>
<runstats><finished time="2" exit="success"/></runstats>
</nmaprun>"""


def fake_nmap_for(xml_by_ip, calls=None, status="ok"):
    async def fake(args, timeout, kind="", target=""):
        if calls is not None:
            calls.append((args, timeout, kind, target))
        return sw.NmapRun(xml_by_ip(args[-1]), status)
    return fake


@pytest.fixture
def nmap_here(monkeypatch):
    monkeypatch.setattr(ds, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(sw, "find_nmap", lambda: "/usr/bin/nmap")


# ---------------------------------------------------------------- activity


def test_activity_lists_what_is_in_flight_and_forgets_it_when_done():
    act = activity.Activity()
    with act.working("ping sweep", "10.20.4.0/24"):
        with act.working("ping sweep", "10.20.5.0/24") as item:
            item.detail = "Ping Scan"
            assert act.summary() == "ping sweep 10.20.4.0/24, 10.20.5.0/24 (Ping Scan)"
        with act.working("SNMP", "10.0.0.1"):
            assert act.summary() == "ping sweep 10.20.4.0/24 · SNMP 10.0.0.1"
    assert act.now() == [] and act.summary() == ""
    # many of one kind: the first few and a count
    many = [act.working("port scan", f"10.1.0.{i}") for i in range(9)]
    for cm in many:
        cm.__enter__()
    assert act.summary(limit=3).endswith("(+6 more)")
    for cm in many:
        cm.__exit__(None, None, None)
    # long-running items show how long they have been going
    it = activity.Item("deep scan", "10.9.9.9", started=time.time() - 125)
    assert it.describe() == "10.9.9.9 (2m05s)"
    assert activity.span(["10.1.0.1", "10.1.0.2"]) == "10.1.0.1, 10.1.0.2"
    assert activity.span([f"10.1.0.{i}" for i in range(1, 25)]) == "10.1.0.1 - 10.1.0.24 (24)"


def test_each_task_tree_reports_into_its_own_activity():
    seen = {}

    async def job(name):
        act = activity.Activity()
        activity.use(act)

        async def child():
            with activity.working("ping sweep", name):
                await asyncio.sleep(0.02)

        t = asyncio.ensure_future(child())
        await asyncio.sleep(0.01)
        seen[name] = act.summary()
        await t

    async def main():
        await asyncio.gather(job("10.1.0.0/24"), job("10.2.0.0/24"))

    asyncio.run(main())
    assert seen == {"10.1.0.0/24": "ping sweep 10.1.0.0/24", "10.2.0.0/24": "ping sweep 10.2.0.0/24"}


def test_an_nmap_run_is_listed_while_it_runs_with_its_stage(monkeypatch):
    seen = []

    async def fake_process(cmd, timeout, item):
        seen.append(activity.current().summary())
        item.detail = "Service scan"
        seen.append(activity.current().summary())
        return sw.NmapRun("<nmaprun/>", "ok")

    monkeypatch.setattr(sw, "_nmap_process", fake_process)
    act = activity.Activity()

    async def main():
        activity.use(act)
        await sw._run_nmap(["-sV", "10.1.0.1"], 5, "port scan", "10.1.0.1")

    asyncio.run(main())
    assert seen == ["port scan 10.1.0.1", "port scan 10.1.0.1 (Service scan)"] and act.now() == []


# ---------------------------------------------------------------- entered ranges have no size cap


def test_an_entered_range_is_swept_whatever_its_size_with_a_warning(monkeypatch, caplog):
    blocks = []

    async def fake_nmap(args, timeout, kind="", target=""):
        blocks.append(args[-1])
        return sw.NmapRun("<nmaprun/>", "ok")

    monkeypatch.setattr(sw, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(sw, "_run_nmap", fake_nmap)
    inv = Inventory()
    with caplog.at_level("WARNING", logger="netmap.sweep"):
        asyncio.run(sw.discover_targets(inv, [ia.ip_network("10.64.0.0/16")], [ia.ip_network("10.0.0.0/8")], []))
    assert len(blocks) == 256 and inv.subnets["10.64.0.0/16"].swept
    assert "10.64.0.0/16 is large (65,536 addresses, 256 /24 blocks)" in caplog.text and "takes roughly" in caplog.text
    # discovered subnets keep the cap; named ones (max_prefix=None) do not
    blocks.clear()
    asyncio.run(sw.sweep(inv, ["10.65.0.0/20"], [ia.ip_network("10.0.0.0/8")], [], max_prefix=22))
    assert blocks == []
    asyncio.run(sw.sweep(inv, ["10.65.0.0/20"], [ia.ip_network("10.0.0.0/8")], [], max_prefix=None))
    assert len(blocks) == 16


def test_sweep_estimate_is_a_rough_range():
    assert sw.sweep_estimate(256) == "a minute"
    assert sw.sweep_estimate(65536) == "3 min to 16 min"
    assert sw.sweep_estimate(2 ** 24) == "11 h to 3 days"


def test_cli_sweep_of_named_subnets_is_uncapped(monkeypatch, tmp_path):
    import netmap.cli as cli

    seen = {}

    async def fake_sweep(inv, subnets, scope, exclude, max_prefix=22, **kw):
        seen["max_prefix"] = max_prefix
        return 0

    monkeypatch.setattr(cli, "sweep", fake_sweep)
    monkeypatch.setattr(cli, "_outputs", lambda inv, args: None)
    asyncio.run(cli.cmd_sweep(build_parser().parse_args(["sweep", "-m", str(tmp_path / "m.json"), "--subnet", "10.0.0.0/16"])))
    assert seen["max_prefix"] is None


# ---------------------------------------------------------------- deep scan


def test_deep_args_cover_every_port_and_respect_privilege():
    opts = ds.DeepScanOptions(udp=True)
    user = ds.deep_args(opts, admin=False)
    assert "-p-" in user and "-sT" in user and "-sU" not in user and "-O" not in user and "--traceroute" not in user
    assert user[user.index("--script") + 1] == "default and safe" and "--version-all" in user and "-v" in user
    root = ds.deep_args(opts, admin=True)
    assert "-sS" in root and "-sU" in root and "-O" in root and "--traceroute" in root
    assert root[root.index("-p") + 1].startswith("T:1-65535,U:53,")
    assert "--script" not in ds.deep_args(ds.DeepScanOptions(scripts=False), admin=True)


def test_parse_deep_xml_reads_ports_scripts_os_and_path():
    rec = ds.parse_deep_xml(SAMPLE_XML, "10.20.0.15")
    assert rec["hostname"] == "fs01.corp.local" and rec["mac"] == "00:50:56:AA:BB:CC" and rec["vendor"] == "VMware"
    assert [p["port"] for p in rec["ports"]] == [22, 443, 8080]
    ssh = rec["ports"][0]
    assert ssh["product"] == "OpenSSH" and ssh["version"].startswith("8.9p1") and ssh["cpe"] == ["cpe:/a:openbsd:openssh:8.9p1"]
    assert "ED25519" in ssh["scripts"]["ssh-hostkey"]
    assert rec["ports"][1]["tunnel"] == "ssl" and rec["ports"][1]["scripts"]["http-title"] == "Files"
    assert rec["os"][0] == {"name": "Linux 5.0 - 5.14", "accuracy": 96, "family": "Linux", "vendor": "Linux", "gen": "5.X", "type": "general purpose"}
    assert rec["uptime"]["seconds"] == 864000 and rec["distance"] == 2 and rec["host_scripts"] == {"clock-skew": "0s"}
    assert [h["ip"] for h in rec["trace"]] == ["10.10.0.1", "10.20.0.15"] and rec["trace"][0]["host"] == "core-rtr"
    assert rec["not_shown"] == ["65,532 filtered"]
    assert [p["port"] for p in ds.standard_ports(rec)] == [22, 443]
    assert ds.standard_ports(rec)[0]["product"] == "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 Ubuntu Linux; protocol 2.0"
    # cut short mid-host: nothing for that host; another address: None
    assert ds.parse_deep_xml(SAMPLE_XML[:SAMPLE_XML.index("<os>")], "10.20.0.15") is None
    assert ds.parse_deep_xml(SAMPLE_XML, "10.20.0.16") is None


def test_deep_scan_is_kept_in_the_project_and_folded_onto_the_host(nmap_here, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(ds, "_run_nmap", fake_nmap_for(lambda ip: SAMPLE_XML, calls))
    monkeypatch.setattr(ds, "is_admin", lambda: True)
    inv = Inventory()
    inv.add_device(Device(id="10.10.0.1"))
    result = asyncio.run(ds.deep_scan_into(inv, ["10.20.0.15", "10.10.0.1", "10.99.0.1"], ds.DeepScanOptions(timeout=600),
                                           exclude=[ia.ip_network("10.99.0.0/16")]))
    # the excluded address is refused without running nmap
    assert result["refused"] == ["10.99.0.1"] and sorted(c[0][-1] for c in calls) == ["10.10.0.1", "10.20.0.15"]
    assert all(c[1] == 600 and c[2] == "deep scan" for c in calls)
    # an address that was not in the project becomes a host with the findings
    h = inv.hosts["10.20.0.15"]
    assert {p["port"] for p in h.ports} == {22, 443} and h.probes["nmap"]["os"] == "Linux 5.0 - 5.14"
    assert inv.deep_scans["10.20.0.15"]["status"] == "ok" and inv.deep_scans["10.20.0.15"]["ports"][1]["scripts"]["http-title"] == "Files"
    # the device's record is kept too (nmap reported no host for it in this fake)
    assert inv.deep_scans["10.10.0.1"]["status"] == "ok" and "ports" not in inv.deep_scans["10.10.0.1"]
    # saved and loaded with the project
    inv.save(str(tmp_path / "p.json"))
    again = Inventory.load(str(tmp_path / "p.json"))
    assert again.deep_scans["10.20.0.15"]["os"][0]["accuracy"] == 96
    # an unfinished rescan does not replace a finished deep scan
    monkeypatch.setattr(ds, "_run_nmap", fake_nmap_for(lambda ip: SAMPLE_XML[:SAMPLE_XML.index("<host ")], status="timeout"))
    asyncio.run(ds.deep_scan_into(inv, ["10.20.0.15"]))
    assert inv.deep_scans["10.20.0.15"]["status"] == "ok"
    # forgetting the host forgets its deep scan
    inv.remove_host("10.20.0.15")
    assert "10.20.0.15" not in inv.deep_scans


def test_cli_deepscan(nmap_here, monkeypatch, tmp_path, capsys):
    import netmap.cli as cli

    calls = []
    monkeypatch.setattr(ds, "_run_nmap", fake_nmap_for(lambda ip: SAMPLE_XML, calls))
    path = str(tmp_path / "site.json")
    rc = asyncio.run(cli.cmd_deepscan(build_parser().parse_args(["deepscan", "10.20.0.15", "-m", path, "--nmap-timeout", "20", "--no-scripts"])))
    out = capsys.readouterr().out
    assert rc == 0 and "10.20.0.15: ok, 2 open port(s); OS Linux 5.0 - 5.14 (96%)" in out and "443/tcp" in out
    assert calls[0][1] == 1200 and "--script" not in calls[0][0]
    assert Inventory.load(path).deep_scans["10.20.0.15"]["hostname"] == "fs01.corp.local"
    assert asyncio.run(cli.cmd_deepscan(build_parser().parse_args(["deepscan", "not-an-ip", "-m", path]))) == 2
