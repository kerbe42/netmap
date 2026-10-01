"""Bounded nmap runs: sweeps cut into /24 blocks, runs stopped at their time limit keep what
they finished and retry the rest, and the port scan only goes to addresses that answer."""
import asyncio
import ipaddress as ia
import stat
import sys
import time

import pytest

import subnetsleuth.sweep as sw
from subnetsleuth.cli import build_parser
from subnetsleuth.model import Device, Inventory
from subnetsleuth.scan import ScanRequest, run_scan
from subnetsleuth.snmp import Credential

from .fake_snmp import make_prober


def nets(*items):
    return [ia.ip_network(x) for x in items]


def host_xml(ip, ports=(), finished=True):
    ps = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="svc{p}"/></port>' for p in ports)
    return (f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>{ps}</ports></host>'
            if finished else f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>')


def doc(*hosts, complete=True):
    return '<?xml version="1.0"?><nmaprun scanner="nmap">' + "".join(hosts) + ("</nmaprun>" if complete else "")


@pytest.fixture
def nmap_present(monkeypatch):
    monkeypatch.setattr(sw, "find_nmap", lambda: "/usr/bin/nmap")


def test_truncated_output_keeps_every_finished_host():
    # nmap stopped mid-way: two whole hosts, then a third cut off inside its <ports>
    text = doc(host_xml("10.0.0.1", [22]), host_xml("10.0.0.2"), host_xml("10.0.0.3", [80], finished=False), complete=False)
    recs = sw._parse_nmap_xml(text)
    assert [r["ip"] for r in recs] == ["10.0.0.1", "10.0.0.2"]
    assert recs[0]["ports"][0]["port"] == 22
    assert sw._parse_nmap_xml("") == [] and sw._parse_nmap_xml('<?xml version="1.0"?><nmaprun>') == []


def test_large_subnet_is_swept_as_24_blocks_side_by_side(nmap_present, monkeypatch):
    calls, running, peak = [], [0], [0]

    async def fake_nmap(args, timeout, kind="", target=""):
        calls.append((args, timeout))
        running[0] += 1
        peak[0] = max(peak[0], running[0])
        await asyncio.sleep(0.01)
        running[0] -= 1
        block = ia.ip_network(args[-1])
        return sw.NmapRun(doc(host_xml(str(block.network_address + 10))), "ok")

    monkeypatch.setattr(sw, "_run_nmap", fake_nmap)
    hosts, complete = asyncio.run(sw.sweep_subnet("10.8.0.0/20", nmap_timeout=60, scope=nets("10.0.0.0/8"), exclude=nets("10.8.3.0/24")))
    blocks = sorted(a[-1] for a, _ in calls)
    assert len(blocks) == 15 and "10.8.3.0/24" not in blocks and all(b.endswith("/24") for b in blocks)
    assert all(t == 60 for _, t in calls)
    assert complete and len(hosts) == 15
    assert 1 < peak[0] <= sw.NMAP_PARALLEL


def test_a_block_that_times_out_keeps_its_hosts_and_is_retried_with_twice_the_time(nmap_present, monkeypatch, caplog):
    calls = []

    async def fake_nmap(args, timeout, kind="", target=""):
        calls.append(timeout)
        if len(calls) == 1:  # first run: stopped at its limit after reporting one host
            return sw.NmapRun(doc(host_xml("10.9.0.5"), complete=False), "timeout")
        return sw.NmapRun(doc(host_xml("10.9.0.5"), host_xml("10.9.0.77")), "ok")

    monkeypatch.setattr(sw, "_run_nmap", fake_nmap)
    with caplog.at_level("WARNING", logger="subnetsleuth.sweep"):
        hosts, complete = asyncio.run(sw.sweep_subnet("10.9.0.0/24", nmap_timeout=120))
    assert calls == [120, 240]
    assert complete and sorted(h["ip"] for h in hosts) == ["10.9.0.5", "10.9.0.77"]
    assert "kept the 1 live address(es)" in caplog.text and "2 min" in caplog.text and "4 min" in caplog.text


def test_a_subnet_that_never_finishes_is_not_marked_swept(nmap_present, monkeypatch):
    async def fake_nmap(args, timeout, kind="", target=""):
        return sw.NmapRun(doc(host_xml("10.9.0.5"), complete=False), "timeout")

    monkeypatch.setattr(sw, "_run_nmap", fake_nmap)
    inv = Inventory()
    live = set()
    n = asyncio.run(sw.sweep(inv, ["10.9.0.0/24"], nets("10.0.0.0/8"), [], nmap_timeout=1, live=live))
    # what it did find is kept, but the next sweep (without --resweep) tries the subnet again
    assert n == 1 and "10.9.0.5" in inv.hosts and live == {"10.9.0.5"}
    assert inv.subnets["10.9.0.0/24"].swept is False


def test_port_scan_retries_only_the_unfinished_addresses_in_smaller_batches(nmap_present, monkeypatch, caplog):
    calls = []
    slow = {"10.1.0.7"}  # never finishes in time

    async def fake_nmap(args, timeout, kind="", target=""):
        targets = [a for a in args if a.startswith("10.")]
        calls.append((targets, timeout))
        assert "--open" not in args and "-Pn" in args
        if len(calls) == 1:  # the first batch is stopped after three of its addresses
            return sw.NmapRun(doc(*[host_xml(ip, [443] if ip == "10.1.0.1" else []) for ip in targets[:3]], complete=False), "timeout")
        done = [ip for ip in targets if ip not in slow]
        return sw.NmapRun(doc(*[host_xml(ip, [22]) for ip in done], complete=not (set(targets) & slow)),
                          "timeout" if set(targets) & slow else "ok")

    monkeypatch.setattr(sw, "_run_nmap", fake_nmap)
    ips = [f"10.1.0.{i}" for i in range(1, 11)]
    with caplog.at_level("WARNING", logger="subnetsleuth.sweep"):
        out = asyncio.run(sw.nmap_inspect(ips, batch=8, nmap_timeout=300))
    first, *rest = calls
    assert first == (ips[:8], 300)
    retried = [ip for targets, t in rest if t == 600 for ip in targets]
    # the three it finished are not scanned again; the five it had not reached are, two at a time
    assert sorted(retried) == sorted(ips[3:8]) and all(len(t) <= 2 for t, lim in rest if lim == 600)
    # a finished address with no open port is not reported; one with a port is
    assert "10.1.0.2" not in out and out["10.1.0.1"]["ports"][0]["port"] == 443
    assert out["10.1.0.4"]["ports"][0]["port"] == 22 and "10.1.0.7" not in out
    assert "could not finish 1 address(es) even with 10 min: 10.1.0.7" in caplog.text


def test_live_addresses_counts_unfinished_batches_as_up(nmap_present, monkeypatch):
    async def fake_nmap(args, timeout, kind="", target=""):
        targets = [a for a in args if a.startswith("10.")]
        if "10.2.0.9" in targets:  # this batch never finishes, even on the retry
            return sw.NmapRun(doc(host_xml("10.2.0.8"), complete=False), "timeout")
        return sw.NmapRun(doc(host_xml(targets[0])), "ok")

    monkeypatch.setattr(sw, "_run_nmap", fake_nmap)
    up = asyncio.run(sw.live_addresses(["10.2.0.1", "10.2.0.2", "10.2.0.8", "10.2.0.9"], nmap_timeout=60, batch=2))
    # first batch: only .1 answered; second batch never finished, so both count as up
    assert up == {"10.2.0.1", "10.2.0.8", "10.2.0.9"}
    monkeypatch.setattr(sw, "find_nmap", lambda: None)
    assert asyncio.run(sw.live_addresses(["10.2.0.1"])) is None


def _port_scan_inventory():
    inv = Inventory()
    inv.add_device(Device(id="10.0.0.1"))  # from an earlier scan: not polled now
    inv.add_device(Device(id="10.0.0.2", collected_at=time.time() + 3600))  # polled during this scan
    for ip in ("10.0.5.10", "10.0.5.11", "10.0.5.12"):
        inv.touch_host(ip, "arp")
    return inv


def test_port_scan_goes_only_to_addresses_that_answer(monkeypatch):
    seen = {}

    async def fake_live(ips, nmap_timeout=None, **kw):
        seen["pinged"], seen["ping_limit"] = sorted(ips), nmap_timeout
        return {"10.0.5.10"}

    async def fake_inspect(ips, nmap_timeout=None, **kw):
        seen["scanned"], seen["scan_limit"] = sorted(ips), nmap_timeout
        return {}

    monkeypatch.setattr(sw, "live_addresses", fake_live)
    monkeypatch.setattr(sw, "nmap_inspect", fake_inspect)
    creds = [Credential(kind="v2c", community="x")]
    req = ScanRequest(scope=["10.0.0.0/8"], credentials=creds, port_scan=True, nmap_timeout=45)
    asyncio.run(run_scan(_port_scan_inventory(), req, engine=object(), prober=make_prober({})))
    # the device polled this scan is known to be up; everything else is pinged first
    assert seen["pinged"] == ["10.0.0.1", "10.0.5.10", "10.0.5.11", "10.0.5.12"]
    assert seen["scanned"] == ["10.0.0.2", "10.0.5.10"]
    assert seen["ping_limit"] == seen["scan_limit"] == 45 * 60
    # turned off: every address found is port-scanned, with no limit when 0
    seen.clear()
    req = ScanRequest(scope=["10.0.0.0/8"], credentials=creds, port_scan=True, ping_first=False, nmap_timeout=0)
    asyncio.run(run_scan(_port_scan_inventory(), req, engine=object(), prober=make_prober({})))
    assert "pinged" not in seen and len(seen["scanned"]) == 5 and seen["scan_limit"] is None


def test_cli_nmap_timeout_and_ping_first(monkeypatch, tmp_path):
    import subnetsleuth.cli as cli

    seen = {}

    async def fake_run_scan(inv, req):
        seen["req"] = req
        return {}

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_outputs", lambda inv, args: None)
    out = str(tmp_path / "m.json")
    asyncio.run(cli.cmd_crawl(build_parser().parse_args(["crawl", "--seed", "10.7.0.1", "--out", out])))
    assert seen["req"].nmap_timeout == 30 and seen["req"].ping_first is True
    asyncio.run(cli.cmd_crawl(build_parser().parse_args(["crawl", "--seed", "10.7.0.1", "--out", out, "--nmap-timeout", "0", "--no-ping-first"])))
    assert seen["req"].nmap_timeout == 0 and seen["req"].ping_first is False
    cfg = tmp_path / "n.toml"
    cfg.write_text("[crawl]\nnmap_timeout = 90\nping_first = false\n")
    asyncio.run(cli.cmd_crawl(build_parser().parse_args(["crawl", "--seed", "10.7.0.1", "--out", out, "-c", str(cfg)])))
    assert seen["req"].nmap_timeout == 90 and seen["req"].ping_first is False


@pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX shell script in place of nmap")
def test_a_real_run_stopped_at_its_limit_returns_what_it_had_written(monkeypatch, tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\n"
                    f"printf '%s' '{doc(host_xml('10.3.0.1', [22]), complete=False)}'\n"
                    "exec sleep 30\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(sw, "find_nmap", lambda: str(fake))
    t0 = time.time()
    run = asyncio.run(sw._run_nmap(["-sn", "10.3.0.0/24"], 1.0))
    assert run.status == "timeout" and time.time() - t0 < 10
    assert [r["ip"] for r in sw._parse_nmap_xml(run.xml)] == ["10.3.0.1"]
    # no limit: runs to the end
    fake.write_text(f"#!/bin/sh\nprintf '%s' '{doc(host_xml('10.3.0.2'))}'\n")
    run = asyncio.run(sw._run_nmap([], None))
    assert run.status == "ok" and [r["ip"] for r in sw._parse_nmap_xml(run.xml)] == ["10.3.0.2"]


def test_fmt_limit():
    assert sw.fmt_limit(None) == "no limit" and sw.fmt_limit(0) == "no limit"
    assert sw.fmt_limit(1800) == "30 min" and sw.fmt_limit(90) == "1.5 min" and sw.fmt_limit(1.0) == "1 s"
