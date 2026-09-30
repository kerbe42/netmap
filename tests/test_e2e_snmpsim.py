"""End-to-end: real pysnmp against snmpsim agents on loopback, driven through the CLI."""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from . import labnet

PORT = 11161
RESPONDER = os.path.join(os.path.dirname(sys.executable), "snmpsim-command-responder")
pytestmark = pytest.mark.skipif(not os.path.exists(RESPONDER), reason="snmpsim not installed")


def _wait_agent(ip, cred_args, timeout=15):
    from netmap import oids as O
    from netmap.snmp import Credential, SnmpSession
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

    async def one():
        eng = SnmpEngine()
        try:
            r = await SnmpSession(eng, ip, Credential.from_dict(cred_args), port=PORT, timeout=1, retries=0).get(O.SYS_NAME)
            return r.get(O.SYS_NAME)
        finally:
            eng.close_dispatcher()

    end = time.time() + timeout
    while time.time() < end:
        try:
            if asyncio.run(one()):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


@pytest.fixture(scope="module")
def agents(tmp_path_factory):
    lab = labnet.build("127")
    procs = []
    root = tmp_path_factory.mktemp("snmpsim")
    for ip, dev in lab.items():
        d = root / ip.replace(".", "_")
        d.mkdir()
        (d / "lab.snmprec").write_text(dev.snmprec())
        cmd = [
            RESPONDER, f"--data-dir={d}", f"--agent-udpv4-endpoint={ip}:{PORT}", "--logging-method=null",
            "--v3-user=netmap", "--v3-auth-key=authpass123", "--v3-auth-proto=SHA", "--v3-priv-key=privpass123", "--v3-priv-proto=AES",
        ]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    ok = all(_wait_agent(ip, {"kind": "v2c", "community": "lab"}) for ip in lab)
    if not ok:
        for p in procs:
            p.kill()
        pytest.skip("snmpsim agents did not come up on loopback")
    yield lab
    for p in procs:
        p.kill()
        p.wait()


def _run_cli(args, cwd):
    env = {**os.environ, "NETMAP_ALLOW_LOOPBACK": "1"}
    return subprocess.run([sys.executable, "-m", "netmap", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=300)


def test_cli_crawl_v2c(agents, tmp_path):
    r = _run_cli(
        ["crawl", "--seed", "127.0.0.1", "--port", str(PORT), "-C", "wrongcommunity", "-C", "lab", "--scope", "127.0.0.0/8", "--timeout", "1", "--retries", "0",
         "--out", "map.json", "--html", "map.html", "--graphml", "map.graphml", "--dot", "map.dot", "--csv", "inv-"],
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stderr[-2000:]
    inv = json.loads((tmp_path / "map.json").read_text())
    assert set(inv["devices"]) == {"127.0.0.1", "127.0.0.2", "127.1.0.2"}
    sw1 = inv["devices"]["127.0.0.2"]
    assert sw1["name"] == "dist-sw1" and sw1["role"] == "l3switch" and sw1["serial"] == "FOC1234SW1X" and sw1["credential"] == "v2c:lab***"
    assert {n["remote_name"] for n in sw1["neighbors"]} == {"acc-sw2", "ap-lobby", "branch-fw", "core-rtr.example.test"}
    assert any(f["mac"] == labnet.MAC_C and f["vlan"] == 20 and f["if_index"] == 5 for f in sw1["fdb"])
    assert any(r_["dest"] == "0.0.0.0/0" and r_["nexthop"] == "127.0.0.1" for r_ in sw1["routes"])
    assert sw1["vlans"] == {"10": "USERS", "20": "SERVERS", "30": "BRANCH"}
    assert sw1["errors"] == []
    sw2 = inv["devices"]["127.1.0.2"]
    assert sw2["vendor"] == "HP" and sw2["role"] == "switch" and len([f for f in sw2["fdb"] if f["if_index"] == 24]) == 14
    assert inv["hosts"]["127.1.0.50"]["mac"] == labnet.MAC_A
    # OS version, ENTITY-MIB components, per-port VLAN/mode, LAG and ifLastChange through real pysnmp:
    # Gauge32 PVIDs, PortList octet strings, TimeTicks and the 1.2.840 LAG subtree all decode
    assert (sw1["os_version"], sw2["os_version"], inv["devices"]["127.0.0.1"]["os_version"]) == ("16.12.4", "YA.16.10.0016", "17.6.4")
    comps = {c["index"]: c for c in sw1["components"]}
    assert sorted(comps) == [1, 1000, 1002, 1003, 1005, 1008, 2000, 2002]
    assert [c["serial"] for c in sw1["components"] if c["cls"] == "chassis"] == ["FOC1234SW1X", "FOC1234SW2Y"]
    assert {k: comps[1008][k] for k in ("cls", "model", "serial", "hw_rev", "fru", "parent")} == {
        "cls": "port", "model": "SFP-10G-SR", "serial": "AVD2045K1LM", "hw_rev": "V03", "fru": True, "parent": 1005}
    assert (comps[1002]["cls"], comps[1002]["parent"], comps[1]["cls"]) == ("powerSupply", 1000, "stack")
    s1 = {i["index"]: i for i in sw1["interfaces"]}
    assert [(s1[i]["mode"], s1[i]["vlan"]) for i in (2, 5, 24, 1)] == [("trunk", 1), ("access", 20), ("access", 10), ("", None)]
    assert s1[5]["last_change_s"] == 987 and s1[2]["last_change_s"] == 12
    s2 = {i["index"]: i for i in sw2["interfaces"]}
    assert [(s2[p]["vlan"], s2[p]["mode"]) for p in (3, 4, 2, 24, 289)] == [(10, "access"), (10, "access"), (1, "access"), (1, "trunk"), (20, "access")]
    assert (s2[21]["lag"], s2[22]["lag"], s2[24]["lag"]) == ("Trk1", "Trk1", "")
    assert sw2["errors"] == [] and inv["devices"]["127.0.0.1"]["errors"] == []
    assert "AVD2045K1LM" in (tmp_path / "inv-hardware.csv").read_text()
    for f in ("map.html", "map.graphml", "map.dot", "inv-devices.csv", "inv-links.csv", "inv-hosts.csv", "inv-subnets.csv", "inv-interfaces.csv", "inv-hardware.csv"):
        assert (tmp_path / f).stat().st_size > 100, f
    assert "core-rtr" in r.stdout and "dist-sw1" in r.stdout
    links = (tmp_path / "inv-links.csv").read_text()
    assert "Gi1/0/2" in links and "acc-sw2" in links
    # show/render from the saved map
    r2 = _run_cli(["show", "-m", "map.json"], cwd=tmp_path)
    assert r2.returncode == 0 and "Links (L2/L3)" in r2.stdout


def test_cli_target_subnets_without_seeds(agents, tmp_path):
    """The operator names the ranges and gives no seed: --probe-all finds the kit anyway.

    --probe-all is the ICMP-filtered case, so this also proves discovery does not depend on
    ping or on nmap being installed.
    """
    (tmp_path / "ranges.txt").write_text("# ranges from the target\n127.0.0.0/30\n127.1.0.0/30, 127.1.0.0/30\n")
    r = _run_cli(
        ["crawl", "--target-file", "ranges.txt", "--probe-all", "--sweep-max-size", "30", "--port", str(PORT),
         "-C", "lab", "--timeout", "1", "--retries", "0", "--out", "t.json", "--xlsx", "t.xlsx", "--csv", "t-", "--no-summary"],
        cwd=tmp_path,
    )
    assert r.returncode == 0, r.stderr[-3000:]
    inv = json.loads((tmp_path / "t.json").read_text())
    # 127.0.0.1 and 127.0.0.2 are inside the first target; 127.1.0.2 inside the second.
    assert set(inv["devices"]) == {"127.0.0.1", "127.0.0.2", "127.1.0.2"}
    assert all(d["discovered_via"] == "seed" for d in inv["devices"].values())
    # scope came from the targets, so the out-of-scope firewall and WAN next-hop were never probed
    assert not any(ip.startswith("192.168.") or ip.startswith("203.0.113.") for ip in inv["unreachable"])
    ipam = (tmp_path / "t-ipam.csv").read_text()
    assert "utilisation_pct" in ipam and "127.0.0.0/30" in ipam
    assert (tmp_path / "t.xlsx").stat().st_size > 5000
    # a named range that answers nothing is reported rather than silently dropped
    r2 = _run_cli(["crawl", "--target", "127.9.9.0/30", "--probe-all", "--sweep-max-size", "30", "--port", str(PORT),
                   "-C", "lab", "--timeout", "1", "--retries", "0", "--out", "empty.json", "--no-summary"], cwd=tmp_path)
    assert r2.returncode == 0 and "none replied" in r2.stderr


def test_cli_crawl_v3_fallback(agents, tmp_path):
    cfg = tmp_path / "netmap.toml"
    cfg.write_text(
        f'''
[crawl]
seeds = ["127.0.0.1"]
scope = ["127.0.0.0/8"]
max_depth = 1
timeout = 1.0
retries = 0

[[credentials]]
kind = "v2c"
community = "nope"

[[credentials]]
kind = "v3"
label = "v3-netmap"
user = "netmap"
auth = "SHA"
auth_key = "env:NETMAP_V3_AUTH"
priv = "AES"
priv_key = "privpass123"
context = "lab"
'''
    )
    env = {**os.environ, "NETMAP_ALLOW_LOOPBACK": "1", "NETMAP_V3_AUTH": "authpass123"}
    r = subprocess.run([sys.executable, "-m", "netmap", "crawl", "-c", str(cfg), "--port", str(PORT), "--out", "v3.json", "--no-summary"], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    inv = json.loads((tmp_path / "v3.json").read_text())
    assert set(inv["devices"]) == {"127.0.0.1", "127.0.0.2"}  # max_depth 1
    assert all(d["credential"] == "v3-netmap" for d in inv["devices"].values())
