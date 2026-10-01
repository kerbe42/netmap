"""Review follow-ups in the scan pipeline: scope enforcement, SNMP walk robustness, table
decoding, device dedupe, rescan carry-over, credential hygiene and CLI input handling."""
import asyncio
import hashlib
import ipaddress as ia
import sys

import pytest
from pysnmp.proto import errind

from netmap import oids as O
from netmap.cli import build_parser, parse_target_item, read_target_file
from netmap.collect import (
    CollectOptions,
    apply_counter_deltas,
    collect_arp,
    collect_counters,
    collect_device,
    collect_fdb,
    collect_poe,
    collect_routes,
    decode_inet_cidr_index,
    fdb_id_to_vlan,
    record_truncations,
)
from netmap.crawl import CrawlConfig, Crawler, same_device, shared_real_addresses
from netmap.dns import resolve_names
from netmap.model import Device, Interface, Inventory
from netmap.snmp import Credential, SnmpError, SnmpSession
from netmap.sweep import discover_targets, sweep_addresses, sweep_subnet
from netmap.util import scope_devices, scope_hosts, scoped_networks, split_scope

from . import labnet
from .fake_snmp import FakeSession, make_prober


def nets(*items):
    return [ia.ip_network(x) for x in items]


# ---------------------------------------------------------------- 2: sweep target computation


def test_scoped_networks_cuts_out_excludes_and_scope():
    # an excluded range in the middle of a subnet leaves the two sides
    pieces = scoped_networks("10.0.0.0/24", nets("10.0.0.0/8"), nets("10.0.0.128/26"))
    assert [str(p) for p in pieces] == ["10.0.0.0/25", "10.0.0.192/26"]
    # an excluded /32 punches a hole
    pieces = scoped_networks("10.0.0.0/28", nets("10.0.0.0/8"), nets("10.0.0.5/32"))
    assert ia.ip_address("10.0.0.5") not in {a for p in pieces for a in p}
    assert sum(p.num_addresses for p in pieces) == 15
    # the subnet is clipped to the scope it overlaps
    assert [str(p) for p in scoped_networks("10.0.0.0/23", nets("10.0.1.0/24"), [])] == ["10.0.1.0/24"]
    # nothing may be touched: excluded /32 target, or a range outside the scope
    assert scoped_networks("10.0.0.5/32", nets("10.0.0.0/8"), nets("10.0.0.5/32")) == []
    assert scoped_networks("192.168.1.0/24", nets("10.0.0.0/8"), []) == []
    assert scoped_networks("10.0.0.0/24", nets("10.0.0.0/8"), nets("10.0.0.0/24")) == []
    # a wholly in-scope subnet is itself
    assert scoped_networks("10.0.0.0/24", nets("10.0.0.0/8"), nets("10.9.0.0/24")) == nets("10.0.0.0/24")


def test_sweep_addresses_for_small_prefixes():
    assert [str(a) for a in sweep_addresses("10.0.0.5/32")] == ["10.0.0.5"]
    assert [str(a) for a in sweep_addresses("10.0.0.4/31")] == ["10.0.0.4", "10.0.0.5"]
    assert [str(a) for a in sweep_addresses("10.0.0.0/30")] == ["10.0.0.1", "10.0.0.2"]


def test_sweep_subnet_hands_nmap_only_the_in_scope_pieces(monkeypatch):
    import netmap.sweep as sw

    calls = []

    async def fake_nmap(args, timeout, kind="", target=""):
        calls.append(args)
        return sw.NmapRun("<nmaprun></nmaprun>", "ok")

    monkeypatch.setattr(sw, "find_nmap", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(sw, "_run_nmap", fake_nmap)
    scope, excl = nets("10.0.0.0/8"), nets("10.0.0.128/26", "10.0.0.7/32")
    asyncio.run(sweep_subnet("10.0.0.0/24", scope=scope, exclude=excl))
    targets = [a for call in calls for a in call if "/" in a]
    assert "10.0.0.0/24" not in targets
    covered = {a for t in targets for a in ia.ip_network(t)}
    assert ia.ip_address("10.0.0.7") not in covered and ia.ip_address("10.0.0.130") not in covered
    assert ia.ip_address("10.0.0.6") in covered and ia.ip_address("10.0.0.200") in covered
    # a subnet entirely outside the rules is refused without running nmap
    calls.clear()
    assert asyncio.run(sweep_subnet("10.0.0.7/32", scope=scope, exclude=excl)) == ([], True)
    assert calls == []


def test_ping_fallback_skips_excluded_addresses(monkeypatch):
    import netmap.sweep as sw

    pinged = []

    async def fake_ping(ip, sem):
        pinged.append(ip)
        return None

    monkeypatch.setattr(sw, "find_nmap", lambda: None)
    monkeypatch.setattr(sw, "_ping", fake_ping)
    asyncio.run(sweep_subnet("10.0.0.0/28", scope=nets("10.0.0.0/8"), exclude=nets("10.0.0.5/32", "10.0.0.8/30")))
    assert "10.0.0.5" not in pinged and not any(ip.startswith("10.0.0.") and 8 <= int(ip.split(".")[-1]) <= 11 for ip in pinged)
    assert set(pinged) == {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.6", "10.0.0.7", "10.0.0.12", "10.0.0.13", "10.0.0.14"}


def test_discover_targets_refuses_excluded_single_addresses(caplog):
    inv = Inventory()
    scope = nets("10.50.0.0/24")
    # an excluded /32 target used to slip through because only wider prefixes were gated
    ips = asyncio.run(discover_targets(inv, nets("10.50.0.9/32"), scope, nets("10.50.0.9/32"), probe_all=True))
    assert ips == [] and "10.50.0.9/32" not in inv.subnets
    # an in-scope /32 and /31 are probed on the network address itself
    ips = asyncio.run(discover_targets(inv, nets("10.50.0.9/32", "10.50.0.10/31"), scope, [], probe_all=True))
    assert ips == ["10.50.0.9", "10.50.0.10", "10.50.0.11"]
    # a target outside the scope is refused
    assert asyncio.run(discover_targets(inv, nets("10.60.0.0/30"), scope, [], probe_all=True)) == []


# ---------------------------------------------------------------- 1: scan-pipeline scope filtering


def test_scope_filters_for_post_crawl_phases():
    inv = Inventory()
    inv.add_device(Device(id="10.0.0.1", ips=["10.0.0.1", "10.0.5.1"]))
    inv.add_device(Device(id="192.168.7.1", ips=["192.168.7.1"]))  # from an older, wider scan
    for ip in ("10.0.0.50", "10.0.9.9", "172.16.3.3", "10.0.5.1"):
        inv.touch_host(ip, "dhcp")
    scope, excl = nets("10.0.0.0/16"), nets("10.0.9.0/24")
    assert scope_devices(inv, scope, excl) == ["10.0.0.1"]
    # excluded, out of scope, and a device's own address are all left out
    assert scope_hosts(inv, scope, excl) == ["10.0.0.50"]
    assert split_scope(["10.0.0.50", "172.16.3.3"], scope, excl) == (["10.0.0.50"], ["172.16.3.3"])


def test_resolve_names_only_touches_the_addresses_it_is_given():
    inv = Inventory()
    inv.add_device(Device(id="10.0.0.1"))
    inv.add_device(Device(id="192.168.7.1"))
    inv.touch_host("10.0.0.50", "arp"), inv.touch_host("172.16.3.3", "dhcp")
    asked = []

    def lookup(ip):
        asked.append(ip)
        return f"host-{ip.replace('.', '-')}"

    n = asyncio.run(resolve_names(inv, lookup=lookup, hosts=["10.0.0.1", "10.0.0.50"]))
    assert n == 2 and sorted(asked) == ["10.0.0.1", "10.0.0.50"]
    assert inv.devices["10.0.0.1"].dns_name and not inv.devices["192.168.7.1"].dns_name
    assert inv.hosts["10.0.0.50"].hostname and not inv.hosts["172.16.3.3"].hostname
    # no list: everything, as before
    asked.clear()
    asyncio.run(resolve_names(inv, lookup=lookup))
    assert sorted(asked) == ["172.16.3.3", "192.168.7.1"]


# ---------------------------------------------------------------- 14: ARP rows for device addresses


def test_arp_rows_naming_a_device_address_do_not_become_hosts():
    lab = labnet.build("10")
    prober = make_prober({ip: d.values() for ip, d in lab.items()})
    inv = Inventory()
    cfg = CrawlConfig(seeds=["10.0.0.1"], credentials=[Credential(kind="v2c", community="lab", label="lab")], scope=nets("10.0.0.0/8"), workers=2)
    asyncio.run(Crawler(cfg, inv, engine=object(), prober=prober).run())
    # acc-sw2's ARP names dist-sw1's SVI 10.1.0.1, and dist-sw1's ARP names core-rtr: both were
    # already polled devices when those tables were read, so they are not hosts
    assert "10.1.0.1" not in inv.hosts and "10.0.0.1" not in inv.hosts
    assert "10.1.0.50" in inv.hosts


# ---------------------------------------------------------------- 3: walk() termination and truncation

BASE = "1.3.6.1.2.1.17.7.1.2.2.1.2"


def _session():
    sess = SnmpSession(object(), "10.0.0.9", Credential(kind="v2c", community="x", label="t"), walk_deadline=30.0)
    sess._target = object()  # never open a socket
    return sess


def _rows(*items):
    return [(f"{BASE}.{i}", i) for i in items]


def _gen_from(pdus):
    """Fake pysnmp walk generator: each PDU is (err_ind, rows) or an exception to raise."""

    async def gen():
        for pdu in pdus:
            if isinstance(pdu, Exception):
                raise pdu
            err, rows = pdu
            yield err, None, None, rows

    return gen()


def test_walk_stops_on_a_non_increasing_oid_and_records_it():
    sess = _session()
    # an agent that goes backwards would keep pysnmp (ignoreNonIncreasingOid) going for ever
    pdus = [(None, _rows(1, 2, 3)), (None, _rows(3, 4)), (None, _rows(5, 6))]
    sess._walk_gen = lambda start, lexicographic: _gen_from(pdus)
    out = asyncio.run(sess.walk(BASE))
    assert [v for _o, v in out] == [1, 2, 3]
    assert len(sess.truncations) == 1 and "non-increasing" in sess.truncations[0] and "after 3 rows" in sess.truncations[0]
    dev = Device(id="10.0.0.9")
    record_truncations(sess, dev)
    assert dev.errors == [f"DOT1Q_FDB_PORT: truncated after 3 rows (non-increasing OID)"] and sess.truncations == []


def test_walk_mid_timeout_resumes_once_then_records_truncation():
    sess = _session()
    starts = []

    def gen(start, lexicographic):
        starts.append((start, lexicographic))
        if len(starts) == 1:
            return _gen_from([(None, _rows(1, 2)), (errind.requestTimedOut, [])])
        return _gen_from([(None, _rows(3, 4)), (None, [(O.DOT1Q_FDB_STATUS + ".1", 3)])])  # resumed pass leaves the subtree

    sess._walk_gen = gen
    out = asyncio.run(sess.walk(BASE))
    # resumed from the last OID received, lexicographically, and the table came back whole
    assert starts == [(BASE, False), (f"{BASE}.2", True)]
    assert [v for _o, v in out] == [1, 2, 3, 4] and sess.truncations == []

    sess = _session()
    passes = []

    def gen2(start, lexicographic):
        passes.append(start)
        if len(passes) == 1:
            return _gen_from([(None, _rows(1, 2)), (errind.requestTimedOut, [])])
        return _gen_from([(errind.requestTimedOut, [])])  # the resumed pass times out as well

    sess._walk_gen = gen2
    out = asyncio.run(sess.walk(BASE))
    assert [v for _o, v in out] == [1, 2] and len(passes) == 2
    assert len(sess.truncations) == 1 and "timeout" in sess.truncations[0] and "after 2 rows" in sess.truncations[0]

    # an agent that answers the resumed pass with the rows it already sent is caught too
    sess = _session()
    sess._walk_gen = lambda start, lexicographic: _gen_from([(None, _rows(1, 2)), (errind.requestTimedOut, [])])
    out = asyncio.run(sess.walk(BASE))
    assert [v for _o, v in out] == [1, 2] and "non-increasing" in sess.truncations[0]

    # an error before any row is a plain failure, as before
    sess = _session()
    sess._walk_gen = lambda start, lexicographic: _gen_from([(errind.requestTimedOut, [])])
    with pytest.raises(SnmpError):
        asyncio.run(sess.walk(BASE))


def test_walk_row_cap_and_vlan_sessions_share_truncations():
    sess = _session()
    sess.max_rows = 3
    sess._walk_gen = lambda start, lexicographic: _gen_from([(None, _rows(1, 2, 3, 4, 5))])
    out = asyncio.run(sess.walk(BASE))
    assert len(out) == 3 and "row limit" in sess.truncations[0]
    assert sess.with_vlan(10).truncations is sess.truncations


def test_collect_device_surfaces_truncations_in_errors():
    class TruncatingSession(FakeSession):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.truncations = []

        async def walk(self, base):
            rows = await super().walk(base)
            if base == O.DOT1Q_FDB_PORT:
                self.truncations.append(f"{base}: truncated after {len(rows) - 1} rows (timeout)")
                return rows[:-1]
            return rows

    lab = labnet.build("10")
    dev = asyncio.run(collect_device(TruncatingSession("10.0.0.2", lab["10.0.0.2"].values()), "10.0.0.2", CollectOptions()))
    assert any(e.startswith("DOT1Q_FDB_PORT: truncated after") and e.endswith("(timeout)") for e in dev.errors)


# ---------------------------------------------------------------- 5: dot1qFdbId -> VLAN


def test_fdb_id_maps_to_vlan_through_dot1q_vlan_fdb_id():
    rows = [(f"{O.DOT1Q_VLAN_FDB_ID}.0.10", 100), (f"{O.DOT1Q_VLAN_FDB_ID}.0.20", 200)]
    assert fdb_id_to_vlan(rows) == {100: 10, 200: 20}
    t = {f"{O.DOT1D_BASE_PORT_IFINDEX}.1": 1001}
    for oid, v in rows:
        t[oid] = v
    t[f"{O.DOT1Q_FDB_PORT}.100.{labnet.mac_oid(labnet.MAC_A)}"] = 1
    t[f"{O.DOT1Q_FDB_PORT}.200.{labnet.mac_oid(labnet.MAC_B)}"] = 1
    t[f"{O.DOT1Q_FDB_PORT}.30.{labnet.mac_oid(labnet.MAC_C)}"] = 1  # no mapping row: identity fallback
    dev = Device(id="10.0.0.5")
    asyncio.run(collect_fdb(FakeSession(dev.id, t), dev, CollectOptions()))
    assert {f.mac: f.vlan for f in dev.fdb} == {labnet.MAC_A: 10, labnet.MAC_B: 20, labnet.MAC_C: 30}
    assert all(f.if_index == 1001 for f in dev.fdb)


# ---------------------------------------------------------------- 4: dedupe needs identity


def _box(ip, name, serial, extra_ips=(), vip=None):
    d = labnet.Dev()
    d.system(name, "Linux host", "1.3.6.1.4.1.8072.3.2.10", 72)
    d.entity("Server", serial)
    d.iface(1, "eth0", mac="00:11:22:33:" + ip.split(".")[-2].zfill(2) + ":" + ip.split(".")[-1].zfill(2))
    d.addr(ip, 1, "255.255.255.0")
    for n, x in enumerate(extra_ips, 2):
        d.iface(n, f"br{n}", mac=None)
        d.addr(x, n, "255.255.0.0")
    if vip:
        d.vrrp(1, 1, vip)
    return d


def _crawl(tables, seeds, scope):
    base = make_prober(tables)

    async def prober(engine, ip, creds, timeout, retries, port=161):
        await asyncio.sleep(0)  # let both seeds be probed before either is added
        return await base(engine, ip, creds, timeout, retries, port)

    inv = Inventory()
    cfg = CrawlConfig(seeds=seeds, credentials=[Credential(kind="v2c", community="lab", label="lab")], scope=nets(*scope), workers=4, follow_gateways=False)
    asyncio.run(Crawler(cfg, inv, engine=object(), prober=prober).run())
    return inv


def test_two_container_hosts_sharing_a_bridge_address_stay_separate():
    a = _box("10.9.0.1", "docker-a", "SER-A", extra_ips=["172.17.0.1"])
    b = _box("10.9.0.2", "docker-b", "SER-B", extra_ips=["172.17.0.1"])
    inv = _crawl({"10.9.0.1": a.values(), "10.9.0.2": b.values()}, ["10.9.0.1", "10.9.0.2"], ["10.9.0.0/24"])
    assert set(inv.devices) == {"10.9.0.1", "10.9.0.2"}
    assert shared_real_addresses(inv.devices["10.9.0.1"], inv.devices["10.9.0.2"]) == []


def test_fhrp_pair_sharing_a_vip_stay_separate_but_an_svi_reach_merges():
    a = _box("10.9.0.1", "gw-a", "SER-A", extra_ips=["10.9.0.254"], vip="10.9.0.254")
    b = _box("10.9.0.2", "gw-b", "SER-B", extra_ips=["10.9.0.254"], vip="10.9.0.254")
    inv = _crawl({"10.9.0.1": a.values(), "10.9.0.2": b.values()}, ["10.9.0.1", "10.9.0.2"], ["10.9.0.0/24"])
    assert set(inv.devices) == {"10.9.0.1", "10.9.0.2"}
    # the same switch reached at its SVI: same serial, same address -> one record
    c = _box("10.9.0.3", "sw-c", "SER-C", extra_ips=["10.9.1.1"])
    inv = _crawl({"10.9.0.3": c.values(), "10.9.1.1": c.values()}, ["10.9.0.3", "10.9.1.1"], ["10.9.0.0/16"])
    assert len(inv.devices) == 1 and inv.ip_to_device["10.9.1.1"] == inv.ip_to_device["10.9.0.3"]
    # two boxes with different serials sharing a real address are two records
    d = _box("10.9.0.4", "sw-d", "SER-D", extra_ips=["10.9.2.1"])
    e = _box("10.9.0.5", "sw-e", "SER-E", extra_ips=["10.9.2.1"])
    inv = _crawl({"10.9.0.4": d.values(), "10.9.0.5": e.values()}, ["10.9.0.4", "10.9.0.5"], ["10.9.0.0/16"])
    assert set(inv.devices) == {"10.9.0.4", "10.9.0.5"}


def test_same_device_verdicts():
    assert same_device(Device(id="a", serial="X"), Device(id="b", serial="X")) is True
    assert same_device(Device(id="a", serial="X"), Device(id="b", serial="Y")) is False
    assert same_device(Device(id="a", lldp_chassis_id="aa:bb"), Device(id="b", lldp_chassis_id="aa:bb")) is True
    assert same_device(Device(id="a", name="sw1", sysobjectid="1.2"), Device(id="b", name="sw1", sysobjectid="1.2")) is True
    assert same_device(Device(id="a", name="sw1", sysobjectid="1.2"), Device(id="b", name="sw1", sysobjectid="1.3")) is False
    assert same_device(Device(id="a"), Device(id="b")) is None


# ---------------------------------------------------------------- 6: replace_device carry-over


def test_replace_device_keeps_facts_a_refresh_did_not_recollect():
    inv = Inventory()
    old = Device(id="10.0.0.1", name="sw1", first_seen=100.0, ports=[{"port": 22}], os_detail="Linux 5.x", os_family="linux",
                 functions=["ssh"], mgmt={"ssh": True}, dns_name="sw1.example.test")
    inv.add_device(old)
    new = Device(id="10.0.0.1", name="sw1-renamed", os_family="ios")
    inv.replace_device(new)
    d = inv.devices["10.0.0.1"]
    assert d.name == "sw1-renamed" and d.first_seen == 100.0
    assert d.ports == [{"port": 22}] and d.os_detail == "Linux 5.x" and d.functions == ["ssh"] and d.mgmt == {"ssh": True}
    assert d.dns_name == "sw1.example.test"
    assert d.os_family == "ios"  # a value the refresh did collect wins


# ---------------------------------------------------------------- 7: credential label


def test_credential_label_says_nothing_about_the_community():
    c = Credential.from_dict({"kind": "v2c", "community": "s3cretcommunity"})
    assert "s3c" not in c.label and "***" not in c.label and c.label.startswith("v2c")
    assert Credential.from_dict({"kind": "v2c", "community": "s3cretcommunity"}).label != c.label  # numbered, not derived
    assert Credential.from_dict({"kind": "v2c"}).community == "" and Credential.from_dict({"community": None}).label
    assert Credential.from_dict({"kind": "v3", "user": "ro"}).label == "v3:ro"
    # the label reaches every device record, so this is what the review was about
    dev = Device(id="10.0.0.1", credential=c.label)
    assert "s3cret" not in dev.credential


def test_snmpv1_credential_uses_mp_model_zero():
    c = Credential.from_dict({"kind": "v1", "community": "old"})
    assert c.kind == "v1" and c.label.startswith("v1")
    assert int(c.auth_data().message_processing_model) == 0 and int(Credential(kind="v2c", community="x").auth_data().message_processing_model) == 1
    args = build_parser().parse_args(["crawl", "--seed", "10.0.0.1", "--v1-community", "old"])
    from netmap.cli import build_credentials

    assert [k.kind for k in build_credentials(args, {})] == ["v1"]


# ---------------------------------------------------------------- 8: secret identifier


@pytest.mark.skipif(sys.platform == "win32", reason="keyring path only")
def test_keyring_identifier_is_not_derived_from_the_secret(monkeypatch):
    from netmap import secret

    class FakeBackend:
        pass

    store = {}

    class FakeKeyring:
        @staticmethod
        def set_password(svc, ident, plain):
            store[(svc, ident)] = plain

        @staticmethod
        def get_password(svc, ident):
            return store.get((svc, ident))

        @staticmethod
        def get_keyring():
            return FakeBackend()

    monkeypatch.setattr(secret, "keyring", FakeKeyring)
    assert secret.available()
    t1, t2 = secret.protect("public"), secret.protect("public")
    ident = t1[len("keyring:"):]
    assert t1 != t2 and ident != hashlib.sha256(b"public").hexdigest()[:16] and len(ident) >= 16
    assert secret.unprotect(t1) == "public" and secret.unprotect(t2) == "public"
    # a null backend is no store at all
    FakeBackend.__module__ = "keyring.backends.null"
    assert secret.available() == ""
    FakeBackend.__module__ = "keyring.backends.fail"
    assert secret.available() == ""


# ---------------------------------------------------------------- 15: CLI input handling


def test_target_file_accepts_ranges(tmp_path):
    p = tmp_path / "ranges.txt"
    p.write_text("10.1.0.10-10.1.0.20\n10.2.0.10-20, 10.3.0.0/24\n10.4.0.0-10.4.0.255\n10.5.0.9-3\n")
    got = read_target_file(str(p))
    first = [ia.ip_network(x) for x in got if x.startswith("10.1.")]
    assert {a for n in first for a in n} == {ia.ip_address(f"10.1.0.{i}") for i in range(10, 21)}
    second = [ia.ip_network(x) for x in got if x.startswith("10.2.")]
    assert {a for n in second for a in n} == {ia.ip_address(f"10.2.0.{i}") for i in range(10, 21)}
    assert "10.3.0.0/24" in got and "10.4.0.0/24" in got
    assert not any(x.startswith("10.5.") for x in got)  # end before start: ignored with a warning
    assert parse_target_item("192.168.5.10") == ["192.168.5.10/32"]
    with pytest.raises(ValueError):
        parse_target_item("not-a-range")


def test_cli_explicit_zero_values_and_exit_codes(monkeypatch, tmp_path):
    import netmap.cli as cli

    seen = {}

    async def fake_run_scan(inv, req):
        seen["req"] = req
        return {}

    monkeypatch.setattr(cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_outputs", lambda inv, args: None)
    args = build_parser().parse_args(["crawl", "--target", "10.7.0.0/30", "--workers", "0", "--timeout", "0", "--out", str(tmp_path / "m.json"), "--no-summary"])
    rc = asyncio.run(cli.cmd_crawl(args))
    assert seen["req"].workers == 0 and seen["req"].timeout == 0.0  # not silently replaced by the defaults
    assert rc == 1  # targets named, nothing answered
    args = build_parser().parse_args(["crawl", "--seed", "10.7.0.1", "--out", str(tmp_path / "m.json"), "--no-summary"])
    assert asyncio.run(cli.cmd_crawl(args)) == 0  # seed-only scans keep the old contract
    # a missing map is a clear error, exit 2, not a traceback
    with pytest.raises(SystemExit) as e:
        cli.main(["show", "--map", str(tmp_path / "missing.json")])
    assert e.value.code == 2


def test_cli_warns_when_priv_key_has_no_auth_key(caplog):
    from netmap.cli import build_credentials

    args = build_parser().parse_args(["crawl", "--seed", "10.0.0.1", "--v3-user", "ro", "--v3-priv-key", "p"])
    with caplog.at_level("WARNING", logger="netmap"):
        build_credentials(args, {})
    assert any("--v3-priv-key" in r.message and "--v3-auth-key" in r.message for r in caplog.records)
    for flag in ("--community", "--v3-auth-key", "--v3-priv-key"):
        assert "env:VAR" in next(a.help for a in build_parser()._subparsers._group_actions[0].choices["crawl"]._actions if flag in a.option_strings)


# ---------------------------------------------------------------- 16: inetCidrRouteTable


def _inet_index(dest, pfx, nh, policy=(0, 0)):
    d = [int(x) for x in dest.split(".")]
    n = [int(x) for x in nh.split(".")] if nh else []
    return ".".join(str(x) for x in [1, 4, *d, pfx, len(policy), *policy, 1 if n else 0, len(n), *n])


def test_inet_cidr_index_decoding():
    assert decode_inet_cidr_index([int(x) for x in _inet_index("10.1.0.0", 24, "10.0.0.1").split(".")]) == ("10.1.0.0", 24, "10.0.0.1")
    assert decode_inet_cidr_index([int(x) for x in _inet_index("0.0.0.0", 0, "203.0.113.1").split(".")]) == ("0.0.0.0", 0, "203.0.113.1")
    # connected route: next hop type unknown(0), zero length
    assert decode_inet_cidr_index([int(x) for x in _inet_index("10.2.0.0", 24, "").split(".")]) == ("10.2.0.0", 24, "0.0.0.0")
    # IPv6 rows are skipped; malformed indexes are None rather than an exception
    v6 = [2, 16, *([0] * 16), 64, 2, 0, 0, 2, 16, *([0] * 16)]
    assert decode_inet_cidr_index(v6) is None
    assert decode_inet_cidr_index([1, 4, 10, 0]) is None and decode_inet_cidr_index([]) is None


def test_inet_cidr_route_table_is_preferred_and_falls_back():
    t = {}
    for dest, pfx, nh, idx, typ, proto in (("0.0.0.0", 0, "203.0.113.1", 2, 4, 3), ("10.1.0.0", 24, "", 10, 3, 2), ("10.2.0.0", 24, "10.0.0.2", 1, 4, 13)):
        sfx = _inet_index(dest, pfx, nh)
        t[f"{O.INET_CIDR_ROUTE_IFINDEX}.{sfx}"] = idx
        t[f"{O.INET_CIDR_ROUTE_TYPE}.{sfx}"] = typ
        t[f"{O.INET_CIDR_ROUTE_PROTO}.{sfx}"] = proto
    # an old-style table with a different route proves the new one wins
    d = labnet.Dev()
    d.cidr_route("10.99.0.0", "255.255.255.0", "10.0.0.9", 1)
    t.update(d.values())
    dev = Device(id="10.0.0.1")
    asyncio.run(collect_routes(FakeSession(dev.id, t), dev))
    routes = {r.dest: r for r in dev.routes}
    assert set(routes) == {"0.0.0.0/0", "10.1.0.0/24", "10.2.0.0/24"}
    assert routes["0.0.0.0/0"].nexthop == "203.0.113.1" and routes["0.0.0.0/0"].type == 4 and routes["0.0.0.0/0"].proto == 3
    assert routes["10.1.0.0/24"].nexthop == "0.0.0.0" and routes["10.1.0.0/24"].if_index == 10 and routes["10.2.0.0/24"].proto == 13
    # without it, the RFC 2096 table is used (the lab devices only serve that one)
    dev2 = Device(id="10.0.0.2")
    asyncio.run(collect_routes(FakeSession(dev2.id, d.values()), dev2))
    assert [r.dest for r in dev2.routes] == ["10.99.0.0/24"]


# ---------------------------------------------------------------- 9: bad mask on one row


def test_non_contiguous_mask_skips_only_that_route():
    d = labnet.Dev()
    d.cidr_route("10.1.0.0", "255.255.0.255", "10.0.0.1", 1)  # a bogus mask
    d.cidr_route("10.2.0.0", "255.255.255.0", "10.0.0.1", 1)
    dev = Device(id="10.0.0.1")
    asyncio.run(collect_routes(FakeSession(dev.id, d.values()), dev))
    assert [r.dest for r in dev.routes] == ["10.2.0.0/24"]


# ---------------------------------------------------------------- 11: ARP type, VLAN state, max_vlans note


def test_arp_keeps_only_dynamic_and_static_rows():
    d = labnet.Dev()
    d.arp(1, "10.0.0.50", labnet.MAC_A)  # dynamic(3) by the helper
    d.arp(1, "10.0.0.51", labnet.MAC_B)
    d.t[f"{O.ARP_TYPE}.1.10.0.0.51"] = (2, 2)  # invalid
    d.arp(1, "10.0.0.52", labnet.MAC_C)
    d.t[f"{O.ARP_TYPE}.1.10.0.0.52"] = (2, 4)  # static
    d.s(f"{O.ARP_PHYS}.1.10.0.0.53", labnet.mac_bytes("de:ad:be:ef:00:53"))  # no type row at all: kept
    dev = Device(id="10.0.0.1")
    asyncio.run(collect_arp(FakeSession(dev.id, d.values()), dev))
    assert {a.ip for a in dev.arp} == {"10.0.0.50", "10.0.0.52", "10.0.0.53"}


def test_cisco_per_vlan_fdb_walks_operational_vlans_and_notes_the_cap():
    d = labnet.Dev()
    d.bridge_ports({1: 1})
    for v in (10, 20, 30):
        d.vlan(v, f"V{v}")
        d.i(f"{O.VTP_VLAN_STATE}.1.{v}", 1 if v != 20 else 2)  # 20 is suspended
    d.fdb_d(labnet.MAC_A, 1)
    dev = Device(id="10.0.0.1", vendor="Cisco", vlans={10: "V10", 20: "V20", 30: "V30"})
    sess = FakeSession(dev.id, d.values())
    vlans_seen = []
    orig = sess.with_vlan

    def with_vlan(v):
        vlans_seen.append(v)
        return orig(v)

    sess.with_vlan = with_vlan
    asyncio.run(collect_fdb(sess, dev, CollectOptions(cisco_vlan_fdb=True, max_vlans=1)))
    assert vlans_seen == [10]  # only operational VLANs, cut at max_vlans
    assert any("max_vlans" in e and "1 of 2" in e for e in dev.errors)


# ---------------------------------------------------------------- 12: PoE ports on a stack


def test_poe_ports_match_stack_member_and_port_before_ifindex():
    d = labnet.Dev()
    d.poe_main(740, 60)
    d.poe_port(3, status=3, cls=4, milliwatts=15000, group=1)
    d.poe_port(3, status=2, cls=0, group=2)
    dev = Device(id="10.0.0.1")
    # ifIndex 3 is a member of stack 2 - the old ifIndex-first mapping put group 1's power on it
    dev.interfaces = [Interface(index=1, name="Gi1/0/3"), Interface(index=3, name="Gi2/0/3"), Interface(index=7, name="Gi1/0/7")]
    asyncio.run(collect_poe(FakeSession(dev.id, d.values()), dev))
    assert (dev.iface(1).poe_status, dev.iface(1).poe_watts) == ("delivering", 15.0)
    assert (dev.iface(3).poe_status, dev.iface(3).poe_watts) == ("searching", 0.0)
    assert dev.iface(7).poe_status == ""
    # a flat switch with plain numbered ports still maps by port number
    d2 = labnet.Dev()
    d2.poe_port(24, status=3, cls=3, group=1)
    dev2 = Device(id="10.0.0.2")
    dev2.interfaces = [Interface(index=124, name="24"), Interface(index=24, name="VLAN24")]
    asyncio.run(collect_poe(FakeSession(dev2.id, d2.values()), dev2))
    assert dev2.iface(124).poe_status == "delivering" and dev2.iface(24).poe_status == ""


# ---------------------------------------------------------------- 13: wrap recovery only for 32-bit counters


def test_wrap_recovery_applies_to_32_bit_counters_only():
    d = labnet.Dev()
    d.counters(1, in_oct=1000)  # HC counters
    d.i(f"{O.IF_IN_OCTETS}.2", 1000)  # 32-bit only
    d.i(f"{O.IF_HC_IN_OCTETS}.2", 1000)  # (the table has to be complete for the fake, so index 2 gets both)
    dev = Device(id="10.0.0.1")
    dev.interfaces = [Interface(index=1, speed_mbps=1000), Interface(index=2, speed_mbps=1000)]
    asyncio.run(collect_counters(FakeSession(dev.id, d.values()), dev))
    assert ("in", 1) in dev._hc_counters
    old = Device(id="10.0.0.1")
    old.interfaces = [Interface(index=1, speed_mbps=1000, in_octets=(1 << 32) - 1_000_000, counters_at=1000.0),
                      Interface(index=2, speed_mbps=1000, in_octets=(1 << 32) - 1_000_000, counters_at=1000.0)]
    new = Device(id="10.0.0.1")
    new.interfaces = [Interface(index=1, speed_mbps=1000, in_octets=250_000, counters_at=1010.0),
                      Interface(index=2, speed_mbps=1000, in_octets=250_000, counters_at=1010.0)]
    new._hc_counters = {("in", 1)}  # only ifIndex 1 came from ifHCInOctets
    apply_counter_deltas(old, new)
    # 64-bit went backwards: a reset, not a wrap -> no utilisation figure
    assert new.interfaces[0].in_util_pct == 0.0
    # 32-bit: one wrap recovered -> 1.25 MB in 10 s = 1 Mbit/s = 0.1% of a gigabit link
    assert new.interfaces[1].in_util_pct == 0.1
    # loaded from disk (no marker): a value at or above 2^32 says 64-bit
    old.interfaces[0].in_octets, new.interfaces[0].in_octets = (1 << 33), 1
    del new._hc_counters
    new.interfaces[0].in_util_pct = 0.0
    apply_counter_deltas(old, new)
    assert new.interfaces[0].in_util_pct == 0.0


# ---------------------------------------------------------------- 10: LLDP local port by subtype / bridge port


def test_lldp_local_port_mac_subtype_and_bridge_port_mapping():
    from netmap.collect import collect_lldp

    d = labnet.Dev()
    d.iface(1001, "ge-0/0/1", mac="00:11:22:33:44:01")
    d.iface(1002, "ge-0/0/2", mac="00:11:22:33:44:02")
    d.i(O.LLDP_LOC_CHASSIS_SUBTYPE, 4), d.s(O.LLDP_LOC_CHASSIS_ID, labnet.mac_bytes("00:11:22:33:44:00"))
    # local port 5 identifies itself by MAC (subtype 3); local port 6 has an opaque id and is a bridge port
    d.i(f"{O.LLDP_LOC_PORT_ID_SUBTYPE}.5", 3), d.s(f"{O.LLDP_LOC_PORT_ID}.5", labnet.mac_bytes("00:11:22:33:44:01"))
    d.i(f"{O.LLDP_LOC_PORT_ID_SUBTYPE}.6", 7), d.s(f"{O.LLDP_LOC_PORT_ID}.6", "6")
    d.lldp_rem(5, 1, labnet.MAC_A, "p1", "", "peer-a", "x", 0x04)
    d.lldp_rem(6, 2, labnet.MAC_B, "p2", "", "peer-b", "x", 0x04)
    dev = Device(id="10.0.0.1")
    asyncio.run(__import__("netmap.collect", fromlist=["collect_interfaces"]).collect_interfaces(FakeSession(dev.id, d.values()), dev))
    asyncio.run(collect_lldp(FakeSession(dev.id, d.values()), dev, bp={"6": 1002}))
    by = {n.remote_name: n for n in dev.neighbors}
    assert by["peer-a"].local_if_index == 1001 and by["peer-a"].local_port == "ge-0/0/1"
    assert by["peer-b"].local_if_index == 1002 and by["peer-b"].local_port == "ge-0/0/2"
