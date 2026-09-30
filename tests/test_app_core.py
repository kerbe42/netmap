"""The pieces the desktop app is built on, tested without a GUI: layouts, diagrams, diffs,
rescans, findings and the sample network."""
import asyncio
import ipaddress
import xml.etree.ElementTree as ET

import pytest

from netmap import diagram, layout
from netmap.crawl import CrawlConfig, Crawler
from netmap.diff import compare
from netmap.graph import build_graph
from netmap.model import Device, Inventory
from netmap.scan import ScanRequest, resolve_scope, run_scan
from netmap.snmp import Credential
from netmap.views import PAGES, Snapshot, finding_rows, link_rows, short_port

from . import demonet, labnet
from .fake_snmp import make_prober
from .test_crawl import crawl


@pytest.fixture(scope="module")
def campus():
    return demonet.build_project()


def test_sample_network_is_inventoried(campus):
    inv = campus
    assert len(inv.devices) == 11
    roles = {d.name: d.role for d in inv.devices.values()}
    assert roles["core-sw-01"] == "l3switch" and roles["fw-edge-01"] == "firewall" and roles["rtr-wan-01"] == "router"
    # access switches say "routing" in sysServices but only have a management SVI: layer 2
    assert roles["acc-fl2-01"] == "switch" and roles["wh-sw-01"] == "switch"
    g = build_graph(inv)
    # APs announced over LLDP are typed from their capabilities, not their (HPE) MAC vendor
    aps = [n for n, a in g.nodes(data=True) if a.get("kind") == "host" and a.get("role") == "wireless"]
    assert len(aps) == 8
    assert inv.hosts[aps[0]].role == "wireless"  # and the inventory agrees, so exports do too
    # PTR names came through reverse DNS
    assert inv.devices["10.99.0.2"].dns_name == "core-sw-01.mgmt.northwind.example"
    assert sum(1 for h in inv.hosts.values() if h.hostname) > 250
    # the stack's members, supplies and optics are in the asset register
    acc = next(d for d in inv.devices.values() if d.name == "acc-fl1-01")
    assert sum(1 for c in acc.components if c.cls == "chassis") == 2 and any(c.model == "SFP-10G-LR" for c in acc.components)


def test_findings_on_sample(campus):
    s = Snapshot(campus)
    cats = {}
    for f in finding_rows(s):
        cats.setdefault(f["category"], []).append(f)
    assert {f["item"] for f in cats["Neighbour not polled"]} >= {"rtr-branch-leeds", "GS724T-basement"}
    mismatch = cats["Link speed mismatch"]
    assert len(mismatch) == 1 and "acc-fl3-01" in mismatch[0]["item"]
    assert cats["VLAN named differently"][0]["item"] == "VLAN 20"
    # the Links page lists network links, not every phone's LLDP announcement
    rows = link_rows(s)
    assert 20 <= len(rows) <= 40 and all("SEP" not in r["b"] for r in rows)
    assert s.endpoint_links > 50
    # every page builds
    for key, (cols, fn) in PAGES.items():
        out = fn(s)
        assert isinstance(out, list), key


def test_views_ports_are_oriented_and_short():
    assert short_port("GigabitEthernet1/0/2") == "Gi1/0/2" and short_port("TenGigabitEthernet1/1/1") == "Te1/1/1"
    assert short_port("Ethernet1/49") == "Eth1/49" and short_port("port1") == "port1"
    inv, _, _ = crawl()
    rows = {(r["a"], r["b"]): r for r in link_rows(Snapshot(inv))}
    r = rows[("dist-sw1", "acc-sw2")]
    assert r["a_port"] == "Gi1/0/2" and r["b_port"] == "24"


def test_layered_layout_puts_the_core_on_top(campus):
    g = build_graph(campus)
    flags = {k: v for k, v in diagram.PRESETS["physical"].items() if k != "title"}
    nodes, edges = diagram.select(g, flags, "physical")
    pos = layout.layered(nodes, [(u, v) for u, v, _ in edges])
    y = {campus.devices[n].name: pos[n][1] for n in nodes if n in campus.devices}
    assert y["fw-edge-01"] < y["core-sw-01"] < y["acc-fl1-01"]
    assert y["core-sw-01"] == y["core-sw-02"]
    assert len({(round(x), round(yy)) for x, yy in pos.values()}) == len(pos)  # no two nodes on the same spot
    # with hosts, a switch's endpoints are packed in a block under it rather than one long row
    flags["hosts"] = True
    nodes, edges = diagram.select(g, flags, "physical")
    pos = layout.layered(nodes, [(u, v) for u, v, _ in edges])
    xs = [x for x, _ in pos.values()]
    assert max(xs) - min(xs) < 40 * 104 * 2
    org = layout.organic(nodes, [(u, v) for u, v, _ in edges], init=pos, iterations=20)
    rad = layout.radial(nodes, [(u, v) for u, v, _ in edges], "10.99.0.2")
    assert set(org) == set(nodes) == set(rad)


def test_logical_view_hides_plain_switches(campus):
    g = build_graph(campus)
    flags = {k: v for k, v in diagram.PRESETS["logical"].items() if k != "title"}
    nodes, _ = diagram.select(g, flags, "logical")
    roles = {a.get("role") for a in nodes.values() if a.get("kind") == "device"}
    assert "switch" not in roles and {"l3switch", "firewall", "router"} <= roles
    assert any(a.get("vlan_name") == "USERS" for a in nodes.values() if a.get("kind") == "subnet")


def test_saved_positions_win_and_new_nodes_land_near_neighbours():
    nodes = {n: {"kind": "device", "role": "switch", "label": n} for n in "abcd"}
    edges = [("a", "b", {}), ("b", "c", {}), ("c", "d", {})]
    auto = diagram.positions(nodes, edges)
    saved = {"a": [1000.0, 1000.0], "b": [1200.0, 1000.0], "c": [1400.0, 1000.0]}
    pos = diagram.positions(nodes, edges, saved)
    assert pos["a"] == (1000.0, 1000.0)
    # d had no saved position: it keeps its layout offset from c, its neighbour
    assert pos["d"] == (1400.0 + auto["d"][0] - auto["c"][0], 1000.0 + auto["d"][1] - auto["c"][1])


def test_drawio_export(campus, tmp_path):
    g = build_graph(campus)
    campus.layout["physical"] = {"10.99.0.2": [5000.0, 5000.0]}
    p = diagram.export_drawio(campus, g, str(tmp_path / "net.drawio"))
    root = ET.parse(p).getroot()
    pages = root.findall("diagram")
    assert [d.get("name") for d in pages] == ["Physical (cabling)", "Logical (routing & subnets)"]
    objs = pages[0].findall("mxGraphModel/root/UserObject")
    core = next(o for o in objs if o.get("netmap_id") == "10.99.0.2")
    geo = core.find("mxCell/mxGeometry")
    assert float(geo.get("x")) == pytest.approx(5000 - 25)  # the saved hand-placed position was used
    assert '<font style="font-size:9px"' in core.get("label")  # HTML label, escaped once
    assert "prIcon=l3_switch" in core.find("mxCell").get("style")
    labels = [c.get("value") for c in pages[0].iter("mxCell") if c.get("value")]
    assert "Twe1/0/1" in labels or "Te1/1/1" in labels  # port names at the link ends
    del campus.layout["physical"]


def test_diff_detects_changes(campus):
    old = campus.copy()
    new = campus.copy()
    d = new.devices["10.99.0.13"]
    d.os_version = "17.12.1"
    d.serial = "CHANGED1"
    new.remove_device("10.99.0.32")
    moved = new.devices.pop("10.99.0.31")
    moved.id = "10.99.0.131"
    moved.ips = ["10.99.0.131"]
    new.add_device(moved)
    new.touch_host("10.10.3.200", "arp", "00:50:56:01:02:03")
    diff = compare(old, new)
    kinds = {(c.kind, c.change, c.item) for c in diff.changes}
    assert ("device", "changed", "10.99.0.13") in kinds
    assert ("device", "removed", "10.99.0.32") in kinds
    assert ("device", "moved", "10.99.0.131") in kinds
    assert ("host", "added", "10.10.3.200") in kinds
    assert "OS version: 17.6.5 → 17.12.1" in next(c.detail for c in diff.changes if c.item == "10.99.0.13")
    assert compare(old, old.copy()).changes == []


def test_rescan_refreshes_known_devices_and_keeps_notes(tmp_path):
    inv, _, _ = crawl()
    inv.annotate("10.0.0.2", notes="closet B", site="HQ")
    before = inv.devices["10.0.0.2"].collected_at
    first = inv.devices["10.0.0.2"].first_seen
    lab = labnet.build("10")
    prober = make_prober({ip: d.values() for ip, d in lab.items()})
    req = ScanRequest(seeds=["10.1.0.1"], scope=["10.0.0.0/8"], credentials=[Credential(kind="v2c", community="lab", label="lab")],
                      refresh=True, refresh_ids=["10.0.0.2"], max_depth=0, save_path=str(tmp_path / "p.netmap"))
    rec = asyncio.run(run_scan(inv, req, engine=object(), prober=prober))
    # reached through its SVI address, polled at its management address, replaced in place
    assert prober.probed == ["10.0.0.2"]
    assert rec["found"]["refreshed"] == 1 and rec["found"]["new_devices"] == []
    d = inv.devices["10.0.0.2"]
    assert d.collected_at >= before and d.first_seen == first and d.depth == 1
    assert inv.note("10.0.0.2")["notes"] == "closet B"
    assert Inventory.load(str(tmp_path / "p.netmap")).history[-1]["request"]["credentials"] == ["lab"]
    # a device that went quiet keeps its data and says so
    prober2 = make_prober({})
    asyncio.run(run_scan(inv, ScanRequest(seeds=["10.0.0.2"], scope=["10.0.0.0/8"], credentials=[Credential(kind="v2c", community="x")],
                                          refresh=True, max_depth=0), engine=object(), prober=prober2))
    assert "10.0.0.2" in inv.devices and "no answer on rescan" in inv.devices["10.0.0.2"].errors


def test_scan_can_be_cancelled_and_keeps_results():
    lab = labnet.build("10")
    tables = {ip: d.values() for ip, d in lab.items()}
    base = make_prober(tables)

    async def slow(engine, ip, creds, timeout, retries, port=161):
        await asyncio.sleep(0.2)
        return await base(engine, ip, creds, timeout, retries, port)

    inv = Inventory()
    req = ScanRequest(seeds=["10.0.0.1"], scope=["10.0.0.0/8"], credentials=[Credential(kind="v2c", community="lab")], workers=1)

    async def go():
        t = asyncio.ensure_future(run_scan(inv, req, engine=object(), prober=slow))
        await asyncio.sleep(0.35)
        t.cancel()
        return await t

    rec = asyncio.run(go())
    assert rec["cancelled"] is True and 1 <= len(inv.devices) < 3
    assert inv.history[-1] is rec


def test_project_file_round_trip_and_forward_compat(tmp_path):
    inv, _, _ = crawl()
    inv.annotate("10.0.0.1", name="Core router", tags=["core", "wan"], status="Verified")
    inv.layout["physical"] = {"10.0.0.1": [1.0, 2.0]}
    inv.project = {"name": "Acme", "scan": {"targets": ["10.0.0.0/8"]}}
    p = tmp_path / "a.netmap"
    inv.save(str(p))
    back = Inventory.load(str(p))
    assert back.note("10.0.0.1")["tags"] == ["core", "wan"] and back.layout["physical"]["10.0.0.1"] == [1.0, 2.0]
    assert back.project["name"] == "Acme" and back.display_name("10.0.0.1") == "Core router"
    # a file written by a newer version with fields we do not know still opens
    import json

    d = json.loads(p.read_text())
    d["devices"]["10.0.0.1"]["some_future_field"] = 1
    d["devices"]["10.0.0.1"]["interfaces"][0]["another"] = "x"
    d["hosts"][next(iter(d["hosts"]))]["new_host_thing"] = True
    p.write_text(json.dumps(d))
    assert Inventory.load(str(p)).devices["10.0.0.1"].name == "core-rtr"
    # annotate() drops empty values and empty records
    back.annotate("10.0.0.1", name="", tags=[], status="")
    assert "10.0.0.1" not in back.annotations


def test_subnet_lookup_is_longest_prefix():
    inv = Inventory()
    for c in ("10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "192.168.0.0/24"):
        inv.add_subnet(c, "test")
    assert inv.subnet_for_ip("10.1.2.3") == "10.1.2.0/24"
    assert inv.subnet_for_ip("10.1.9.9") == "10.1.0.0/16"
    assert inv.subnet_for_ip("10.200.0.1") == "10.0.0.0/8"
    assert inv.subnet_for_ip("172.16.0.1") is None and inv.subnet_for_ip("junk") is None
    inv.add_subnet("10.1.2.128/25", "test")  # the index notices new subnets
    assert inv.subnet_for_ip("10.1.2.200") == "10.1.2.128/25"


def test_resolve_scope():
    scope, exclude = resolve_scope(["10.1.0.0/24"], [], ["10.1.0.128/25"])
    assert [str(s) for s in scope] == ["10.1.0.0/24"] and [str(e) for e in exclude] == ["10.1.0.128/25"]
    scope, _ = resolve_scope([], [], [])
    assert {str(s) for s in scope} == {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}


def test_asset_list_check(campus, tmp_path):
    from netmap.reconcile import guess_columns, read_table, reconcile, write_csv

    p = tmp_path / "assets.csv"
    p.write_text(
        "Acme network assets (from the previous team)\n"
        "Hostname;Mgmt IP;Serial Number;Model;Location\n"
        "core-sw-01;10.99.0.2;FDO25330QX1;C9500-24Y4C;Comms A\n"   # wrong serial on the list
        "core-sw-02;10.99.0.3;FDO25331QX;C9500-24Y4C;Comms A\n"    # hm, serial differs too (list typo)
        "fw-edge-01;10.0.0.1;FG100FTK21009876;FG-100F;Comms A\n"   # exact
        "old-core;10.99.0.9;FOX0000;WS-C3750X;Basement\n"          # gone
        "wh-sw-01;;SG91KHM000;;Warehouse\n",                        # by name, the serial is wrong
        encoding="utf-8",
    )
    headers, rows = read_table(str(p))
    cols = guess_columns(headers)
    assert set(cols) == {"name", "ip", "serial", "model", "site"} and len(rows) == 5
    rec = reconcile(campus, rows, cols)
    by = {m.listed.get("name"): m for m in rec.matches}
    assert by["fw-edge-01"].node == "10.0.0.1" and not by["fw-edge-01"].differences
    assert by["old-core"].node == "" and by["old-core"] in rec.missing
    assert by["core-sw-01"].how == "address" and any(d.startswith("serial:") for d in by["core-sw-01"].differences)
    assert by["wh-sw-01"].how == "name" and by["wh-sw-01"].node == "10.99.0.31"
    assert "10.99.0.11" in rec.unlisted and "10.0.0.1" not in rec.unlisted
    out = write_csv(campus, rec, str(tmp_path / "check.csv"))
    text = open(out, encoding="utf-8-sig").read()
    assert "not found" in text and "not in list" in text
    # the same from an Excel file
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.append(["Device Name", "IP Address", "S/N"])
    ws.append(["fw-edge-01", "10.0.0.1", "FG100FTK21009876"])
    wb.save(tmp_path / "assets.xlsx")
    h2, r2 = read_table(str(tmp_path / "assets.xlsx"))
    rec2 = reconcile(campus, r2, guess_columns(h2))
    assert len(rec2.found) == 1


def test_bogus_and_shared_macs_are_dropped():
    from netmap.util import plausible_mac
    from netmap.graph import enrich_inventory

    assert not plausible_mac("12:34:56:78:9a:bc")   # nmap-on-Windows placeholder
    assert not plausible_mac("ff:ff:ff:ff:ff:ff") and not plausible_mac("00:00:00:00:00:00")
    assert not plausible_mac("01:00:5e:00:00:01")   # multicast bit set
    assert not plausible_mac("aa:aa:aa:aa:aa:aa")
    assert plausible_mac("00:50:56:ab:cd:ef")       # real VMware unicast
    assert plausible_mac("a4:83:e7:11:22:33")       # real Apple, randomised-looking but fine

    inv = Inventory()
    # the same placeholder handed to five swept hosts, as nmap does across a router/VPN
    for i in range(5):
        inv.touch_host(f"10.9.0.{10 + i}", "sweep", "12:34:56:78:9a:bc")
    # a genuinely shared uplink MAC that belongs to a polled device must be kept
    d = Device(id="10.9.0.1", name="rtr", vendor="Cisco")
    d.macs.append("00:11:22:aa:bb:cc")
    d.ips.append("10.9.0.1")
    inv.add_device(d)
    for i in range(4):
        inv.touch_host(f"10.9.9.{10 + i}", "arp", "00:11:22:aa:bb:cc")
    enrich_inventory(inv)
    assert all(inv.hosts[f"10.9.0.{10 + i}"].mac is None for i in range(5))       # bogus, dropped
    assert all(inv.hosts[f"10.9.9.{10 + i}"].mac == "00:11:22:aa:bb:cc" for i in range(4))  # real device MAC, kept
