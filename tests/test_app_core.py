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


def test_topology_paths(campus):
    from netmap import paths
    g = build_graph(campus)
    # switched path from the core to a floor access switch, with the port at each end
    p = paths.path_to(campus, g, "10.99.0.13")
    assert p.ok and p.nodes()[0] == p.origin
    assert p.nodes()[-1] == "10.99.0.13"
    assert any(h.out_port and h.in_port for h in p.hops)
    # path to a host ends with the access-port hop onto its switch
    hostip = next(ip for ip, h in campus.hosts.items()
                  if ip not in campus.ip_to_device and any(s.get("via") == "fdb" for s in h.seen_on))
    p2 = paths.path_to(campus, g, hostip)
    assert p2.ok and p2.hops[-1].node == hostip and p2.hops[-1].kind == "access"
    assert p2.hops[-2].node in campus.devices  # the switch it hangs off
    # routed path reconstructed from routing tables to a branch subnet behind the WAN router
    rp = paths.route_path(campus, "10.99.0.2", "10.110.0.5")
    names = [campus.devices[h.node].name for h in rp if h.node in campus.devices]
    assert "core-sw-01" in names and "rtr-wan-01" in names
    assert rp[-1].node == "172.16.100.2"  # next hop past the edge of what we polled


def test_profile_identifies_from_multiple_signals():
    from netmap.model import Host
    from netmap.profile import profile_host

    # a printer known only from its OUI and mDNS advert
    h = Host(ip="10.0.0.5", mac="00:1b:a9:11:22:33")  # Brother OUI
    h.probes = {"mdns": {"hostname": "BRW001BA9112233.local", "services": ["_ipp._tcp", "_pdl-datastream._tcp"], "model": "MFC-L2750DW"}}
    h.names = {"mdns": "BRW001BA9112233.local"}
    p = profile_host(h)
    assert p.role == "printer" and p.model == "MFC-L2750DW"
    assert any("mDNS" in e["source"] for e in p.evidence) and p.confidence in ("high", "medium")

    # a Windows box: NetBIOS + open ports agree
    w = Host(ip="10.0.0.6", ports=[{"port": 3389, "proto": "tcp", "service": "ms-wbt-server", "product": ""},
                                   {"port": 445, "proto": "tcp", "service": "microsoft-ds", "product": ""}])
    w.probes = {"netbios": {"hostname": "FINANCE-PC1", "domain": "ACME", "is_dc": False, "mac": "00:50:56:aa:bb:cc"}}
    w.names = {"netbios": "FINANCE-PC1"}
    pw = profile_host(w)
    assert pw.role == "windows" and pw.os_family == "windows" and pw.confidence == "high"

    # a domain controller
    dc = Host(ip="10.0.0.7")
    dc.probes = {"netbios": {"hostname": "DC01", "domain": "ACME", "is_dc": True}}
    dc.names = {"netbios": "DC01"}
    assert profile_host(dc).os_family == "windows" and "domain controller" in " ".join(e["implies"] for e in profile_host(dc).evidence).lower()

    # nothing but an OUI: low confidence, still names the vendor
    bare = Host(ip="10.0.0.8", mac="b8:27:eb:00:11:22")  # Raspberry Pi
    pb = profile_host(bare)
    assert pb.vendor.startswith("Raspberry") and pb.confidence in ("low", "medium")


def test_server_functions_from_ports():
    from netmap.model import Host
    from netmap.profile import profile_host, server_functions

    def mk(ports, os="", fam=""):
        h = Host(ip="10.0.0.1", os=os, os_family=fam)
        h.ports = [{"port": p, "proto": "tcp", "service": "", "product": ""} for p in ports]
        return h

    # a Linux box serving web + SSH -> webserver role, functions listed
    p = profile_host(mk([22, 80, 443], "Ubuntu 22.04", "linux"))
    assert p.role == "webserver" and "Web server" in p.functions

    # SQL Server box -> database role, product named specifically
    p = profile_host(mk([80, 443, 1433, 445, 3389], "Windows Server 2019", "windows"))
    assert p.role == "database" and "SQL Server" in p.functions

    # a plain Windows 10 desktop opens SMB+RDP but is NOT a file server, and offers
    # no real service - so it reports no server functions and stays a client role
    p = profile_host(mk([135, 139, 445, 3389, 5985], "Windows 10", "windows"))
    assert p.role == "windows" and p.functions == []

    # NFS/AFP makes a real file server (nas role already covers storage)
    assert "File server" in profile_host(mk([22, 2049, 548], "Ubuntu", "linux")).functions

    # domain controller: directory wins over the other services it runs
    p = profile_host(mk([53, 88, 389, 636, 3268, 445, 135], "Windows Server", "windows"))
    assert p.role == "dc" and "Directory (LDAP/AD)" in p.functions

    # ESXi: virtualization outranks its management web UI
    assert profile_host(mk([22, 443, 902], "VMware ESXi", "esxi")).role == "hypervisor"

    # a printer's web UI is a management surface, not a "web server" function
    p = profile_host(mk([80, 515, 631, 9100]))
    assert p.role == "printer" and p.functions == []

    # no ports -> no functions, role unchanged
    assert server_functions(Host(ip="10.0.0.2")) == []


def test_device_os_family():
    from netmap.profile import device_os_family
    from netmap.model import Device
    assert device_os_family(Device(id="1", vendor="Cisco", sysdescr="Cisco IOS-XE Software, Version 17.9")) == "ios-xe"
    assert device_os_family(Device(id="2", vendor="Fortinet", sysdescr="FortiGate-100F v7.2.8")) == "fortios"
    assert device_os_family(Device(id="3", vendor="", sysdescr="Linux host 5.15.0", role="server")) == "linux"


def test_nmap_os_and_ports_parse_and_apply():
    from netmap.sweep import _parse_nmap_xml
    from netmap.scan import _apply_nmap
    from netmap.model import Inventory, Device
    from netmap.profile import profile_host

    xml = """<nmaprun><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows Server 2019"/></port>
        <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
      </ports>
      <os><osmatch name="Microsoft Windows Server 2019" accuracy="98"><osclass osfamily="Windows" vendor="Microsoft"/></osmatch>
          <osmatch name="Microsoft Windows 10" accuracy="90"><osclass osfamily="Windows" vendor="Microsoft"/></osmatch></os>
    </host></nmaprun>"""
    recs = _parse_nmap_xml(xml)
    assert len(recs) == 1
    r = recs[0]
    assert r["os"] == "Microsoft Windows Server 2019" and r["os_accuracy"] == 98  # highest-accuracy osmatch wins
    assert r["os_family_raw"] == "Windows" and {p["port"] for p in r["ports"]} == {445, 3389}
    assert any(p["product"] == "Windows Server 2019" for p in r["ports"])

    inv = Inventory()
    _apply_nmap(inv, "10.0.0.9", r)  # unknown ip -> becomes a host
    h = inv.hosts["10.0.0.9"]
    assert {p["port"] for p in h.ports} == {445, 3389} and h.probes["nmap"]["os"] == "Microsoft Windows Server 2019"
    p = profile_host(h)
    assert p.os == "Microsoft Windows Server 2019" and p.os_family == "windows" and p.confidence == "high"

    # applied to a polled device: ports land on the device, SNMP os_version is not clobbered
    d = Device(id="10.0.0.1", vendor="Cisco", os_version="17.9.4a"); d.ips.append("10.0.0.1"); inv.add_device(d)
    _apply_nmap(inv, "10.0.0.1", {"ports": [{"port": 443, "proto": "tcp", "service": "https", "product": ""}], "os": "Linux 5.x", "os_family_raw": "Linux"})
    assert inv.devices["10.0.0.1"].ports[0]["port"] == 443 and inv.devices["10.0.0.1"].os_version == "17.9.4a"
    assert "10.0.0.1" not in inv.hosts  # a device is never downgraded to a host
