import asyncio
import ipaddress
import json
import os
import tempfile

import pytest

from netmap.crawl import CrawlConfig, Crawler
from netmap.graph import build_graph, export_csv, export_dot, export_graphml, text_summary
from netmap.model import Inventory
from netmap.render import render_html
from netmap.snmp import Credential
from netmap.util import mask_to_prefix, oid_suffix, short_name

from . import labnet
from .fake_snmp import make_prober


def crawl(base="10", **kw):
    lab = labnet.build(base)
    tables = {ip: d.values() for ip, d in lab.items()}
    prober = make_prober(tables)
    cfg = CrawlConfig(seeds=[f"{base}.0.0.1"], credentials=[Credential(kind="v2c", community="lab", label="lab")], scope=[ipaddress.ip_network(f"{base}.0.0.0/8")], workers=4, **kw)
    inv = Inventory()
    c = Crawler(cfg, inv, engine=object(), prober=prober)
    asyncio.run(c.run())
    return inv, prober, lab


def test_util():
    assert oid_suffix("1.2.3.4.5", "1.2.3") == [4, 5]
    assert oid_suffix("1.2.30.4", "1.2.3") == []
    assert mask_to_prefix("255.255.255.0") == 24
    assert short_name("dist-sw1.example.test") == "dist-sw1"
    assert short_name("core-rtr.example.test(FDO123)") == "core-rtr"


def test_crawl_finds_all_devices_and_links():
    inv, prober, lab = crawl()
    assert set(inv.devices) == {"10.0.0.1", "10.0.0.2", "10.1.0.2"}
    r1, sw1, sw2 = inv.devices["10.0.0.1"], inv.devices["10.0.0.2"], inv.devices["10.1.0.2"]
    assert (r1.name, r1.vendor, r1.role, r1.model, r1.serial) == ("core-rtr", "Cisco", "router", "ISR4331/K9", "FDO2222R1XX")
    assert (sw1.role, sw2.role, sw2.vendor) == ("l3switch", "switch", "HP")
    assert sw1.depth == 1 and sw2.depth == 2
    # SW1 reached by CDP mgmt address from R1; SW2 by LLDP mgmt address from SW1
    assert sw1.discovered_via.startswith("cdp:") and sw2.discovered_via.startswith("lldp:")
    # the same box reached via its SVI address is deduped, not re-collected
    assert inv.ip_to_device["10.1.0.1"] == "10.0.0.2"
    assert "10.1.0.1" not in inv.devices
    # out-of-scope neighbour and WAN next-hop were never probed
    assert "192.168.99.2" not in prober.probed and "192.168.99.7" not in inv.hosts and "203.0.113.1" not in prober.probed
    # interface details
    gi1 = sw1.iface(1)
    assert gi1.name == "Gi1/0/1" and gi1.alias == "uplink core-rtr" and gi1.speed_mbps == 1000 and "10.0.0.2/30" in gi1.ips
    assert sw1.vlans == {10: "USERS", 20: "SERVERS", 30: "BRANCH"}
    # neighbours parsed
    lldp = {n.remote_name: n for n in sw1.neighbors if n.proto == "lldp"}
    assert lldp["acc-sw2"].remote_mgmt_ips == ["10.1.0.2"] and lldp["acc-sw2"].local_port == "Gi1/0/2" and lldp["acc-sw2"].local_if_index == 2
    assert lldp["ap-lobby"].remote_chassis_id == labnet.MAC_AP and lldp["ap-lobby"].remote_caps == "wlan-ap"
    cdp = [n for n in sw1.neighbors if n.proto == "cdp"][0]
    assert cdp.remote_mgmt_ips == ["10.0.0.1"] and cdp.local_port == "Gi1/0/1" and cdp.remote_port == "GigabitEthernet0/0/0"
    # routes / arp / fdb
    assert any(r.dest == "0.0.0.0/0" and r.nexthop == "10.0.0.1" for r in sw1.routes)
    assert any(r.dest == "10.1.0.0/24" and r.nexthop == "10.0.0.2" for r in r1.routes)
    assert {a.ip for a in sw1.arp} >= {"10.1.0.50", "10.1.0.51", "10.2.0.10", "10.1.0.60"}
    assert any(f.mac == labnet.MAC_C and f.if_index == 5 and f.vlan == 20 for f in sw1.fdb)
    assert any(f.mac == labnet.MAC_A and f.if_index == 3 and f.vlan is None for f in sw2.fdb)
    # hosts from ARP; the phone was LLDP-announced with a mgmt IP that does not speak SNMP
    assert "10.1.0.50" in inv.hosts and inv.hosts["10.1.0.50"].mac == labnet.MAC_A
    assert inv.hosts["10.1.0.90"].snmp_failed is True
    # subnets: three in scope plus the out-of-scope one recorded from the SVI (not crawled)
    assert {"10.0.0.0/30", "10.1.0.0/24", "10.2.0.0/24"} <= set(inv.subnets)
    assert not sw1.errors and not sw2.errors and not r1.errors


def test_graph_edges_and_exports(tmp_path):
    inv, _, _ = crawl()
    g = build_graph(inv)
    kinds = {}
    for u, v, a in g.edges(data=True):
        kinds.setdefault(a["kind"], []).append((u, v, a))
    l2 = {tuple(sorted((u, v))) for u, v, _ in kinds["cdp"] + kinds["lldp"]}
    assert ("10.0.0.1", "10.0.0.2") in l2  # R1 - SW1 via CDP (deduped both directions)
    assert ("10.0.0.2", "10.1.0.2") in l2  # SW1 - SW2 via LLDP
    assert ("10.0.0.2", "10.1.0.60") in l2  # SW1 - AP resolved to the ARP host by chassis MAC
    assert ("10.1.0.2", "10.1.0.90") in l2  # SW2 - phone resolved by LLDP mgmt IP
    assert g.nodes["10.1.0.60"]["role"] == "wireless" and g.nodes["10.1.0.60"]["label"] == "ap-lobby"
    assert g.nodes["10.1.0.90"]["role"] == "phone"
    assert "stub:branch-fw" in g and g.nodes["stub:branch-fw"]["role"] == "unpolled"
    # exactly one R1-SW1 edge: L3 edge suppressed when an L2 link exists
    assert sum(1 for _ in g.subgraph(["10.0.0.1", "10.0.0.2"]).edges) == 1
    # FDB host placement: A and B on SW2 ports 3/4, C on SW1 Gi1/0/5, nothing on uplinks
    fdb = {(u, v): a for u, v, a in kinds["fdb"]}
    assert fdb[("10.1.0.2", "10.1.0.50")]["port"] == "3" and fdb[("10.1.0.2", "10.1.0.51")]["port"] == "4"
    assert fdb[("10.0.0.2", "10.2.0.10")]["port"] == "Gi1/0/5" and fdb[("10.0.0.2", "10.2.0.10")]["vlan"] == 20
    assert not any(a["port"] in ("24", "Gi1/0/2") for a in fdb.values())
    # subnet membership
    assert g.has_edge("10.0.0.2", "10.1.0.0/24") and g.has_edge("10.1.0.50", "10.1.0.0/24")
    # exports
    p = tmp_path / "m"
    render_html(g, str(p) + ".html"), export_graphml(g, str(p) + ".graphml"), export_dot(g, str(p) + ".dot")
    files = export_csv(inv, g, str(p) + "-")
    assert (p.parent / "m.html").stat().st_size > 5000 and len(files) == 5
    assert "acc-sw2" in (p.parent / "m-hosts.csv").read_text()  # host A placed on acc-sw2
    txt = text_summary(inv, g)
    assert "core-rtr" in txt and "branch-fw" in txt
    # round-trip persistence
    inv.save(str(p) + ".json")
    inv2 = Inventory.load(str(p) + ".json")
    assert set(inv2.devices) == set(inv.devices) and inv2.devices["10.0.0.2"].vlans == inv.devices["10.0.0.2"].vlans
    assert len(build_graph(inv2).edges) == len(g.edges)


def test_max_depth_and_resume(tmp_path):
    inv, prober, _ = crawl(max_depth=1)
    assert set(inv.devices) == {"10.0.0.1", "10.0.0.2"}  # SW2 is depth 2
    out = tmp_path / "map.json"
    inv.save(str(out))
    # resume with deeper limit: already-collected devices are not re-probed
    lab = labnet.build("10")
    prober2 = make_prober({ip: d.values() for ip, d in lab.items()})
    cfg = CrawlConfig(seeds=["10.0.0.1"], credentials=[Credential(kind="v2c", community="lab")], scope=[ipaddress.ip_network("10.0.0.0/8")], max_depth=5)
    inv2 = Inventory.load(str(out))
    asyncio.run(Crawler(cfg, inv2, engine=object(), prober=prober2).run())
    assert "10.0.0.1" not in prober2.probed
    # SW2 is reachable on resume because the unmatched-neighbour pass re-enqueues LLDP mgmt IPs
    assert "10.1.0.2" in inv2.devices
