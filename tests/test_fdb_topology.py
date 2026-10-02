"""Inferring switch-to-switch links from MAC forwarding tables when LLDP/CDP is silent."""
from subnetsleuth.graph import _infer_fdb_links, build_graph
from subnetsleuth.model import Device, FdbEntry, Interface, Inventory

# three switches cabled in a line A - B - C, each with one MAC, no LLDP/CDP at all.
MAC = {"A": "00:00:00:00:00:0a", "B": "00:00:00:00:00:0b", "C": "00:00:00:00:00:0c"}


def _switch(id_, mac, fdb_ports):
    """fdb_ports: {if_index: [device MACs learned on that port]}."""
    d = Device(id=id_, role="switch", macs=[mac], services=2,
               interfaces=[Interface(index=i, name=f"Gi0/{i}", type=6) for i in (1, 2)])
    for ifidx, macs in fdb_ports.items():
        for m in macs:
            d.fdb.append(FdbEntry(mac=m, if_index=ifidx))
    return d


def _line_inventory():
    inv = Inventory()
    # A: B and C are both reached out port 1 (toward B)
    inv.add_device(_switch("10.0.0.1", MAC["A"], {1: [MAC["B"], MAC["C"]]}))
    # B: A out port 1 (toward A), C out port 2 (toward C)
    inv.add_device(_switch("10.0.0.2", MAC["B"], {1: [MAC["A"]], 2: [MAC["C"]]}))
    # C: A and B both reached out port 1 (toward B)
    inv.add_device(_switch("10.0.0.3", MAC["C"], {1: [MAC["A"], MAC["B"]]}))
    inv.reindex()
    return inv


def test_infers_the_chain_not_the_shortcut():
    inv = _line_inventory()
    g = build_graph(inv, include_hosts=False, include_subnets=False)
    fdb_edges = {frozenset((u, v)) for u, v, a in g.edges(data=True) if a.get("kind") == "fdb-link"}
    assert frozenset(("10.0.0.1", "10.0.0.2")) in fdb_edges  # A-B
    assert frozenset(("10.0.0.2", "10.0.0.3")) in fdb_edges  # B-C
    # A-C must NOT be a direct link: B is learned beyond both their facing ports
    assert frozenset(("10.0.0.1", "10.0.0.3")) not in fdb_edges


def test_does_not_duplicate_an_lldp_linked_pair():
    from subnetsleuth.model import Neighbor
    inv = _line_inventory()
    # give A a real LLDP neighbour to B; the FDB inference must not add a parallel A-B link
    inv.devices["10.0.0.1"].neighbors.append(
        Neighbor(proto="lldp", local_port="Gi0/1", remote_port="Gi0/1",
                 remote_chassis_id=MAC["B"], remote_mgmt_ips=["10.0.0.2"]))
    inv.reindex()
    g = build_graph(inv, include_hosts=False, include_subnets=False)
    ab = [a.get("kind") for u, v, a in g.edges(data=True) if {u, v} == {"10.0.0.1", "10.0.0.2"}]
    assert "lldp" in ab and "fdb-link" not in ab


def test_inference_is_optional():
    inv = _line_inventory()
    g = build_graph(inv, include_hosts=False, include_subnets=False, fdb_links=False)
    assert not any(a.get("kind") == "fdb-link" for u, v, a in g.edges(data=True))


def test_limited_snmp_visibility_finding():
    from subnetsleuth.views import Snapshot, finding_rows
    inv = Inventory()
    inv.add_device(Device(id="10.0.0.1", name="blind-sw", role="switch"))  # no neighbours/fdb/routes
    inv.reindex()
    cats = {r["category"] for r in finding_rows(Snapshot(inv))}
    assert "Limited SNMP visibility" in cats
    # a switch that returned a MAC table is placeable, so no finding
    ok = Inventory()
    ok.add_device(Device(id="10.0.0.2", role="switch", fdb=[FdbEntry(mac="aa:bb:cc:dd:ee:ff", if_index=1)]))
    ok.reindex()
    assert "Limited SNMP visibility" not in {r["category"] for r in finding_rows(Snapshot(ok))}


def test_norm_mac_handles_formats():
    from subnetsleuth.graph import _norm_mac
    assert _norm_mac("00:24:50:65:13:27") == _norm_mac("0024.5065.1327") == "002450651327"
    assert _norm_mac("00-24-50-65-13-27") == "002450651327"
    assert _norm_mac("") == "" and _norm_mac("xyz") == ""
