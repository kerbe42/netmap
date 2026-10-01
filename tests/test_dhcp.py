"""DHCP lease/scope import parsers and enrichment."""
from subnetsleuth.dhcp import import_leases, parse_isc_leases, parse_leases, parse_windows_csv
from subnetsleuth.model import Inventory


ISC = """
lease 10.10.0.50 {
  starts 4 2026/09/28 10:00:00;
  ends 4 2026/09/28 22:00:00;
  binding state active;
  hardware ethernet 00:50:56:aa:bb:cc;
  client-hostname "finance-pc1";
}
lease 10.10.0.51 {
  binding state free;
  hardware ethernet 00:50:56:dd:ee:01;
}
"""

WIN = """DHCP Server Lease Export
IPAddress,ScopeId,HostName,ClientId,AddressState,LeaseExpiryTime
10.10.0.60,10.10.0.0,SALES-LT-7.corp.local,3c-52-82-1a-2b-3c,Active,2026-09-29 08:00
10.10.0.61,10.10.0.0,,aa-bb-cc-11-22-33,Active,2026-09-29 08:00
"""


def test_parse_isc():
    ls = parse_isc_leases(ISC)
    assert len(ls) == 2
    a = ls[0]
    assert a.ip == "10.10.0.50" and a.mac == "00:50:56:aa:bb:cc" and a.hostname == "finance-pc1" and a.state == "active"
    assert ls[1].state == "free"


def test_parse_windows_and_autodetect():
    ls = parse_leases(WIN)  # auto-detect skips the title line and finds the header
    assert len(ls) == 2 and ls[0].hostname == "SALES-LT-7" and ls[0].mac == "3c:52:82:1a:2b:3c" and ls[0].state == "active"
    assert ls[0].scope == "10.10.0.0"


def test_import_enriches_hosts():
    inv = Inventory()
    inv.add_subnet("10.10.0.0/24", "test")
    summary = import_leases(inv, parse_isc_leases(ISC))
    assert summary["named"] == 1 and summary["scopes"] == 1
    h = inv.hosts["10.10.0.50"]
    assert h.hostname == "finance-pc1" and h.mac == "00:50:56:aa:bb:cc" and "dhcp" in h.sources
    assert h.probes["dhcp"]["state"] == "active"
    assert inv.dhcp_scopes["10.10.0.0/24"]["leases"] >= 1
    # a lease for a polled device does not overwrite it as a host
    from subnetsleuth.model import Device
    inv2 = Inventory()
    d = Device(id="10.10.0.50", name="sw1"); d.ips.append("10.10.0.50"); inv2.add_device(d)
    import_leases(inv2, parse_isc_leases(ISC))
    assert "10.10.0.50" not in inv2.hosts


def test_dhcp_scopes_persist(tmp_path):
    inv = Inventory()
    inv.add_subnet("10.10.0.0/24", "test")
    import_leases(inv, parse_isc_leases(ISC))
    p = tmp_path / "p.sleuth"
    inv.save(str(p))
    assert Inventory.load(str(p)).dhcp_scopes["10.10.0.0/24"]["leases"] >= 1
