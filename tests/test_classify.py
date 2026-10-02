"""Device role classification: evidence (capabilities, bridge tables, ports) over sysDescr text,
and never a blind fall-back to "router" on the SNMP routing bit."""
from subnetsleuth.collect import classify_role, reclassify_from_neighbor_caps
from subnetsleuth.model import Device, Interface, Neighbor, Route

L3BIT = 4  # sysServices "internet/routing" bit — set on nearly every managed switch


def _ports(n, type_=6):
    return [Interface(index=i, name=f"Gi1/0/{i}", type=type_) for i in range(1, n + 1)]


def test_capabilities_drive_classification():
    assert classify_role(Device(id="1", lldp_caps="bridge")) == "switch"
    assert classify_role(Device(id="1", lldp_caps="wlan-ap")) == "wireless"
    assert classify_role(Device(id="1", lldp_caps="router")) == "router"
    # bridge + router + evidence it routes -> L3 switch
    d = Device(id="1", lldp_caps="bridge,router", routes=[Route(dest="10.9.0.0/24", nexthop="10.0.0.2")])
    assert classify_role(d) == "l3switch"


def test_switch_with_many_ports_is_not_a_router():
    """The regression the user hit: an unrecognised switch with the routing service bit set
    used to fall through to 'router'. Now its ports (and lack of real routes) make it a switch."""
    d = Device(id="1", sysdescr="Acme ThingOS 4.2", services=L3BIT, interfaces=_ports(24))
    assert classify_role(d) == "switch"


def test_router_needs_real_routes_not_just_the_bit():
    # L3 bit set but nothing else -> unknown, never "router"
    assert classify_role(Device(id="1", services=L3BIT)) == "unknown"
    # a device with a learned route and few ports is a router
    d = Device(id="1", services=L3BIT, interfaces=_ports(2),
               routes=[Route(dest="10.9.0.0/24", nexthop="10.0.0.2", type=0)])
    assert classify_role(d) == "router"


def test_fdb_presence_makes_a_switch():
    from subnetsleuth.model import FdbEntry
    d = Device(id="1", sysdescr="unknown vendor", services=L3BIT,
               fdb=[FdbEntry(mac="aa:bb:cc:00:00:01", if_index=3)])
    assert classify_role(d) == "switch"


def test_text_signals_still_work_without_capabilities():
    assert classify_role(Device(id="1", sysdescr="Cisco Catalyst 9300")) == "switch"
    assert classify_role(Device(id="1", sysdescr="FortiGate-60F firewall")) == "firewall"
    assert classify_role(Device(id="1", sysdescr="Cisco Aironet access point")) == "wireless"
    assert classify_role(Device(id="1", sysdescr="HP LaserJet printer")) == "printer"


def test_reclassify_from_neighbor_caps_types_an_unknown_device():
    from subnetsleuth.model import Inventory
    inv = Inventory()
    # A couldn't be typed from its own data (unrecognised, no bridge table, no caps)
    a = Device(id="10.0.0.1", role="unknown")
    # B saw A over CDP and reports A advertises the switch/bridge capability
    b = Device(id="10.0.0.2", role="switch",
               neighbors=[Neighbor(proto="cdp", remote_mgmt_ips=["10.0.0.1"], remote_caps="switch")])
    inv.add_device(a)
    inv.add_device(b)
    inv.reindex()
    assert reclassify_from_neighbor_caps(inv) == 1
    assert inv.devices["10.0.0.1"].role == "switch"  # CDP "switch" -> bridge -> switch


def test_reclassify_never_overrides_a_confident_role():
    """A router a neighbour happens to advertise with the CDP 'switch' bit must stay a router."""
    from subnetsleuth.model import Inventory
    inv = Inventory()
    rtr = Device(id="10.0.0.1", role="router", sysdescr="Cisco ISR4331")
    peer = Device(id="10.0.0.2", role="l3switch",
                  neighbors=[Neighbor(proto="cdp", remote_mgmt_ips=["10.0.0.1"], remote_caps="router,switch")])
    inv.add_device(rtr)
    inv.add_device(peer)
    inv.reindex()
    assert reclassify_from_neighbor_caps(inv) == 0
    assert inv.devices["10.0.0.1"].role == "router"
