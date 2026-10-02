"""The role taxonomy that keeps "Network infrastructure" and "Endpoints by type" from overlapping."""
from subnetsleuth.roles import (
    ENDPOINT_GROUPS,
    NETWORK_ROLES,
    endpoint_group,
    group_key,
    is_network_role,
)
from subnetsleuth.views import Snapshot, device_rows, host_rows

from . import demonet


def test_network_and_endpoint_roles_are_disjoint():
    endpoint_roles = set()
    for _key, _label, roles, _icon in ENDPOINT_GROUPS:
        endpoint_roles |= set(roles)
    # nothing is both network fabric and an endpoint
    assert not (NETWORK_ROLES & endpoint_roles)


def test_group_keys_are_collision_free_for_substring_filtering():
    # the key becomes a `group:` filter token matched as a substring, so no key may be a
    # substring of another (or of "network", used for the fabric)
    keys = [k for k, _, _, _ in ENDPOINT_GROUPS] + ["network"]
    for a in keys:
        for b in keys:
            if a != b:
                assert a not in b, f"group key {a!r} is a substring of {b!r}"


def test_server_subtypes_all_fall_under_servers():
    for role in ("server", "webserver", "fileserver", "mailserver", "dnsserver", "dc", "database", "hypervisor", "vm"):
        assert endpoint_group(role)[0] == "servers"
        assert group_key(role) == "servers"


def test_network_roles_classify_as_network():
    for role in ("firewall", "router", "l3switch", "switch", "wireless"):
        assert is_network_role(role)
        assert group_key(role) == "network"


def test_unknown_and_generic_fall_under_other():
    for role in ("host", "unknown", "unpolled", "", "something-new"):
        assert endpoint_group(role)[0] == "other"
        assert group_key(role) == "other"


def test_endpoint_groups_cover_the_misc_roles():
    assert endpoint_group("printer")[0] == "printers"
    assert endpoint_group("phone")[0] == "phones"
    assert endpoint_group("camera")[0] == "cameras"
    assert endpoint_group("nas")[0] == "storage"
    assert endpoint_group("ups")[0] == "facilities"
    assert endpoint_group("bmc")[0] == "lightsout"


def test_rows_carry_a_group_for_filtering():
    s = Snapshot(demonet.build_project())
    # every device row (polled or stub) and host row has a group token
    for r in device_rows(s):
        assert r["group"], r
        # a switch/router/firewall device is "network"; an SNMP printer/UPS is its endpoint group
        assert r["group"] == group_key(r["_role"])
    for r in host_rows(s):
        assert r["group"] == group_key(r["_role"])
    # the sample has real infrastructure and real endpoints, and they don't overlap
    groups = {r["group"] for r in device_rows(s)} | {r["group"] for r in host_rows(s)}
    assert "network" in groups and "servers" in groups
