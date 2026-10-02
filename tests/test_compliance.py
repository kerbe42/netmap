"""Configuration checks on the sample network, including the hardware end-of-support lookup.

The EoL part is deliberately run through the real bundled data file rather than a fixture:
the table shipped in no release for several versions because packaging dropped it, and the
check then silently found nothing. A failure here means the data file is missing or empty.
"""
from datetime import date

import pytest

from subnetsleuth import eol
from subnetsleuth.compliance import Check, compliance_checks, summary
from subnetsleuth.model import Device, Inventory
from subnetsleuth.views import Snapshot

from . import demonet


@pytest.fixture(scope="module")
def sample():
    return demonet.build_project()


def test_eol_table_is_loaded_and_matches_known_platforms():
    eol._RECORDS = None  # ignore anything cached by an earlier test
    table = eol._load()
    assert len(table) > 20, "eol.json missing or empty: check packaging"
    assert all(callable(getattr(r["_rx"], "search", None)) for r in table)
    hit = eol.eol_status("Cisco", "WS-C2960-24TT-L", today=date(2030, 1, 1))
    assert hit and hit["status"] == "end-of-support" and "2960" in hit["family"]


def test_sample_network_has_an_end_of_support_device(sample):
    """The simulated campus keeps one old access switch on purpose (HP J9147A, ProCurve 2910al)."""
    hits = {d.id: eol.annotate_device(d) for d in sample.devices.values()}
    past = {ip: h for ip, h in hits.items() if h and h["status"] == "end-of-support"}
    assert past, hits
    assert any("2910" in h["family"] for h in past.values())
    assert all(h["days_to_eol"] < 0 for h in past.values())


def test_compliance_checks_on_the_sample(sample):
    checks = compliance_checks(Snapshot(sample))
    assert checks and all(isinstance(c, Check) for c in checks)
    cats = {c.category for c in checks}
    assert "Past end-of-support" in cats, cats
    eol_checks = [c for c in checks if c.category == "Past end-of-support"]
    assert all(c.severity == "high" and "2910" in c.found and c.node in sample.devices for c in eol_checks)
    # every finding names a device or host in the project and a standard to meet
    assert all(c.node and c.item and c.standard for c in checks)
    # sorted high -> low
    order = {"high": 0, "medium": 1, "low": 2}
    assert [order[c.severity] for c in checks] == sorted(order[c.severity] for c in checks)
    s = summary(checks)
    assert s["high"] >= 1 and sum(s.values()) == len(checks)


def test_end_of_sale_and_default_community_checks():
    inv = Inventory()
    old = Device(id="10.9.9.1", name="old-core", vendor="Cisco", model="WS-C2960-24TT-L", credential="public", role="switch")
    inv.devices[old.id] = old
    inv.reindex() if hasattr(inv, "reindex") else None
    checks = compliance_checks(Snapshot(inv))
    cats = {c.category for c in checks}
    assert "Past end-of-support" in cats
    assert "Default SNMP community" in cats
    assert "SNMPv2c in use" in cats  # 'public' is a v2c community label
    assert all(c.node == "10.9.9.1" for c in checks)


def test_default_community_finding_on_auto_tried_default():
    """A device that answered one of the auto-tried default communities carries the
    "default community '…'" credential label and must be flagged; a custom-named
    credential must not."""
    from subnetsleuth.communities import default_label

    inv = Inventory()
    hit = Device(id="10.9.9.3", name="left-on-default", vendor="Cisco", credential=default_label("cisco"), role="switch")
    custom = Device(id="10.9.9.4", name="named-ro", vendor="Cisco", credential="corp-monitoring", role="switch")
    inv.devices[hit.id] = hit
    inv.devices[custom.id] = custom
    inv.reindex() if hasattr(inv, "reindex") else None
    checks = compliance_checks(Snapshot(inv))
    flagged = {c.node for c in checks if c.category == "Default SNMP community"}
    assert "10.9.9.3" in flagged
    assert "10.9.9.4" not in flagged


def test_unknown_hardware_raises_no_eol_finding():
    inv = Inventory()
    dev = Device(id="10.9.9.2", name="mystery", vendor="Acme", model="ZX-9000", credential="v3:ro", role="switch")
    inv.devices[dev.id] = dev
    inv.reindex() if hasattr(inv, "reindex") else None
    checks = compliance_checks(Snapshot(inv))
    assert not any(c.category in ("Past end-of-support", "Approaching end-of-life") for c in checks)
