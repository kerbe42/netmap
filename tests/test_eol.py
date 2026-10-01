"""The offline hardware end-of-life lookup, exercised against the real bundled data file."""
import json
from datetime import date

import pytest

from subnetsleuth import eol, util
from subnetsleuth.model import Device


def test_data_file_is_a_list_and_dates_parse():
    """Guards against typos: the file is a JSON list and every date is YYYY-MM-DD or blank."""
    with open(util.resource_path("data", "eol.json"), encoding="utf-8") as f:
        raw = json.load(f)
    assert isinstance(raw, list) and raw
    for rec in raw:
        assert rec.get("match"), f"record missing match: {rec}"
        for key in ("eos", "eol"):
            val = rec.get(key, "")
            if val:
                # raises ValueError on a malformed date -> fails the test
                date.fromisoformat(val)


def test_catalyst_2960_is_end_of_support():
    r = eol.eol_status("Cisco", "WS-C2960-24TT-L", today=date(2030, 1, 1))
    assert r is not None
    assert "2960" in r["family"]
    assert r["status"] == "end-of-support"
    assert r["days_to_eol"] < 0  # well past EoL


def test_active_platform_before_dates():
    """A platform reported active when 'today' is before its end-of-sale."""
    r = eol.eol_status("Cisco", "WS-C2960X-48FPD-L", today=date(2016, 1, 1))
    assert r is not None
    assert r["status"] == "active"
    assert r["days_to_eol"] > 0


def test_match_off_sysdescr_when_model_blank():
    sysdescr = "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), WS-C3750-48TS"
    r = eol.eol_status("Cisco", "", sysdescr, today=date(2030, 1, 1))
    assert r is not None
    assert "3750" in r["family"]
    assert r["status"] == "end-of-support"


def test_unknown_model_returns_none():
    assert eol.eol_status("Acme", "TotallyMadeUp-9000", today=date(2030, 1, 1)) is None
    assert eol.eol_status("", "", "", today=date(2030, 1, 1)) is None


def test_most_specific_record_wins():
    """WS-C3560X (the -X series) must beat the generic WS-C3560 fallback."""
    generic = eol.eol_status("Cisco", "WS-C3560-24TS", today=date(2030, 1, 1))
    xseries = eol.eol_status("Cisco", "WS-C3560X-24P-S", today=date(2030, 1, 1))
    assert generic is not None and xseries is not None
    assert generic["family"] == "Catalyst 3560"
    assert xseries["family"] == "Catalyst 3560-X"
    assert len(xseries["match"]) >= len(generic["match"])


def test_missing_eol_is_unknown_without_raising():
    """A current platform with no announced dates reports 'unknown' and no days_to_eol."""
    r = eol.eol_status("Cisco", "C9300-48P", today=date(2024, 1, 1))
    assert r is not None
    assert r["status"] == "unknown"
    assert "days_to_eol" not in r


def test_bad_dates_never_raise():
    # Directly feed a record with a garbage date through the parser path.
    assert eol._parse_date("not-a-date") is None
    assert eol._parse_date("") is None
    assert eol._parse_date(None) is None
    assert eol._parse_date("2020-13-45") is None


def test_annotate_device():
    dev = Device(id="10.0.0.1", vendor="Cisco", model="WS-C2960-24TT-L")
    r = eol.annotate_device(dev)
    assert r is not None and "2960" in r["family"]
    assert eol.annotate_device(Device(id="10.0.0.2", vendor="Acme", model="Nope")) is None


def test_vendor_mismatch_is_rejected():
    # A Juniper-branded device should not match a Cisco-only record even if strings overlap.
    r = eol.eol_status("Juniper", "EX4200-48T", today=date(2030, 1, 1))
    assert r is not None and r["family"] == "EX4200"
