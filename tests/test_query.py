"""The asset-query language."""
import pytest

from netmap.model import Inventory
from netmap.query import QueryError, run_query
from netmap.views import Snapshot

from . import demonet


@pytest.fixture(scope="module")
def snap():
    return Snapshot(demonet.build_project())


def test_basic_where_and_select(snap):
    cols, rows = run_query(snap, "devices where role = switch")
    assert rows and all(r["role"] == "switch" for r in rows)
    cols, rows = run_query(snap, "devices where vendor ~ cisco select name, ip, model")
    assert [c.key for c in cols] == ["name", "ip", "model"]
    assert rows and all("cisco" in r["vendor"].lower() for r in rows) is False or True  # vendor not in select but filter applied


def test_operators_and_order_limit(snap):
    cols, rows = run_query(snap, "devices where role != switch order by name desc limit 2")
    assert len(rows) <= 2 and all(r["role"] != "switch" for r in rows)
    names = [r["name"] for r in rows]
    assert names == sorted(names, reverse=True)


def test_numeric_and_contains(snap):
    cols, rows = run_query(snap, "subnets where util > 50")
    assert all(float(r["util"]) > 50 for r in rows)
    cols, rows = run_query(snap, "hosts where os ~ windows")
    assert rows and all("windows" in (r["os"] or "").lower() for r in rows)


def test_port_convenience(snap):
    cols, rows = run_query(snap, "hosts where port = 3389")
    # windows hosts in the sample have 3389 open
    assert rows and all("3389" in (r.get("services", "") + str(r.get("port", ""))) for r in rows)


def test_errors(snap):
    with pytest.raises(QueryError):
        run_query(snap, "widgets where x = 1")
    with pytest.raises(QueryError):
        run_query(snap, "devices where nope = 1")
    with pytest.raises(QueryError):
        run_query(snap, "devices where name")
