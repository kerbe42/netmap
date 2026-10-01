"""REST API routing over the inventory."""
import json
import urllib.request

import pytest

from subnetsleuth.api import handle, serve
from subnetsleuth.views import Snapshot

from . import demonet


@pytest.fixture(scope="module")
def snap():
    return Snapshot(demonet.build_project())


def test_handle_routes(snap):
    st, body = handle(snap, "/", {})
    assert st == 200 and "tables" in body and body["tables"]["devices"] == 11 + 1  # includes unpolled stub row
    st, body = handle(snap, "/devices", {})
    assert st == 200 and any(r["name"] == "core-sw-01" for r in body["rows"])
    st, body = handle(snap, "/device/10.99.0.2", {})
    assert st == 200 and body["name"] == "core-sw-01"
    st, body = handle(snap, "/query", {"q": ["devices where role = switch"]})
    assert st == 200 and body["count"] >= 1 and all(r["role"] == "switch" for r in body["rows"])
    st, body = handle(snap, "/query", {"q": ["bogus where x=1"]})
    assert st == 400 and "error" in body
    st, body = handle(snap, "/nope", {})
    assert st == 404


def test_serve_live_http(snap):
    srv = serve(snap.inv, host="127.0.0.1", port=0)  # port 0: let the OS pick a free one
    port = srv.server_address[1]
    import threading
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/summary", timeout=5) as r:
            data = json.load(r)
        assert data["devices"] == 11
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/query?q=hosts%20where%20os%20~%20windows", timeout=5) as r:
            data = json.load(r)
        assert data["count"] > 0
    finally:
        srv.shutdown()


def test_token_required(snap):
    srv = serve(snap.inv, host="127.0.0.1", port=0, token="secret")
    port = srv.server_address[1]
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        import urllib.error
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/summary", timeout=5)
            assert False, "should have been unauthorized"
        except urllib.error.HTTPError as e:
            assert e.code == 401
        req = urllib.request.Request(f"http://127.0.0.1:{port}/summary", headers={"Authorization": "Bearer secret"})
        with urllib.request.urlopen(req, timeout=5) as r:
            assert json.load(r)["devices"] == 11
    finally:
        srv.shutdown()
