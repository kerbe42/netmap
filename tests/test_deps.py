"""Dependency mapping from host connections."""
from subnetsleuth.deps import build_dependencies, dependencies_of, service_name
from subnetsleuth.model import Inventory


def _host(inv, ip, conns):
    h = inv.touch_host(ip, "ssh")
    h.connections = conns
    return h


def test_dependencies_infer_server_side_and_aggregate():
    inv = Inventory()
    # a web server (10.0.0.10) and two clients hitting it on 443; the server also talks to a DB
    _host(inv, "10.0.0.11", [{"proto": "tcp", "laddr": "10.0.0.11", "lport": 51000, "raddr": "10.0.0.10", "rport": 443, "state": "ESTAB", "process": "chrome"}])
    _host(inv, "10.0.0.12", [{"proto": "tcp", "laddr": "10.0.0.12", "lport": 52000, "raddr": "10.0.0.10", "rport": 443, "state": "ESTAB"},
                             {"proto": "tcp", "laddr": "10.0.0.12", "lport": 52001, "raddr": "10.0.0.10", "rport": 443, "state": "ESTAB"}])
    _host(inv, "10.0.0.10", [{"proto": "tcp", "laddr": "10.0.0.10", "lport": 55000, "raddr": "10.0.0.20", "rport": 5432, "state": "ESTAB", "process": "app"},
                             {"proto": "tcp", "laddr": "10.0.0.10", "lport": 443, "raddr": "10.0.0.12", "rport": 52000, "state": "ESTAB"}])
    deps = build_dependencies(inv)
    edges = {(d.client, d.server, d.port): d for d in deps}
    # both clients depend on the web server on 443 (server side inferred from the well-known port)
    assert ("10.0.0.11", "10.0.0.10", 443) in edges and ("10.0.0.12", "10.0.0.10", 443) in edges
    assert edges[("10.0.0.12", "10.0.0.10", 443)].count == 2 and edges[("10.0.0.12", "10.0.0.10", 443)].service == "https"
    # the web server depends on the database
    assert ("10.0.0.10", "10.0.0.20", 5432) in edges and edges[("10.0.0.10", "10.0.0.20", 5432)].service == "postgres"
    # loopback / self connections are ignored
    _host(inv, "10.0.0.30", [{"proto": "tcp", "laddr": "10.0.0.30", "lport": 5000, "raddr": "127.0.0.1", "rport": 6000, "state": "ESTAB"}])
    assert not any(d.client == "10.0.0.30" or d.server == "10.0.0.30" for d in build_dependencies(inv))


def test_dependencies_of_node():
    inv = Inventory()
    _host(inv, "10.0.0.10", [{"proto": "tcp", "laddr": "10.0.0.10", "lport": 55000, "raddr": "10.0.0.20", "rport": 5432, "state": "ESTAB"}])
    _host(inv, "10.0.0.11", [{"proto": "tcp", "laddr": "10.0.0.11", "lport": 51000, "raddr": "10.0.0.10", "rport": 443, "state": "ESTAB"}])
    d = dependencies_of(inv, "10.0.0.10")
    assert any(u["server"] == "10.0.0.20" and u["service"] == "postgres" for u in d["uses"])
    assert any(u["client"] == "10.0.0.11" and u["service"] == "https" for u in d["used_by"])


def test_service_name():
    assert service_name(443) == "https" and service_name(3389) == "rdp" and service_name(12345) == "12345"
