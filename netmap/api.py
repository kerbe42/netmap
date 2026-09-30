"""A small read-only REST API over an inventory, for scripting and integration.

Serves JSON: the inventory pages, individual objects, and the query language, so another
system can pull the data or search it. Read-only and, by default, bound to localhost. An
optional token guards it. Built on the standard library only.
"""
from __future__ import annotations

import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .views import PAGES, Snapshot

log = logging.getLogger("netmap.api")


def handle(snapshot, path: str, query: dict) -> tuple[int, object]:
    """Route one request to (status, json-able body). Pure, so it is unit-testable."""
    inv = snapshot.inv
    p = path.strip("/")
    if p in ("", "index"):
        return 200, {
            "netmap": "api", "summary": inv.summary(),
            "tables": {k: len(fn(snapshot)) for k, (_c, fn) in PAGES.items()},
            "endpoints": ["/summary", "/query?q=", *[f"/{k}" for k in PAGES], "/device/<ip>", "/host/<ip>", "/subnet/<cidr>"],
        }
    if p == "summary":
        return 200, {"summary": inv.summary(), "devices": len(inv.devices),
                     "hosts": sum(1 for ip in inv.hosts if ip not in inv.ip_to_device),
                     "subnets": len(inv.subnets), "history": inv.history[-5:]}
    if p == "query":
        from .query import QueryError, run_query

        q = (query.get("q") or [""])[0]
        try:
            cols, rows = run_query(snapshot, q)
        except QueryError as e:
            return 400, {"error": str(e)}
        keys = [c.key for c in cols]
        return 200, {"columns": [{"key": c.key, "title": c.title} for c in cols],
                     "rows": [{k: r.get(k) for k in keys} for r in rows], "count": len(rows)}
    if p in PAGES:
        cols, fn = PAGES[p]
        return 200, {"rows": [_clean(r) for r in fn(snapshot)]}
    m = re.match(r"^(device|host|subnet)/(.+)$", p)
    if m:
        kind, key = m.group(1), m.group(2)
        if kind == "device" and key in inv.devices:
            from dataclasses import asdict
            return 200, asdict(inv.devices[key])
        if kind == "host" and key in inv.hosts:
            from dataclasses import asdict
            return 200, asdict(inv.hosts[key])
        if kind == "subnet" and key in inv.subnets:
            return 200, next((r for r in PAGES["subnets"][1](snapshot) if r["cidr"] == key), {})
        return 404, {"error": f"{kind} {key} not found"}
    return 404, {"error": f"no such endpoint: /{p}"}


def _clean(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def make_handler(snapshot_factory, token: str = ""):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            log.debug("api %s", a)

        def do_GET(self):  # noqa: N802
            u = urlparse(self.path)
            if token:
                supplied = self.headers.get("Authorization", "").removeprefix("Bearer ").strip() or (parse_qs(u.query).get("token") or [""])[0]
                if supplied != token:
                    return self._send(401, {"error": "unauthorized"})
            try:
                status, body = handle(snapshot_factory(), u.path, parse_qs(u.query))
            except Exception as e:  # noqa: BLE001
                status, body = 500, {"error": f"{type(e).__name__}: {e}"}
            self._send(status, body)

        def _send(self, status, body):
            data = json.dumps(body, default=list, indent=1).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(inv_or_factory, host: str = "127.0.0.1", port: int = 8088, token: str = "") -> ThreadingHTTPServer:
    """Start the API server. `inv_or_factory` is an Inventory or a callable returning one
    (so a live app can serve current data). Returns the server; call .shutdown() to stop."""
    factory = inv_or_factory if callable(inv_or_factory) else (lambda: inv_or_factory)
    srv = ThreadingHTTPServer((host, port), make_handler(lambda: Snapshot(factory()), token))
    return srv
