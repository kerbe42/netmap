"""A small asset-query language over the inventory, for searching it like a database.

    devices where role = switch and vendor ~ cisco order by name
    hosts where os ~ windows and confidence = high select name, ip, os
    interfaces where util > 80
    findings where severity = attention
    hosts where port = 3389        # matches a host with TCP/3389 open

Grammar: <page> [where <cond> [and|or <cond> ...]] [select <cols>] [order by <col> [desc]] [limit N]
Operators: =  !=  ~ (contains)  !~  >  <  >=  <=. Values may be quoted. It runs over the same
rows the app's pages show, so any visible column (by key or title) is queryable.
"""
from __future__ import annotations

import re
import shlex

from .views import PAGES, sort_key

PAGE_ALIASES = {"device": "devices", "host": "hosts", "subnet": "subnets", "vlan": "vlans",
                "link": "links", "interface": "interfaces", "iface": "interfaces", "dependency": "dependencies",
                "finding": "findings", "compliance": "compliance"}


class QueryError(Exception):
    pass


def pages() -> list[str]:
    return sorted(PAGES)


def _col_index(cols):
    idx = {}
    for c in cols:
        idx[c.key.lower()] = c.key
        idx[c.title.lower()] = c.key
    return idx


_OPS = ["<=", ">=", "!=", "!~", "=", "~", "<", ">"]


def _tokenize_conditions(text: str):
    """Split 'a = b and c ~ d' into [('a','=','b','and'), ...]. Very forgiving."""
    parts = re.split(r"\s+(and|or)\s+", text, flags=re.I)
    conds = []
    joiner = "and"
    for i, part in enumerate(parts):
        if part.lower() in ("and", "or"):
            joiner = part.lower()
            continue
        op = next((o for o in _OPS if o in part), None)
        if not op:
            raise QueryError(f"condition '{part.strip()}' needs an operator ({', '.join(_OPS)})")
        left, right = part.split(op, 1)
        val = right.strip().strip('"').strip("'")
        conds.append((left.strip().lower(), op, val, joiner if conds else "and"))
    return conds


def _match(row: dict, key: str, op: str, val: str, extra) -> bool:
    cell = row.get(key, "")
    if cell is None:
        cell = ""
    s = str(cell).lower()
    v = val.lower()
    if op == "~":
        return v in s
    if op == "!~":
        return v not in s
    if op == "=":
        return s == v or (extra is not None and extra)
    if op == "!=":
        return s != v
    # numeric comparisons where possible, else string
    try:
        a, b = float(cell), float(val)
    except (TypeError, ValueError):
        a, b = s, v
    if op == ">":
        return a > b
    if op == "<":
        return a < b
    if op == ">=":
        return a >= b
    if op == "<=":
        return a <= b
    return False


def run_query(snapshot, text: str):
    """Return (columns, rows) for a query string. `columns` is a list of Column objects."""
    text = (text or "").strip()
    if not text:
        raise QueryError("empty query")
    # page
    m = re.match(r"^(\w+)\s*(.*)$", text, re.S)
    page = PAGE_ALIASES.get(m.group(1).lower(), m.group(1).lower())
    rest = m.group(2).strip()
    if page not in PAGES:
        raise QueryError(f"unknown table '{m.group(1)}'. Try one of: {', '.join(pages())}")
    cols, fn = PAGES[page]
    rows = fn(snapshot)
    idx = _col_index(cols)

    # pull clauses off the end/middle
    limit = None
    ml = re.search(r"\blimit\s+(\d+)\s*$", rest, re.I)
    if ml:
        limit = int(ml.group(1))
        rest = rest[:ml.start()].strip()
    order_key = None
    order_desc = False
    mo = re.search(r"\border\s+by\s+([\w ]+?)(\s+desc|\s+asc)?\s*$", rest, re.I)
    if mo:
        order_key = idx.get(mo.group(1).strip().lower())
        order_desc = bool(mo.group(2) and mo.group(2).strip().lower() == "desc")
        if order_key is None:
            raise QueryError(f"unknown column '{mo.group(1).strip()}' in order by")
        rest = rest[:mo.start()].strip()
    select = None
    ms = re.search(r"\bselect\s+(.+?)\s*$", rest, re.I)
    if ms:
        names = [n.strip().lower() for n in ms.group(1).split(",")]
        select = []
        for n in names:
            if n not in idx:
                raise QueryError(f"unknown column '{n}' in select")
            select.append(idx[n])
        rest = rest[:ms.start()].strip()

    conds = []
    if rest:
        if not rest.lower().startswith("where"):
            raise QueryError("expected 'where', 'select', 'order by' or 'limit'")
        conds = _tokenize_conditions(rest[5:].strip())
        for key, *_ in conds:
            if key not in idx and key != "port":
                raise QueryError(f"unknown column '{key}'. Columns: {', '.join(sorted({c.key for c in cols}))}")

    def keep(row):
        if not conds:
            return True
        result = None
        for key, op, val, joiner in conds:
            extra = None
            if key == "port":  # convenience: match an open port on hosts/devices
                extra = _has_port(row, val)
                real_key = "port"
                ok = extra if op in ("=", "~") else _match(row, idx.get(key, key), op, val, None)
            else:
                ok = _match(row, idx[key], op, val, None)
            result = ok if result is None else (result and ok if joiner == "and" else result or ok)
        return bool(result)

    out = [r for r in rows if keep(r)]
    if order_key:
        okind = next((c.kind for c in cols if c.key == order_key), "text")
        out.sort(key=lambda r: sort_key(okind, r.get(order_key)), reverse=order_desc)
    if limit is not None:
        out = out[:limit]
    shown = [c for c in cols if (select is None or c.key in select)]
    if select is not None:
        shown.sort(key=lambda c: select.index(c.key))
    return shown, out


def _has_port(row, val) -> bool:
    try:
        want = int(re.sub(r"\D", "", val))
    except ValueError:
        return False
    text = str(row.get("services", "")) + " " + str(row.get("open ports", "")) + " " + str(row.get("port", ""))
    return bool(re.search(rf"\b{want}\b", text))
