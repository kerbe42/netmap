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
import time

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
_COND_RE = re.compile(r"^(.+?)\s*(<=|>=|!=|!~|=|~|<|>)\s*(.+)$", re.S)
_JOIN_RE = re.compile(r"\s+(and|or)\s+", re.I)


def _split_conditions(text: str) -> list[str]:
    """Pieces of a where-clause split on and/or, but only outside quotes, so
    ``notes ~ "rack 4 and 5"`` stays one condition."""
    parts: list[str] = []
    buf: list[str] = []
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        m = _JOIN_RE.match(text, i)
        if m:
            parts.append("".join(buf))
            parts.append(m.group(1).lower())
            buf = []
            i = m.end()
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def _tokenize_conditions(text: str):
    """Split 'a = b and c ~ d' into [('a','=','b','and'), ...].

    Each condition is <column> <op> <value>; the value may be quoted and may then contain
    operators or the words and/or. The first operator found in the condition (left to
    right, longest first) is the one: ``name ~ a=b`` compares against "a=b".
    """
    conds = []
    joiner = "and"
    for part in _split_conditions(text):
        if part in ("and", "or"):
            joiner = part
            continue
        m = _COND_RE.match(part.strip())
        if not m:
            raise QueryError(f"condition '{part.strip()}' needs an operator ({', '.join(_OPS)})")
        left, op, right = m.group(1), m.group(2), m.group(3)
        conds.append((_unquote(left).lower(), op, _unquote(right), joiner if conds else "and"))
    return conds


_ORDERED_KINDS = {"ip", "cidr", "int", "pct", "duration", "time"}
_DUR_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([dhms])", re.I)


def _parse_duration(v: str):
    """'30d', '2h 30m', '90' -> seconds; None when it is not a duration."""
    s = str(v).strip().lower()
    if not s:
        return None
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return float(s)
    total = 0.0
    matched = False
    for num, unit in _DUR_RE.findall(s):
        total += float(num) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
        matched = True
    return total if matched else None


def _parse_time(v: str):
    """'2026-09-01' or '2026-09-01 14:30' -> epoch seconds; None when it is not a date."""
    s = str(v).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(s, fmt))
        except ValueError:
            continue
    try:
        return float(s)
    except ValueError:
        return None


def _ordered(kind: str, cell, val: str):
    """(a, b) keys for an ordering comparison, typed by the column's kind so addresses,
    prefixes, durations and dates compare as what they are rather than as text."""
    if kind == "duration":
        want = _parse_duration(val)
        if want is not None:
            return sort_key("int", cell), (0, want)
    if kind == "time":
        want = _parse_time(val)
        if want is not None:
            return sort_key("int", cell), (0, want)
    if kind in _ORDERED_KINDS:
        return sort_key(kind, cell), sort_key(kind, val)
    try:
        return (0, float(cell)), (0, float(val))
    except (TypeError, ValueError):
        return (1, str(cell).lower()), (1, str(val).lower())


def _match(row: dict, key: str, op: str, val: str, kind: str = "text") -> bool:
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
        return s == v
    if op == "!=":
        return s != v
    a, b = _ordered(kind, cell, val)
    if a[0] != b[0]:  # one side unparseable for this kind: no ordering between them
        return False
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
    if not m:
        raise QueryError(f"a query starts with a table name. Try one of: {', '.join(pages())}")
    page = PAGE_ALIASES.get(m.group(1).lower(), m.group(1).lower())
    rest = m.group(2).strip()
    if page not in PAGES:
        raise QueryError(f"unknown table '{m.group(1)}'. Try one of: {', '.join(pages())}")
    cols, fn = PAGES[page]
    rows = fn(snapshot)
    idx = _col_index(cols)
    kinds = {c.key: c.kind for c in cols}
    # `port = 3389` on the hosts/devices pages means "has this open port", not the switch
    # port column; on a page with a real numeric port column (dependencies) it is that column
    port_convenience = any(c.key in ("services", "open ports") for c in cols)

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
        for key, op, *_ in conds:
            if key not in idx and not (key == "port" and port_convenience):
                raise QueryError(f"unknown column '{key}'. Columns: {', '.join(sorted({c.key for c in cols}))}")
            if key == "port" and port_convenience and op not in ("=", "~", "!=", "!~"):
                raise QueryError("'port' on this table means an open port: use =, !=, ~ or !~")

    def keep(row):
        if not conds:
            return True
        result = None
        for key, op, val, joiner in conds:
            if key == "port" and port_convenience:  # convenience: match an open port on hosts/devices
                has = _has_port(row, val)
                ok = has if op in ("=", "~") else not has
            else:
                ok = _match(row, idx[key], op, val, kinds.get(idx[key], "text"))
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
    """Does the row list this open port (in its services / open-ports column)? The switch
    port column ("Gi1/0/22") is deliberately not searched."""
    try:
        want = int(re.sub(r"\D", "", val))
    except ValueError:
        return False
    text = str(row.get("services", "")) + " " + str(row.get("open ports", ""))
    return bool(re.search(rf"(^|[\s,])(tcp/|udp/)?{want}(/|\b)", text))
