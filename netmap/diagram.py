"""Diagram views of the topology graph, shared by the desktop map and the file exports.

A *preset* decides what a diagram shows: `physical` is cabling (LLDP/CDP) with hosts on
their switch ports, `logical` is routing and the subnets devices serve, `all` is both.
`positions` applies the user's hand-placed layout where there is one, and lays out the
rest. `export_drawio` writes those diagrams as pages of a draw.io file, which diagrams.net
opens directly and can convert to Visio.
"""
from __future__ import annotations

import html
import math
import time
from typing import Iterable, Optional

from . import layout as L
from .graph import edge_ports

PRESETS = {
    "physical": {"title": "Physical (cabling)", "l2": True, "l3": True, "subnets": False, "hosts": False, "unpolled": True},
    "logical": {"title": "Logical (routing & subnets)", "l2": False, "l3": True, "subnets": True, "hosts": False, "unpolled": False, "l2devices": False},
    "all": {"title": "Everything", "l2": True, "l3": True, "subnets": True, "hosts": False, "unpolled": True},
}


INFRA_ROLES = {"wireless", "switch", "l3switch", "router", "firewall"}


def select(g, flags: dict, preset: str = "physical") -> tuple[dict, list]:
    """Nodes and edges a diagram with these flags shows: ({id: attrs}, [(u, v, attrs)])."""
    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str, dict]] = []
    if g is None:
        return nodes, edges
    for n, a in g.nodes(data=True):
        kind = a.get("kind")
        if kind == "device":
            if a.get("role") == "unpolled" and not flags.get("unpolled"):
                continue
            if a.get("role") == "switch" and not flags.get("l2devices", True):
                continue  # a layer-2 switch's only address is its management SVI: noise on an L3 diagram
            nodes[n] = a
        elif kind == "subnet" and flags.get("subnets"):
            nodes[n] = a
        elif kind == "host" and flags.get("hosts"):
            nodes[n] = a
        elif kind == "host" and flags.get("l2") and a.get("role") in INFRA_ROLES and _announced(g, n):
            # access points, and switches/routers that announce themselves but could not be
            # polled, are part of the network's cabling, not "hosts"
            nodes[n] = a
    for u, v, a in g.edges(data=True):
        k = a.get("kind")
        if u not in nodes or v not in nodes:
            continue
        both_devices = nodes[u].get("kind") == "device" and nodes[v].get("kind") == "device"
        if k in ("lldp", "cdp") and not flags.get("l2"):
            # hosts announced over LLDP (APs, phones) still hang off their switch
            if not flags.get("hosts") or both_devices:
                continue
        if k == "l3" and not flags.get("l3"):
            continue
        if k == "member":
            if not flags.get("subnets"):
                continue
            hostside = nodes[u].get("kind") == "host" or nodes[v].get("kind") == "host"
            if hostside and flags.get("l2") and preset == "physical":
                continue
        if k == "fdb" and not flags.get("hosts"):
            continue
        edges.append((u, v, a))
    if flags.get("hosts"):
        # a host with nothing to hang off (no switch port, no subnet shown) is noise on a diagram
        linked = {x for u, v, _ in edges for x in (u, v)}
        for n in [n for n, a in nodes.items() if a.get("kind") == "host" and n not in linked]:
            del nodes[n]
    return nodes, edges


def _announced(g, n) -> bool:
    """True if a neighbour announced this node over LLDP/CDP."""
    for _, _, a in g.edges(n, data=True):
        if a.get("kind") in ("lldp", "cdp"):
            return True
    return False


def positions(nodes: dict, edges: list, saved: Optional[dict] = None, kind: str = "layered", root: Optional[str] = None) -> dict:
    """Node positions: the saved (hand-placed) ones where present, a computed layout for the
    rest, placed relative to a neighbour that already has a position so they land near it."""
    pairs = [(u, v) for u, v, _ in edges]
    if kind == "radial" and root:
        auto = L.radial(nodes, pairs, root)
    else:
        auto = L.layered(nodes, edges)  # with edge kinds, so hosts pack under their switch port
        if kind == "organic":
            auto = L.organic(nodes, pairs, init=auto)
    if not saved:
        return auto
    pos: dict = {}
    for n in nodes:
        if n not in saved:
            continue
        try:  # a hand-edited or truncated project file: one bad entry must not lose the layout
            x, y = saved[n][0], saved[n][1]
            x, y = float(x), float(y)
            if math.isfinite(x) and math.isfinite(y):
                pos[n] = (x, y)
        except (TypeError, ValueError, KeyError, IndexError):
            continue
    if not pos:
        return auto
    dxs = [pos[n][0] - auto[n][0] for n in pos if n in auto]
    dys = [pos[n][1] - auto[n][1] for n in pos if n in auto]
    shift = (sum(dxs) / len(dxs), sum(dys) / len(dys)) if dxs else (0.0, 0.0)
    adj: dict[str, list] = {}
    for u, v in pairs:
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
    for n in nodes:
        if n in pos:
            continue
        anchor = next((m for m in adj.get(n, []) if m in pos and m in auto), None)
        if anchor is not None and n in auto:
            pos[n] = (pos[anchor][0] + auto[n][0] - auto[anchor][0], pos[anchor][1] + auto[n][1] - auto[anchor][1])
        else:
            x, y = auto.get(n, (0.0, 0.0))
            pos[n] = (x + shift[0], y + shift[1])
    return pos


# ---------------------------------------------------------------- draw.io
_C19 = "sketch=0;verticalLabelPosition=bottom;html=1;verticalAlign=top;aspect=fixed;align=center;pointerEvents=1;shape=mxgraph.cisco19."
_PAINT = "fillColor=#FAFAFA;strokeColor=#005073;"
DRAWIO_STYLE = {
    "router": _C19 + "rect;prIcon=router;" + _PAINT,
    "l3switch": _C19 + "rect;prIcon=l3_switch;" + _PAINT,
    "switch": _C19 + "rect;prIcon=l2_switch;" + _PAINT,
    "firewall": _C19 + "rect;prIcon=firewall;" + _PAINT,
    "wireless": _C19 + "wireless_access_point2;" + _PAINT,
    "server": _C19 + "server2;" + _PAINT,
    "webserver": _C19 + "rect;prIcon=web_server;" + _PAINT,
    "fileserver": _C19 + "rect;prIcon=file_server;" + _PAINT,
    "mailserver": _C19 + "rect;prIcon=mail_server;" + _PAINT,
    "dnsserver": _C19 + "rect;prIcon=dns;" + _PAINT,
    "dc": _C19 + "rect;prIcon=directory_server;" + _PAINT,
    "hypervisor": _C19 + "rect;prIcon=hypervisor;" + _PAINT,
    "vm": _C19 + "rect;prIcon=hypervisor;" + _PAINT,
    "database": _C19 + "rect;prIcon=database_relational;" + _PAINT,
    "nas": _C19 + "rect;prIcon=storage;" + _PAINT,
    "ups": _C19 + "rect;prIcon=ups;" + _PAINT,
    "plc": "rounded=1;whiteSpace=wrap;html=1;fillColor=#ccece6;strokeColor=#0d9488;",
    "bms": "rounded=1;whiteSpace=wrap;html=1;fillColor=#cfe3f3;strokeColor=#0369a1;",
    "ot": "rounded=1;whiteSpace=wrap;html=1;fillColor=#ccece6;strokeColor=#0d9488;",
    "bmc": "rounded=1;whiteSpace=wrap;html=1;fillColor=#e5d9f6;strokeColor=#7c3aed;",
    "workstation": _C19 + "workstation2;" + _PAINT,
    "windows": _C19 + "workstation2;" + _PAINT,
    "host": _C19 + "workstation2;" + _PAINT,
    "printer": _C19 + "printer2;" + _PAINT,
    "phone": _C19 + "ip_phone2;" + _PAINT,
    "camera": _C19 + "surveillance_camera2;fillColor2=#00bceb;" + _PAINT,
    "subnet": "ellipse;shape=cloud;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;fontSize=10;",
    "unpolled": "rounded=1;dashed=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#666666;fontColor=#333333;fontSize=10;",
    "unknown": "rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#666666;fontColor=#333333;fontSize=10;",
}
DRAWIO_EDGE = {
    "lldp": "endArrow=none;html=1;strokeWidth=2;strokeColor=#2563eb;",
    "cdp": "endArrow=none;html=1;strokeWidth=2;strokeColor=#2563eb;",
    "l3": "endArrow=none;html=1;strokeWidth=1.5;strokeColor=#ea580c;dashed=1;",
    "member": "endArrow=none;html=1;strokeWidth=1;strokeColor=#94a3b8;dashed=1;dashPattern=1 3;",
    "fdb": "endArrow=none;html=1;strokeWidth=1;strokeColor=#94a3b8;",
}


def _esc(s) -> str:
    return html.escape(str(s or ""), quote=True)


def _esc_html_value(s) -> str:
    """A cell value or tooltip that draw.io renders as HTML (style has html=1) must be
    escaped twice: once so the text survives as HTML, once more for the XML attribute."""
    return _esc(_esc(s))


def _size(a: dict) -> tuple[float, float]:
    kind = a.get("kind")
    if kind == "subnet":
        return 110.0, 60.0
    if kind == "host":
        return 36.0, 36.0
    if a.get("role") in ("unpolled", "unknown"):
        return 110.0, 40.0
    return 50.0, 50.0


def drawio_page(name: str, nodes: dict, edges: list, pos: dict, page_id: str) -> str:
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    ids: dict[str, str] = {}
    for i, (n, a) in enumerate(nodes.items()):
        cid = f"{page_id}n{i}"
        ids[n] = cid
        role = "subnet" if a.get("kind") == "subnet" else (a.get("role") or "unknown")
        style = DRAWIO_STYLE.get(role, DRAWIO_STYLE["unknown"])
        w, h = _size(a)
        x, y = pos.get(n, (0.0, 0.0))
        label = _esc(a.get("label") or n)
        if a.get("kind") == "device" and a.get("ip") and a.get("ip") != a.get("label"):
            label += f'<br><font style="font-size:9px" color="#555555">{_esc(a.get("ip"))}</font>'
        elif a.get("kind") == "subnet" and a.get("vlan"):
            label += f"<br>VLAN {_esc(a.get('vlan'))}"
        tip = " | ".join(str(a.get(k)) for k in ("vendor", "model", "serial", "site") if a.get(k))
        tooltip = f' tooltip="{_esc_html_value(tip)}"' if tip else ""
        cells.append(
            f'<UserObject label="{_esc(label)}" id="{cid}"{tooltip} netmap_id="{_esc(n)}">'
            f'<mxCell style="{_esc(style)}fontSize=10;" vertex="1" parent="1">'
            f'<mxGeometry x="{x - w / 2:.1f}" y="{y - h / 2:.1f}" width="{w:.0f}" height="{h:.0f}" as="geometry"/></mxCell></UserObject>'
        )
    for j, (u, v, a) in enumerate(edges):
        eid = f"{page_id}e{j}"
        style = DRAWIO_EDGE.get(a.get("kind"), DRAWIO_EDGE["fdb"])
        cells.append(
            f'<mxCell id="{eid}" style="{_esc(style)}" edge="1" parent="1" source="{ids[u]}" target="{ids[v]}">'
            f'<mxGeometry relative="1" as="geometry"/></mxCell>'
        )
        if a.get("kind") in ("lldp", "cdp"):
            pu, pv = edge_ports(u, v, a)
            for k, (text, x) in enumerate(((pu, -0.7), (pv, 0.7))):
                if text:
                    cells.append(
                        f'<mxCell id="{eid}l{k}" value="{_esc_html_value(text)}" style="edgeLabel;resizable=0;html=1;align=center;verticalAlign=middle;fontSize=8;labelBackgroundColor=#ffffff;" '
                        f'vertex="1" connectable="0" parent="{eid}"><mxGeometry x="{x}" relative="1" as="geometry"><mxPoint as="offset"/></mxGeometry></mxCell>'
                    )
    body = "".join(cells)
    return (
        f'<diagram name="{_esc(name)}" id="{page_id}"><mxGraphModel dx="1000" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" '
        f'connect="1" arrows="1" fold="1" page="0" pageScale="1" math="0" shadow="0"><root>{body}</root></mxGraphModel></diagram>'
    )


def export_drawio(inv, g, path: str, pages: Optional[Iterable[str]] = None, positions_for: Optional[dict] = None) -> str:
    """Write a draw.io file with one page per preset (physical and logical by default).

    Uses the project's saved hand-placed layouts where they exist; `positions_for` can pass
    live positions (the desktop map's current arrangement) keyed by preset.
    """
    pages = list(pages or ("physical", "logical"))
    out = []
    for i, key in enumerate(pages):
        flags = {k: v for k, v in PRESETS[key].items() if k != "title"}
        nodes, edges = select(g, flags, key)
        live = (positions_for or {}).get(key)
        pos = live if live else positions(nodes, edges, inv.layout.get(key) if inv is not None else None)
        out.append(drawio_page(PRESETS[key]["title"], nodes, edges, pos, f"p{i}"))
    doc = f'<mxfile host="netmap" modified="{time.strftime("%Y-%m-%dT%H:%M:%S")}" type="device">' + "".join(out) + "</mxfile>\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path
