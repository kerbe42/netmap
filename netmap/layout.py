"""Node placement for the topology map, independent of any GUI toolkit.

Three layouts, each a function from (nodes, edges) to {node id: (x, y)}:

* ``layered``: the diagram a network engineer would draw. Firewalls and routers on
  top, then L3/core switches, then L2 switches by distance from the core, then what
  hangs off them. Endpoints that hang off one parent are packed into a grid under it,
  so a switch with 48 hosts is a tidy block rather than a line 7000 pixels wide.
* ``organic``: force-directed, for meshes where tiers mean little.
* ``radial``: rings around one chosen node, for "what is near this box".

`nodes` maps id -> attributes (``kind``: device | host | subnet, ``role``, ``label``);
`edges` is an iterable of (u, v) pairs, duplicates and self-loops allowed.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import defaultdict, deque
from typing import Iterable, Optional

TIER = {"firewall": 0, "router": 1, "l3switch": 2, "switch": 3}

Pos = dict[str, tuple[float, float]]


def _adjacency(nodes: dict, edges: Iterable) -> dict[str, set]:
    adj: dict[str, set] = {n: set() for n in nodes}
    for u, v in edges:
        if u != v and u in adj and v in adj:
            adj[u].add(v)
            adj[v].add(u)
    return adj


def _components(adj: dict[str, set]) -> list[list[str]]:
    seen: set = set()
    comps = []
    for start in adj:
        if start in seen:
            continue
        comp, q = [], deque([start])
        seen.add(start)
        while q:
            n = q.popleft()
            comp.append(n)
            for m in adj[n]:
                if m not in seen:
                    seen.add(m)
                    q.append(m)
        comps.append(comp)
    return comps


def natural_key(nodes: dict, n: str):
    """Sort by role, then label with numbers compared as numbers, then address."""
    a = nodes.get(n, {})
    label = str(a.get("label") or n).lower()
    parts = tuple((0, int(t), "") if t.isdigit() else (1, 0, t) for t in re.split(r"(\d+)", label) if t)
    try:
        ip = int(ipaddress.ip_address(str(a.get("ip") or n).split("/")[0]))
    except ValueError:
        ip = 0
    return (str(a.get("role") or ""), parts, ip)


def _tier(a: dict) -> Optional[int]:
    if a.get("kind") == "device":
        role = a.get("role")
        if role in TIER:
            return TIER[role]
        if role == "unpolled":
            caps = str(a.get("caps") or "")
            if "router" in caps:
                return TIER["router"]
            if "bridge" in caps or "switch" in caps:
                return TIER["switch"]
    return None


def _pav(desired: list[float], widths: list[float], gap: float) -> list[float]:
    """Closest positions to `desired` (least squares) that keep order and do not overlap.

    Isotonic regression (pool adjacent violators) after subtracting each item's minimum
    offset from the first, which turns "no overlap" into "non-decreasing".
    """
    n = len(desired)
    if n == 0:
        return []
    off = [0.0] * n
    for i in range(1, n):
        off[i] = off[i - 1] + (widths[i - 1] + widths[i]) / 2 + gap
    blocks: list[list[float]] = []
    for i in range(n):
        blocks.append([desired[i] - off[i], 1.0])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            s, c = blocks.pop()
            blocks[-1][0] += s
            blocks[-1][1] += c
    ys: list[float] = []
    for s, c in blocks:
        ys += [s / c] * int(c)
    return [ys[i] + off[i] for i in range(n)]


def layered(
    nodes: dict,
    edges: Iterable,
    hgap: float = 150.0,
    vgap: float = 160.0,
    leaf_w: float = 104.0,
    leaf_h: float = 84.0,
    pack_min: int = 4,
    comp_gap: float = 220.0,
) -> Pos:
    adj = _adjacency(nodes, edges)
    comps = [c for c in _components(adj) if len(c) > 1]
    isolated = sorted((n for n in adj if not adj[n]), key=lambda n: natural_key(nodes, n))
    comps.sort(key=lambda c: (-len(c), min(c)))
    pos: Pos = {}
    x0 = 0.0
    bottom = 0.0
    for comp in comps:
        p = _layered_component(comp, nodes, adj, hgap, vgap, leaf_w, leaf_h, pack_min)
        minx = min(x for x, _ in p.values())
        maxx = max(x for x, _ in p.values())
        for n, (x, y) in p.items():
            pos[n] = (x - minx + x0, y)
            bottom = max(bottom, y)
        x0 += (maxx - minx) + comp_gap
    if isolated:
        # things with no link at all: a grid below the connected picture
        width = max(x0 - comp_gap, 0.0)
        cols = max(4, min(len(isolated), int(max(width, 8 * leaf_w) // leaf_w), int(math.ceil(math.sqrt(len(isolated) * 3)))))
        top = bottom + vgap * (1.3 if pos else 0)
        for i, n in enumerate(isolated):
            pos[n] = ((i % cols) * leaf_w, top + (i // cols) * leaf_h)
    return pos


def _layered_component(comp, nodes, adj, hgap, vgap, leaf_w, leaf_h, pack_min) -> Pos:
    cset = set(comp)
    layer: dict[str, int] = {}
    tiers = {n: _tier(nodes.get(n, {})) for n in comp}
    for n in comp:
        t = tiers[n]
        if t is not None and t < TIER["switch"]:
            layer[n] = t
    # L2 switches: one tier per hop away from the routed core
    switches = {n for n in comp if tiers[n] == TIER["switch"]}
    q = deque(n for n in layer)
    dist = {n: 0 for n in layer}
    while q:
        n = q.popleft()
        for m in adj[n]:
            if m in switches and m not in dist:
                dist[m] = dist[n] + 1
                layer[m] = TIER["switch"] + dist[m] - 1
                q.append(m)
    rest = sorted(switches - set(layer), key=lambda n: (-len(adj[n]), natural_key(nodes, n)))
    while rest:  # switches not behind any router: start from the best-connected one
        root = rest[0]
        layer[root] = TIER["switch"]
        q = deque([root])
        while q:
            n = q.popleft()
            for m in adj[n]:
                if m in switches and m not in layer:
                    layer[m] = layer[n] + 1
                    q.append(m)
        rest = [n for n in rest if n not in layer]
    if not layer:
        root = max(comp, key=lambda n: (len(adj[n]), n))
        layer[root] = 0
    # everything else sits one below the lowest thing it hangs off
    q = deque(sorted(layer, key=lambda n: layer[n]))
    while q:
        n = q.popleft()
        for m in sorted(adj[n], key=lambda n: natural_key(nodes, n)):
            if m not in layer:
                placed = [layer[k] for k in adj[m] if k in layer]
                layer[m] = max(placed) + 1
                q.append(m)
    # compress unused tiers
    used = sorted(set(layer.values()))
    remap = {v: i for i, v in enumerate(used)}
    layer = {n: remap[v] for n, v in layer.items()}

    # leaves under one parent become a packed block in the layer below it
    children: dict[str, list[str]] = defaultdict(list)
    for n in comp:
        if len(adj[n]) == 1:
            (p,) = tuple(adj[n])
            if layer[n] > layer[p] and len(adj[p]) > 1:
                children[p].append(n)
    blocks: dict[str, list[str]] = {}
    for p, kids in children.items():
        if len(kids) >= pack_min:
            kids.sort(key=lambda n: natural_key(nodes, n))
            blocks[p] = kids
            for k in kids:
                layer[k] = layer[p] + 1
    packed = {k for kids in blocks.values() for k in kids}
    nlayers = max(layer.values()) + 1

    # items per layer: ("n", id) or ("b", parent)
    items: list[list[tuple[str, str]]] = [[] for _ in range(nlayers)]
    order_seen: set = set()

    def visit(n):  # DFS so the first order already follows the wiring
        if n in order_seen:
            return
        order_seen.add(n)
        if n not in packed:
            items[layer[n]].append(("n", n))
        if n in blocks:
            items[layer[n] + 1].append(("b", n))
        for m in sorted(adj[n], key=lambda m: (layer[m], natural_key(nodes, m))):
            if layer[m] > layer[n] and m not in packed:
                visit(m)

    for n in sorted(comp, key=lambda n: (layer[n], natural_key(nodes, n))):
        visit(n)
    for n in comp:  # anything the DFS could not reach downward (links that go up)
        if n not in order_seen:
            order_seen.add(n)
            if n not in packed:
                items[layer[n]].append(("n", n))

    def cols_of(parent):
        k = len(blocks[parent])
        return max(1, min(k, max(pack_min, int(math.ceil(math.sqrt(k * 1.2))))))

    def width(it):
        return cols_of(it[1]) * leaf_w if it[0] == "b" else hgap

    def links(it, up: bool):
        kind, n = it
        if kind == "b":
            return [n] if up else []
        lv = layer[n]
        out = [m for m in adj[n] if m not in packed and (layer[m] < lv if up else layer[m] > lv)]
        if not up and n in blocks:
            out.append(("b", n))
        return out

    def key_of(x):
        return x if isinstance(x, tuple) else ("n", x)

    # crossing reduction: barycentre sweeps down and up
    for _ in range(6):
        for rng, up in ((range(1, nlayers), True), (range(nlayers - 2, -1, -1), False)):
            for li in rng:
                ref = {key_of(it): i for i, it in enumerate(items[li - 1 if up else li + 1])}
                keyed = []
                for i, it in enumerate(items[li]):
                    ns = [ref[key_of(m)] for m in links(it, up) if key_of(m) in ref]
                    keyed.append((sum(ns) / len(ns) if ns else i, i, it))
                keyed.sort(key=lambda t: (t[0], t[1]))
                items[li] = [it for _, _, it in keyed]

    # x: start packed, then pull each item over what it connects to, without overlaps
    x: dict = {}
    for li in range(nlayers):
        cur = 0.0
        for it in items[li]:
            w = width(it)
            x[it] = cur + w / 2
            cur += w + 20
    for _ in range(8):
        for rng, up in ((range(1, nlayers), True), (range(nlayers - 2, -1, -1), False)):
            for li in rng:
                row = items[li]
                desired = []
                for it in row:
                    ns = [x[key_of(m)] for m in links(it, up) if key_of(m) in x]
                    desired.append(sum(ns) / len(ns) if ns else x[it])
                xs = _pav(desired, [width(it) for it in row], 24.0)
                for it, v in zip(row, xs):
                    x[it] = v

    # y: layers top to bottom, with room for the blocks
    ys = []
    y = 0.0
    for li in range(nlayers):
        ys.append(y)
        extent = 0.0
        for kind, n in items[li]:
            if kind == "b":
                rows = int(math.ceil(len(blocks[n]) / cols_of(n)))
                extent = max(extent, (rows - 1) * leaf_h)
        y += extent + vgap
    pos: Pos = {}
    for li in range(nlayers):
        for it in items[li]:
            kind, n = it
            if kind == "n":
                pos[n] = (x[it], ys[li])
            else:
                cols = cols_of(n)
                kids = blocks[n]
                left = x[it] - (cols - 1) * leaf_w / 2
                for i, k in enumerate(kids):
                    pos[k] = (left + (i % cols) * leaf_w, ys[li] + (i // cols) * leaf_h)
    return pos


def organic(nodes: dict, edges: Iterable, init: Optional[Pos] = None, k: float = 130.0, iterations: Optional[int] = None) -> Pos:
    """Fruchterman-Reingold with a spatial grid, so repulsion only looks at nearby nodes.

    Starts from `init` (usually the layered positions) so the result is deterministic
    and settles quickly.
    """
    ids = list(nodes)
    n = len(ids)
    if n == 0:
        return {}
    idx = {v: i for i, v in enumerate(ids)}
    adj = _adjacency(nodes, edges)
    elist = sorted({(min(idx[u], idx[v]), max(idx[u], idx[v])) for u in adj for v in adj[u]})
    if init is None:
        init = layered(nodes, [(ids[a], ids[b]) for a, b in elist])
    px = [float(init.get(v, (0, 0))[0]) for v in ids]
    py = [float(init.get(v, (0, 0))[1]) for v in ids]
    if iterations is None:
        iterations = max(30, min(220, int(60000 / max(n, 1))))
    cell = 2.0 * k
    span = max(max(px) - min(px), max(py) - min(py), k * 4)
    temp = span / 8
    cx = sum(px) / n
    cy = sum(py) / n
    for it in range(iterations):
        dx = [0.0] * n
        dy = [0.0] * n
        grid: dict[tuple[int, int], list[int]] = defaultdict(list)
        for i in range(n):
            grid[(int(px[i] // cell), int(py[i] // cell))].append(i)
        for (gx, gy), members in grid.items():
            near = []
            for ox in (-1, 0, 1):
                for oy in (-1, 0, 1):
                    near.extend(grid.get((gx + ox, gy + oy), ()))
            for i in members:
                xi, yi = px[i], py[i]
                for j in near:
                    if j == i:
                        continue
                    ddx = xi - px[j]
                    ddy = yi - py[j]
                    d2 = ddx * ddx + ddy * ddy
                    if d2 < 0.01:
                        ddx, ddy, d2 = (i - j) * 0.1 + 0.1, 0.1, 0.02
                    if d2 > cell * cell:
                        continue
                    f = k * k / d2
                    dx[i] += ddx * f
                    dy[i] += ddy * f
        for a, b in elist:
            ddx = px[a] - px[b]
            ddy = py[a] - py[b]
            d = math.sqrt(ddx * ddx + ddy * ddy) or 0.01
            f = d / k
            dx[a] -= ddx * f
            dy[a] -= ddy * f
            dx[b] += ddx * f
            dy[b] += ddy * f
        for i in range(n):  # a little gravity keeps separate islands from drifting apart
            dx[i] -= (px[i] - cx) * 0.02
            dy[i] -= (py[i] - cy) * 0.02
            d = math.sqrt(dx[i] * dx[i] + dy[i] * dy[i])
            if d > 0:
                lim = min(d, temp)
                px[i] += dx[i] / d * lim
                py[i] += dy[i] / d * lim
        temp = max(temp * 0.955, 2.0)
    return {v: (px[i], py[i]) for i, v in enumerate(ids)}


def radial(nodes: dict, edges: Iterable, root: str, ring: float = 190.0, min_arc: float = 90.0) -> Pos:
    """Rings of hop distance around `root`; each subtree gets a wedge sized by its leaves."""
    adj = _adjacency(nodes, edges)
    if root not in adj:
        return layered(nodes, edges)
    parent: dict[str, Optional[str]] = {root: None}
    depth = {root: 0}
    order = [root]
    q = deque([root])
    while q:
        n = q.popleft()
        for m in sorted(adj[n], key=lambda m: natural_key(nodes, m)):
            if m not in parent:
                parent[m] = n
                depth[m] = depth[n] + 1
                order.append(m)
                q.append(m)
    kids: dict[str, list[str]] = defaultdict(list)
    for n in order[1:]:
        kids[parent[n]].append(n)
    leaves: dict[str, int] = {}
    for n in reversed(order):
        leaves[n] = sum(leaves[c] for c in kids[n]) or 1
    per_ring: dict[int, int] = defaultdict(int)
    for n in order:
        per_ring[depth[n]] += 1
    radius = {0: 0.0}
    for d in range(1, max(depth.values()) + 1):
        need = per_ring[d] * min_arc / (2 * math.pi)
        radius[d] = max(radius[d - 1] + ring, need)
    pos: Pos = {root: (0.0, 0.0)}
    wedge = {root: (0.0, 2 * math.pi)}
    for n in order:
        a0, a1 = wedge[n]
        total = leaves[n]
        cur = a0
        for c in kids[n]:
            span = (a1 - a0) * leaves[c] / total
            wedge[c] = (cur, cur + span)
            mid = cur + span / 2
            r = radius[depth[c]]
            pos[c] = (r * math.cos(mid), r * math.sin(mid))
            cur += span
    missing = [n for n in nodes if n not in pos]
    if missing:  # not connected to the root: park them in a row underneath
        base = max((y for _, y in pos.values()), default=0.0) + ring
        left = min((x for x, _ in pos.values()), default=0.0)
        for i, n in enumerate(sorted(missing, key=lambda n: natural_key(nodes, n))):
            pos[n] = (left + (i % 16) * 100.0, base + (i // 16) * 80.0)
    return pos
