"""Self-contained interactive HTML map (vis-network from cdnjs, data embedded)."""
from __future__ import annotations

import json
import os
import re
import time

from .graph import graph_to_dict
from .util import resource_path

ROLE_COLORS = {
    "router": "#e07a2f", "l3switch": "#d9a521", "switch": "#3b82f6", "firewall": "#dc2626", "wireless": "#8b5cf6",
    "server": "#10b981", "printer": "#a16207", "unpolled": "#6b7280", "unknown": "#9ca3af",
    "host": "#94a3b8", "workstation": "#94a3b8", "windows": "#38bdf8", "phone": "#c084fc", "camera": "#fb7185",
    "vm": "#34d399", "database": "#facc15", "subnet": "#334155",
    "webserver": "#14b8a6", "fileserver": "#0891b2", "mailserver": "#a78bfa", "dnsserver": "#6366f1", "dc": "#3b82f6", "hypervisor": "#22c55e",
    "nas": "#0ea5e9", "ups": "#f59e0b", "plc": "#0d9488", "bms": "#0369a1", "ot": "#0d9488", "bmc": "#7c3aed",
}

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Network Map</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script>window.addEventListener('error',e=>{if(/ResizeObserver/.test(e.message))return;const s=document.getElementById('stats');if(s)s.textContent='Page error: '+e.message;});</script>
__VIS__
<style>
:root{--bg:#0b1220;--panel:#111a2e;--line:#243049;--fg:#e5e7eb;--muted:#94a3b8;--accent:#60a5fa}
*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--bg);color:var(--fg);font:13px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
#app{display:grid;grid-template-columns:300px 1fr;grid-template-rows:minmax(0,1fr);height:100vh}
#side{background:var(--panel);border-right:1px solid var(--line);padding:14px;overflow:auto}
#net{height:100%;width:100%;min-height:0}
h1{font-size:15px;margin:0 0 10px}h2{font-size:12px;margin:14px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
input[type=search]{width:100%;padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:#0f172a;color:var(--fg)}
label.f{display:flex;gap:6px;align-items:center;margin:3px 0;cursor:pointer}
.sw{display:inline-block;width:11px;height:11px;border-radius:3px}
#detail{font-size:12px;word-break:break-word}#detail table{border-collapse:collapse;width:100%}#detail td{padding:2px 4px;vertical-align:top;border-bottom:1px solid var(--line)}#detail td:first-child{color:var(--muted);white-space:nowrap}
.stat{color:var(--muted);font-size:12px}
button{background:#1e293b;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px 9px;cursor:pointer;margin:2px 2px 2px 0}
@media(max-width:800px){#app{grid-template-columns:1fr;grid-template-rows:auto minmax(0,1fr)}#side{max-height:40vh}}
</style></head><body>
<div id="app"><div id="side">
<h1>Network map</h1><div class="stat" id="stats"></div>
<h2>Search</h2><input type="search" id="q" placeholder="name, IP, MAC, vendor, serial…">
<h2>Show</h2>
<label class="f"><input type="checkbox" id="f_lldp" checked> LLDP/CDP links</label>
<label class="f"><input type="checkbox" id="f_l3" checked> L3 next-hop links</label>
<label class="f"><input type="checkbox" id="f_subnet" checked> Subnets</label>
<label class="f"><input type="checkbox" id="f_host"> Hosts (ARP/sweep)</label>
<label class="f"><input type="checkbox" id="f_fdb"> Host-to-port (FDB) links</label>
<label class="f"><input type="checkbox" id="f_physics" checked> Physics</label>
<div><button id="fit">Fit</button><button id="png">Export PNG</button></div>
<h2>Legend</h2><div id="legend"></div>
<h2>Selected</h2><div id="detail" class="stat">Click a node or edge.</div>
</div><div id="net"></div></div>
<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
const COLORS = __COLORS__;
const shapeFor = n => n.kind==='subnet' ? 'box' : n.kind==='host' ? 'dot' : 'ellipse';
const sizeFor = n => n.kind==='host' ? 8 : n.kind==='subnet' ? 14 : 22;
const nodes = new vis.DataSet(DATA.nodes.map(n => ({
  id:n.id, label:n.label + (n.kind==='device' && n.ip && n.label!==n.ip ? '\n'+n.ip : ''), shape:shapeFor(n),
  color:{background:COLORS[n.kind==='subnet'?'subnet':(n.role||'unknown')]||COLORS.unknown, border:'#0b1220'},
  font:{color:'#e5e7eb', size: n.kind==='host'?10:12}, size:sizeFor(n), mass: n.kind==='device'?3:1, raw:n,
  hidden: n.kind==='host'
})));
const edgeStyle = e => e.kind==='l3' ? {dashes:[6,4], color:{color:'#e07a2f'}, width:1.5}
  : e.kind==='member' ? {dashes:[2,4], color:{color:'#475569'}, width:1}
  : e.kind==='fdb' ? {dashes:[1,3], color:{color:'#64748b'}, width:1}
  : {color:{color:'#93c5fd'}, width:2};
const edges = new vis.DataSet(DATA.edges.map((e,i) => ({id:'e'+i, from:e.source, to:e.target, title:e.label||e.kind, raw:e, ...edgeStyle(e),
  hidden: e.kind==='fdb' || (e.kind==='member' && (nodes.get(e.source)?.raw.kind==='host'))})));
const net = new vis.Network(document.getElementById('net'), {nodes, edges}, {
  physics:{solver:'forceAtlas2Based', forceAtlas2Based:{gravitationalConstant:-60, springLength:120, avoidOverlap:0.6}, stabilization:{iterations:300}},
  interaction:{hover:true, multiselect:true, navigationButtons:true, keyboard:false},
  edges:{smooth:{type:'continuous'}, font:{color:'#94a3b8', size:9, strokeWidth:0}},
});
const kindCount = {}; DATA.nodes.forEach(n=>{kindCount[n.kind]=(kindCount[n.kind]||0)+1});
document.getElementById('stats').textContent = Object.entries(kindCount).map(([k,v])=>`${v} ${k}s`).join(' · ') + ` · ${DATA.edges.length} edges · generated __WHEN__`;
const legend = document.getElementById('legend');
const used = new Set(DATA.nodes.map(n=>n.kind==='subnet'?'subnet':(n.role||'unknown')));
Object.entries(COLORS).filter(([k])=>used.has(k)).forEach(([k,c])=>{const d=document.createElement('div');d.className='f';d.innerHTML=`<span class="sw" style="background:${c}"></span> ${k}`;legend.appendChild(d)});
function applyFilters(){
  const f = id => document.getElementById(id).checked;
  const showHost=f('f_host'), showSub=f('f_subnet');
  nodes.update(nodes.get().map(n=>({id:n.id, hidden: (n.raw.kind==='host'&&!showHost)||(n.raw.kind==='subnet'&&!showSub)})));
  edges.update(edges.get().map(e=>{
    const k=e.raw.kind; const a=nodes.get(e.from), b=nodes.get(e.to);
    let hide = (a&&a.hidden)||(b&&b.hidden);
    if(k==='lldp'||k==='cdp') hide = hide||!f('f_lldp');
    if(k==='l3') hide = hide||!f('f_l3');
    if(k==='fdb') hide = hide||!f('f_fdb');
    return {id:e.id, hidden:hide};
  }));
}
['f_lldp','f_l3','f_subnet','f_host','f_fdb'].forEach(id=>document.getElementById(id).addEventListener('change',applyFilters));
document.getElementById('f_physics').addEventListener('change',e=>net.setOptions({physics:{enabled:e.target.checked}}));
document.getElementById('fit').onclick=()=>net.fit();
document.getElementById('png').onclick=()=>{const c=document.querySelector('#net canvas');const a=document.createElement('a');a.download='netmap.png';a.href=c.toDataURL('image/png');a.click();};
const esc = s => String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function showDetail(obj, title){
  const rows = Object.entries(obj).filter(([k,v])=>v!==''&&v!==null&&!(Array.isArray(v)&&!v.length)).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(Array.isArray(v)?v.join(', '):v)}</td></tr>`).join('');
  document.getElementById('detail').innerHTML = `<b>${esc(title)}</b><table>${rows}</table>`;
}
net.on('click', p=>{
  if(p.nodes.length){const n=nodes.get(p.nodes[0]); const nb=net.getConnectedNodes(n.id).length; showDetail({...n.raw, connected:nb}, n.raw.label);}
  else if(p.edges.length){const e=edges.get(p.edges[0]); showDetail(e.raw, `${nodes.get(e.from).raw.label} ↔ ${nodes.get(e.to).raw.label}`);}
});
document.getElementById('q').addEventListener('input', ev=>{
  const q=ev.target.value.trim().toLowerCase(); if(!q){nodes.update(nodes.get().map(n=>({id:n.id, borderWidth:1, color:{...n.color, border:'#0b1220'}}))); return;}
  const hits = nodes.get().filter(n=>JSON.stringify(n.raw).toLowerCase().includes(q));
  nodes.update(nodes.get().map(n=>({id:n.id, borderWidth: hits.includes(n)?4:1, color:{...n.color, border: hits.includes(n)?'#fbbf24':'#0b1220'}})));
  if(hits.length){ if(hits.some(h=>h.hidden)){document.getElementById('f_host').checked=true; applyFilters();} net.selectNodes(hits.map(h=>h.id)); net.fit({nodes:hits.map(h=>h.id), animation:true}); }
});
net.once('stabilizationIterationsDone', ()=>net.fit());
</script></body></html>
"""


VENDOR_JS = resource_path("vendor", "vis-network.min.js")
CDN_TAG = '<script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.9/dist/vis-network.min.js"></script>'


def _vis_tag(embed: bool) -> str:
    """Embed vis-network so the map opens offline; fall back to the CDN if the vendored copy is missing."""
    if embed and os.path.exists(VENDOR_JS):
        with open(VENDOR_JS, encoding="utf-8") as f:
            return "<script>" + f.read().replace("</script", "<\\/script") + "</script>"
    return CDN_TAG


_PLACEHOLDER_RE = re.compile(r"__(VIS|DATA|COLORS|WHEN)__")


def render_html(g, path: str, embed_js: bool = True) -> None:
    data = json.dumps(graph_to_dict(g), default=list).replace("</", "<\\/")
    values = {
        "__VIS__": _vis_tag(embed_js),
        "__DATA__": data,
        "__COLORS__": json.dumps(ROLE_COLORS),
        "__WHEN__": time.strftime("%Y-%m-%d %H:%M"),
    }
    # one pass over the template: a placeholder that appears inside the data (someone's
    # note reading "__COLORS__") is data, and must not be substituted in turn
    html = _PLACEHOLDER_RE.sub(lambda m: values[m.group(0)], TEMPLATE)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
