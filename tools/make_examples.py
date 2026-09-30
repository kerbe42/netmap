"""Regenerate examples/ from the simulated lab (tests/labnet.py): what the outputs look like.

Run from the repository root: python tools/make_examples.py
"""
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from netmap.diagram import export_drawio  # noqa: E402
from netmap.graph import build_graph, export_csv, export_dot, export_graphml, text_summary  # noqa: E402
from netmap.model import Inventory  # noqa: E402
from netmap.render import render_html  # noqa: E402
from netmap.report import export_xlsx  # noqa: E402
from netmap.scan import ScanRequest, run_scan  # noqa: E402
from netmap.snmp import Credential  # noqa: E402
from tests import labnet  # noqa: E402
from tests.fake_snmp import make_prober  # noqa: E402


def main():
    out = os.path.join(ROOT, "examples")
    lab = labnet.build("10")
    prober = make_prober({ip: d.values() for ip, d in lab.items()})
    inv = Inventory()
    req = ScanRequest(seeds=["10.0.0.1"], scope=["10.0.0.0/8"], credentials=[Credential(kind="v2c", community="lab", label="lab")])
    asyncio.run(run_scan(inv, req, engine=object(), prober=prober))
    g = build_graph(inv)
    p = lambda name: os.path.join(out, name)  # noqa: E731
    inv.save(p("lab-map.json"))
    render_html(g, p("lab-map.html"))
    export_graphml(g, p("lab-map.graphml"))
    export_dot(g, p("lab-map.dot"))
    export_drawio(inv, g, p("lab-map.drawio"))
    export_xlsx(inv, g, p("lab-inventory.xlsx"))
    export_csv(inv, g, p("lab-"))
    with open(p("lab-summary.txt"), "w", encoding="utf-8") as f:
        f.write(text_summary(inv, g) + "\n")
    print("wrote", out)


if __name__ == "__main__":
    main()
