"""netmap command line."""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import sys
import tomllib

from . import __version__
from .collect import CollectOptions
from .crawl import CrawlConfig, Crawler
from .graph import build_graph, export_csv, export_dot, export_graphml, text_summary
from .model import Inventory
from .render import render_html
from .snmp import Credential
from .sweep import sweep
from .util import RFC1918

log = logging.getLogger("netmap")


def _nets(items):
    return [ipaddress.ip_network(x, strict=False) for x in items or []]


def load_config(path):
    if not path:
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def build_credentials(args, cfg) -> list[Credential]:
    creds = [Credential.from_dict(c) for c in cfg.get("credentials", [])]
    for c in args.community or []:
        creds.append(Credential.from_dict({"kind": "v2c", "community": c}))
    if args.v3_user:
        creds.append(
            Credential.from_dict({"kind": "v3", "user": args.v3_user, "auth": args.v3_auth, "auth_key": args.v3_auth_key, "priv": args.v3_priv, "priv_key": args.v3_priv_key})
        )
    if not creds and os.environ.get("NETMAP_COMMUNITY"):
        creds.append(Credential.from_dict({"kind": "v2c", "community": os.environ["NETMAP_COMMUNITY"], "label": "env"}))
    if not creds:
        creds.append(Credential.from_dict({"kind": "v2c", "community": "public", "label": "public"}))
        log.warning("no credentials given; trying community 'public' only")
    return creds


def scope_from(args, cfg):
    c = cfg.get("crawl", {})
    scope = _nets(args.scope or c.get("scope"))
    if not scope:
        scope = list(RFC1918)
        log.warning("no --scope given; limiting crawl to RFC1918 space (10/8, 172.16/12, 192.168/16)")
    exclude = _nets((args.exclude or []) + c.get("exclude", []))
    return scope, exclude


def _outputs(inv: Inventory, args) -> None:
    g = build_graph(inv)
    if getattr(args, "html", None):
        render_html(g, args.html)
        log.info("wrote %s", args.html)
    if getattr(args, "graphml", None):
        export_graphml(g, args.graphml)
        log.info("wrote %s", args.graphml)
    if getattr(args, "dot", None):
        export_dot(g, args.dot)
        log.info("wrote %s", args.dot)
    if getattr(args, "csv", None):
        for p in export_csv(inv, g, args.csv):
            log.info("wrote %s", p)
    if getattr(args, "summary", True):
        print(text_summary(inv, g))


async def cmd_crawl(args) -> int:
    cfg = load_config(args.config)
    c = cfg.get("crawl", {})
    seeds = list(args.seed or []) + list(c.get("seeds", []))
    if not seeds:
        log.error("no seeds: pass --seed IP (repeatable) or seeds=[...] in the config")
        return 2
    scope, exclude = scope_from(args, cfg)
    inv = Inventory.load(args.out) if args.resume and os.path.exists(args.out) else Inventory()
    if args.resume and inv.devices:
        log.info("resuming from %s: %s", args.out, inv.summary())
    ccfg = CrawlConfig(
        seeds=seeds,
        credentials=build_credentials(args, cfg),
        scope=scope,
        exclude=exclude,
        max_depth=args.max_depth if args.max_depth is not None else c.get("max_depth", 6),
        workers=args.workers or c.get("workers", 12),
        timeout=args.timeout or c.get("timeout", 2.0),
        retries=args.retries if args.retries is not None else c.get("retries", 1),
        port=args.port,
        probe_hosts=args.probe_hosts or c.get("probe_hosts", False),
        follow_routes=not args.no_routes,
        follow_gateways=not args.no_gateways,
        collect=CollectOptions(fdb=not args.no_fdb, cisco_vlan_fdb=args.cisco_vlan_fdb or c.get("cisco_vlan_fdb", False), routes=not args.no_routes, arp=not args.no_arp),
        save_path=args.out,
        max_devices=args.max_devices,
    )
    log.info("scope: %s  exclude: %s  seeds: %s  creds: %s", [str(n) for n in scope], [str(n) for n in exclude], seeds, [cr.label for cr in ccfg.credentials])
    inv = await Crawler(ccfg, inv).run()
    if args.sweep:
        n = await sweep(inv, list(inv.subnets), scope, exclude, fingerprint=args.fingerprint, max_prefix=args.sweep_max_size, resweep=args.resweep)
        log.info("sweep found %d hosts", n)
        inv.save(args.out)
    log.info("saved %s (%s)", args.out, inv.summary())
    _outputs(inv, args)
    return 0


async def cmd_sweep(args) -> int:
    cfg = load_config(args.config)
    scope, exclude = scope_from(args, cfg)
    inv = Inventory.load(args.map) if os.path.exists(args.map) else Inventory()
    subnets = list(args.subnet or []) or list(inv.subnets)
    if not subnets:
        log.error("nothing to sweep: give --subnet CIDR or a map with discovered subnets")
        return 2
    n = await sweep(inv, subnets, scope, exclude, fingerprint=args.fingerprint, max_prefix=args.sweep_max_size, resweep=True)
    log.info("sweep found %d hosts", n)
    inv.save(args.map)
    _outputs(inv, args)
    return 0


def cmd_render(args) -> int:
    inv = Inventory.load(args.map)
    _outputs(inv, args)
    return 0


def _add_output_args(p, html_default=None):
    p.add_argument("--html", default=html_default, help="write interactive HTML map")
    p.add_argument("--graphml", help="write GraphML (yEd, Gephi, Cytoscape)")
    p.add_argument("--dot", help="write Graphviz DOT")
    p.add_argument("--csv", help="write CSV inventory files with this prefix, e.g. out/mna-")
    p.add_argument("--no-summary", dest="summary", action="store_false", help="don't print the text summary")


def _add_scope_args(p):
    p.add_argument("--scope", action="append", metavar="CIDR", help="only touch addresses inside these networks (repeatable). Default: RFC1918")
    p.add_argument("--exclude", action="append", metavar="CIDR", help="never touch these networks (repeatable)")
    p.add_argument("--config", "-c", help="TOML config file (see netmap.toml.example)")


def _add_sweep_args(p):
    p.add_argument("--fingerprint", action="store_true", help="after the ping sweep, scan top ports on live hosts with nmap -sV to classify them")
    p.add_argument("--sweep-max-size", type=int, default=22, help="skip subnets larger than this prefix length (default /22)")


def build_parser():
    p = argparse.ArgumentParser(prog="netmap", description="Crawl a network via SNMP (LLDP/CDP/ARP/routes/FDB) and build a topology map.")
    p.add_argument("--version", action="version", version=f"netmap {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info (default), -vv debug")
    p.add_argument("-q", "--quiet", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    cr = sub.add_parser("crawl", help="spider the network starting from seed devices")
    cr.add_argument("--seed", "-s", action="append", metavar="IP", help="starting device (core switch/router). Repeatable")
    cr.add_argument("--community", "-C", action="append", metavar="STR", help="SNMPv2c community to try (repeatable, tried in order)")
    cr.add_argument("--v3-user"), cr.add_argument("--v3-auth", default="SHA"), cr.add_argument("--v3-auth-key"), cr.add_argument("--v3-priv", default="AES"), cr.add_argument("--v3-priv-key")
    cr.add_argument("--port", type=int, default=161)
    cr.add_argument("--max-depth", type=int, help="hops from a seed to follow (default 6)")
    cr.add_argument("--workers", type=int, help="devices polled in parallel (default 12)")
    cr.add_argument("--timeout", type=float, help="SNMP timeout seconds (default 2)")
    cr.add_argument("--retries", type=int, help="SNMP retries (default 1)")
    cr.add_argument("--max-devices", type=int, default=5000)
    cr.add_argument("--probe-hosts", action="store_true", help="also try SNMP against every ARP-learned address (finds APs, printers, servers; slower)")
    cr.add_argument("--no-routes", action="store_true", help="don't collect routing tables or follow next-hops")
    cr.add_argument("--no-gateways", action="store_true", help="don't probe the first/last address of each discovered subnet")
    cr.add_argument("--no-arp", action="store_true"), cr.add_argument("--no-fdb", action="store_true")
    cr.add_argument("--cisco-vlan-fdb", action="store_true", help="walk Cisco per-VLAN bridge tables (community@vlan / vlan-N context)")
    cr.add_argument("--sweep", action="store_true", help="after crawling, ping-sweep every discovered subnet with nmap")
    cr.add_argument("--resweep", action="store_true")
    cr.add_argument("--resume", action="store_true", help="load the existing map and skip devices already collected")
    cr.add_argument("--out", "-o", default="netmap.json", help="inventory JSON (written after every device)")
    _add_scope_args(cr), _add_sweep_args(cr), _add_output_args(cr, html_default="netmap.html")

    sw = sub.add_parser("sweep", help="ping-sweep subnets (from the map, or given) and add hosts")
    sw.add_argument("--map", "-m", default="netmap.json")
    sw.add_argument("--subnet", action="append", metavar="CIDR")
    _add_scope_args(sw), _add_sweep_args(sw), _add_output_args(sw)

    rd = sub.add_parser("render", help="build outputs (HTML/GraphML/DOT/CSV) from a saved map")
    rd.add_argument("--map", "-m", default="netmap.json")
    _add_output_args(rd, html_default="netmap.html")

    sh = sub.add_parser("show", help="print the text summary of a saved map")
    sh.add_argument("--map", "-m", default="netmap.json")
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    level = logging.WARNING if args.quiet else (logging.DEBUG if args.verbose >= 2 else logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-5s %(name)s: %(message)s", datefmt="%H:%M:%S", stream=sys.stderr)
    logging.getLogger("pysnmp").setLevel(logging.WARNING)
    if args.cmd == "crawl":
        rc = asyncio.run(cmd_crawl(args))
    elif args.cmd == "sweep":
        rc = asyncio.run(cmd_sweep(args))
    elif args.cmd == "render":
        rc = cmd_render(args)
    elif args.cmd == "show":
        inv = Inventory.load(args.map)
        print(text_summary(inv, build_graph(inv)))
        rc = 0
    else:
        rc = 2
    sys.exit(rc)
