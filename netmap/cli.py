"""netmap command line."""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import re
import sys
import tomllib

from . import __version__
from .graph import build_graph, export_csv, export_dot, export_graphml, text_summary
from .model import Inventory
from .render import render_html
from .report import export_xlsx
from .scan import ScanRequest, resolve_scope, run_scan
from .snmp import Credential
from .sweep import sweep

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


def read_target_file(path):
    """One subnet or address per line; '#' comments and blank lines ignored.

    Written for the range list a target hands over: paste it into a text file as-is.
    Commas and whitespace separate entries on a line, so a copied spreadsheet row works.
    """
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#")[0].strip()
            if not line:
                continue
            for item in re.split(r"[,\s]+", line):
                if not item:
                    continue
                try:
                    out.append(str(ipaddress.ip_network(item, strict=False)))
                except ValueError:
                    log.warning("%s line %d: %r is not a subnet or address, ignoring", path, n, item)
    return out


def targets_from(args, cfg):
    """Subnets the operator explicitly asked to inventory (--target / --target-file / config)."""
    c = cfg.get("crawl", {})
    items = list(getattr(args, "target", None) or []) + list(c.get("targets", []))
    for path in (getattr(args, "target_file", None) or []) + list(c.get("target_files", [])):
        items += read_target_file(path)
    return _nets(items)


def scope_from(args, cfg, targets=None):
    c = cfg.get("crawl", {})
    # Explicit targets are the scope unless a wider one was asked for; either way they
    # are inside it, so a subnet you named is never skipped as "out of scope".
    return resolve_scope(targets or [], args.scope or c.get("scope") or [], (args.exclude or []) + c.get("exclude", []))


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
    if getattr(args, "xlsx", None):
        export_xlsx(inv, g, args.xlsx)
    if getattr(args, "csv", None):
        for p in export_csv(inv, g, args.csv):
            log.info("wrote %s", p)
    if getattr(args, "summary", True):
        print(text_summary(inv, g))


async def cmd_crawl(args) -> int:
    cfg = load_config(args.config)
    c = cfg.get("crawl", {})
    seeds = list(args.seed or []) + list(c.get("seeds", []))
    targets = targets_from(args, cfg)
    if not seeds and not targets:
        log.error("nothing to do: pass --seed IP to spider from a device, or --target CIDR / --target-file to inventory named subnets")
        return 2
    inv = Inventory.load(args.out) if args.resume and os.path.exists(args.out) else Inventory()
    if args.resume and inv.devices:
        log.info("resuming from %s: %s", args.out, inv.summary())
    if targets:
        log.info("targets: %s", [str(t) for t in targets])
    req = ScanRequest(
        seeds=seeds,
        targets=[str(t) for t in targets],
        scope=[str(n) for n in _nets(args.scope or c.get("scope"))],
        exclude=[str(n) for n in _nets((args.exclude or []) + c.get("exclude", []))],
        credentials=build_credentials(args, cfg),
        probe_all=args.probe_all or c.get("probe_all", False),
        sweep=args.sweep,
        fingerprint=args.fingerprint,
        probe_hosts=args.probe_hosts or c.get("probe_hosts", False),
        resolve_names=args.dns or c.get("resolve_names", False),
        follow_routes=not args.no_routes,
        follow_gateways=not args.no_gateways,
        arp=not args.no_arp,
        fdb=not args.no_fdb,
        routes=not args.no_routes,
        cisco_vlan_fdb=args.cisco_vlan_fdb or c.get("cisco_vlan_fdb", False),
        refresh=args.refresh,
        retry_unreachable=args.retry_unreachable,
        resweep=args.resweep,
        max_depth=args.max_depth if args.max_depth is not None else c.get("max_depth", 6),
        workers=args.workers or c.get("workers", 12),
        timeout=args.timeout or c.get("timeout", 2.0),
        retries=args.retries if args.retries is not None else c.get("retries", 1),
        port=args.port,
        max_devices=args.max_devices,
        sweep_max_prefix=args.sweep_max_size,
        save_path=args.out,
    )
    await run_scan(inv, req)
    log.info("saved %s (%s)", args.out, inv.summary())
    _outputs(inv, args)
    return 0


async def cmd_sweep(args) -> int:
    cfg = load_config(args.config)
    named = _nets(args.subnet)
    scope, exclude = scope_from(args, cfg, named)
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
    p.add_argument("--xlsx", help="write a multi-sheet Excel inventory workbook (devices, IPAM, VLANs, links, hosts, gaps)")
    p.add_argument("--no-summary", dest="summary", action="store_false", help="don't print the text summary")


def _add_scope_args(p):
    p.add_argument("--scope", action="append", metavar="CIDR", help="only touch addresses inside these networks (repeatable). Default: RFC1918")
    p.add_argument("--exclude", action="append", metavar="CIDR", help="never touch these networks (repeatable)")
    p.add_argument("--config", "-c", help="TOML config file (see netmap.toml.example)")


def _add_target_args(p):
    p.add_argument(
        "--target", "-t", action="append", metavar="CIDR",
        help="subnet (or single address) to inventory directly: every live address in it is probed for SNMP. Repeatable. Implies scope unless --scope is given",
    )
    p.add_argument(
        "--target-file", action="append", metavar="PATH",
        help="file of subnets to inventory, one per line ('#' comments allowed) - e.g. the range list the target handed over. Repeatable",
    )
    p.add_argument(
        "--probe-all", action="store_true",
        help="with --target, skip the ping sweep and try SNMP on every address in the targets (for networks that drop ICMP but allow SNMP)",
    )


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
    cr.add_argument("--seed", "-s", action="append", metavar="IP", help="starting device (core switch/router) to spider from. Repeatable. Optional if --target is given")
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
    cr.add_argument("--refresh", action="store_true", help="with --resume, poll devices already in the map again and replace what was collected (notes and layout are kept)")
    cr.add_argument("--retry-unreachable", action="store_true", help="with --resume, try again addresses that did not answer SNMP last time")
    cr.add_argument("--dns", action="store_true", help="name devices and hosts from reverse DNS (PTR) lookups")
    cr.add_argument("--out", "-o", default="netmap.json", help="inventory JSON (written after every device)")
    _add_target_args(cr), _add_scope_args(cr), _add_sweep_args(cr), _add_output_args(cr, html_default="netmap.html")

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
    # A Windows console defaults to a legacy code page, and sysName/sysDescr/ifAlias come
    # back as whatever the device was configured with. Never let an odd character in
    # someone else's asset tag abort a crawl that already ran.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # not a reconfigurable stream (pipe, pytest capture)
            pass
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
