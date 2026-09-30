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
    for c in getattr(args, "v1_community", None) or []:
        creds.append(Credential.from_dict({"kind": "v1", "community": c}))
    if args.v3_priv_key and not args.v3_auth_key:
        log.warning("--v3-priv-key given without --v3-auth-key: SNMPv3 privacy needs authentication, the priv key will not be used")
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


_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*((?:\d{1,3}\.){3}\d{1,3}|\d{1,3})$")


def parse_target_item(item: str) -> list[str]:
    """One entry of a range list -> CIDRs. Accepts a subnet, a single address, and the
    range forms 'a.b.c.d-a.b.c.e' and 'a.b.c.d-e' (summarised to the fewest CIDRs).
    Raises ValueError for anything else."""
    m = _RANGE_RE.match(item)
    if not m:
        return [str(ipaddress.ip_network(item, strict=False))]
    first = ipaddress.ip_address(m.group(1))
    end = m.group(2)
    if "." not in end:
        end = m.group(1).rsplit(".", 1)[0] + "." + end
    last = ipaddress.ip_address(end)
    if last < first:
        raise ValueError(f"range end {last} is before its start {first}")
    return [str(n) for n in ipaddress.summarize_address_range(first, last)]


def read_target_file(path):
    """One subnet, address or range per line; '#' comments and blank lines ignored.

    Written for the range list a target hands over: paste it into a text file as-is.
    Commas and whitespace separate entries on a line, so a copied spreadsheet row works;
    '10.1.0.10-10.1.0.20' and '10.1.0.10-20' are ranges.
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
                    out.extend(parse_target_item(item))
                except ValueError:
                    log.warning("%s line %d: %r is not a subnet, address or range, ignoring", path, n, item)
    return out


def _load_map(path: str) -> Inventory:
    """Open a saved map, or say plainly that it is not there (exit 2) instead of a traceback."""
    if not os.path.exists(path):
        log.error("map file %s does not exist (give --map PATH, or run a crawl first)", path)
        sys.exit(2)
    try:
        return Inventory.load(path)
    except (OSError, ValueError) as e:
        log.error("could not read map file %s: %s", path, e)
        sys.exit(2)


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
    if getattr(args, "drawio", None):
        from .diagram import export_drawio

        export_drawio(inv, g, args.drawio)
        log.info("wrote %s", args.drawio)
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
        identify=args.identify or c.get("identify", False),
        port_scan=args.port_scan or c.get("port_scan", False),
        os_detect=args.os_detect or c.get("os_detect", False),
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
        workers=args.workers if args.workers is not None else c.get("workers", 12),
        timeout=args.timeout if args.timeout is not None else c.get("timeout", 2.0),
        retries=args.retries if args.retries is not None else c.get("retries", 1),
        port=args.port,
        max_devices=args.max_devices,
        sweep_max_prefix=args.sweep_max_size,
        save_path=args.out,
    )
    await run_scan(inv, req)
    log.info("saved %s (%s)", args.out, inv.summary())
    _outputs(inv, args)
    if targets and not inv.devices:
        # the operator named ranges and nothing in them answered SNMP: the outputs are empty,
        # which a script or CI run needs to see in the exit status
        if not (args.repeat and args.repeat > 0):
            return 1
    if args.repeat and args.repeat > 0:
        import asyncio as _a

        req.refresh = True
        log.info("repeating every %ds; Ctrl-C to stop", args.repeat)
        try:
            while True:
                await _a.sleep(args.repeat)
                log.info("=== scheduled rescan ===")
                await run_scan(inv, req)
                _outputs(inv, args)
        except (KeyboardInterrupt, _a.CancelledError):
            log.info("stopped")
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
    inv = _load_map(args.map)
    _outputs(inv, args)
    return 0


def cmd_diff(args) -> int:
    import csv

    from .diff import compare

    d = compare(_load_map(args.old), _load_map(args.new))
    print(d.text())
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["kind", "change", "item", "name", "detail"])
            for c in d.changes:
                w.writerow([c.kind, c.change, c.item, c.name, c.detail])
        log.info("wrote %s", args.csv)
    return 0


def cmd_vmware(args) -> int:
    import getpass
    from .vmware import discover

    inv = _load_map(args.map)
    pw = args.password if args.password is not None else getpass.getpass("vCenter password: ")
    result = discover(inv, args.host, args.user, pw, port=args.port, insecure=args.insecure)
    if result.get("error"):
        log.error("VMware discovery failed: %s", result["error"])
        return 1
    inv.save(args.map)
    print(f"VMware: {result.get('esxi_hosts',0)} ESXi hosts, {result.get('vms',0)} VMs ({result.get('vms_with_ip',0)} with IP). saved {args.map}")
    return 0


def cmd_serve(args) -> int:
    from .api import serve

    inv = _load_map(args.map)
    srv = serve(inv, host=args.bind, port=args.port, token=args.token)
    log.info("serving %s at http://%s:%d/ (Ctrl-C to stop)%s", args.map, args.bind, args.port, " [token required]" if args.token else "")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
        log.info("stopped")
    return 0


def cmd_inspect(args) -> int:
    from .hostinfo import inspect_hosts

    inv = _load_map(args.map)
    creds = {}
    if args.linux_user or args.linux_key:
        creds["linux"] = {"username": args.linux_user or "", "password": args.linux_pass or "", "key_filename": args.linux_key}
    if args.win_user:
        creds["windows"] = {"username": args.win_user, "password": args.win_pass or "", "transport": "ntlm"}
    if not creds:
        log.error("give --linux-user/--linux-key and/or --win-user")
        return 2
    # authenticated inspection stays inside the same ranges as every other step
    cfg = load_config(getattr(args, "config", None))
    scope, exclude = scope_from(args, cfg)
    result = asyncio.run(inspect_hosts(inv, creds, scope=scope, exclude=exclude))
    inv.save(args.map)
    for ip, msg in (result.get("host_key_changed") or {}).items():
        log.warning("HOST KEY CHANGED for %s: %s", ip, msg)
    if result.get("skipped"):
        log.info("%d host(s) skipped (out of scope, appliance role, or no open SSH/WinRM port)", result["skipped"])
    print(f"inspected {result.get('ok', 0)} host(s): {result.get('linux', 0)} Linux, {result.get('windows', 0)} Windows, {result.get('failed', 0)} failed. saved {args.map}")
    return 0


def cmd_capture(args) -> int:
    import getpass

    from .capture import capture_config, store_config

    inv = _load_map(args.map)
    ids = args.device or sorted(inv.devices)
    pw = args.password if args.password is not None else (getpass.getpass("SSH password: ") if not args.key else "")
    ok = changed = 0
    for did in ids:
        dev = inv.devices.get(did)
        if dev is None:
            log.warning("%s is not a device in the map", did)
            continue
        cap = capture_config(did, args.user, pw, os_family=dev.os_family, vendor=dev.vendor, port=args.port, key_filename=args.key)
        if cap.ok:
            ok += 1
            changed += 1 if store_config(inv, did, cap) else 0
            log.info("%s: captured%s", dev.name or did, " (changed)" if inv.configs[did][-1]["sha"] != (inv.configs[did][-2]["sha"] if len(inv.configs[did]) > 1 else None) else "")
        else:
            log.warning("%s: %s", dev.name or did, cap.error)
    inv.save(args.map)
    print(f"captured {ok} of {len(ids)} device(s); {changed} changed. saved {args.map}")
    return 0


def cmd_check(args) -> int:
    from .reconcile import guess_columns, read_table, reconcile, write_csv

    inv = _load_map(args.map)
    headers, rows = read_table(args.assets)
    cols = guess_columns(headers)
    if not cols:
        log.error("%s: no column looks like an address, name, serial or MAC (headers: %s)", args.assets, headers)
        return 2
    log.info("matching on %s", ", ".join(f"{f}={headers[i]!r}" for f, i in cols.items()))
    rec = reconcile(inv, rows, cols)
    print(f"{len(rec.matches)} listed: {len(rec.found)} found, {len(rec.differ)} found but different, {len(rec.missing)} not found; "
          f"{len(rec.unlisted)} devices on the network are not in the list")
    for title, items in (("NOT FOUND", rec.missing), ("DIFFERENT", rec.differ)):
        if items:
            print(f"\n{title}")
            for m in items:
                print(f"  {m.listed.get('name') or m.listed.get('ip') or m.listed.get('serial', '')!s:30} {'; '.join(m.differences)}")
    if rec.unlisted:
        print("\nNOT IN THE LIST")
        for did in rec.unlisted:
            d = inv.devices[did]
            print(f"  {did:16} {d.name:28} {d.vendor} {d.model} {d.serial}")
    if args.csv:
        write_csv(inv, rec, args.csv)
        log.info("wrote %s", args.csv)
    return 0


def _add_output_args(p, html_default=None):
    p.add_argument("--html", default=html_default, help="write interactive HTML map")
    p.add_argument("--graphml", help="write GraphML for graph editors and analysis tools")
    p.add_argument("--dot", help="write Graphviz DOT")
    p.add_argument("--csv", help="write CSV inventory files with this prefix, e.g. out/site-")
    p.add_argument("--xlsx", help="write a multi-sheet .xlsx inventory workbook (devices, IPAM, VLANs, links, hosts, gaps)")
    p.add_argument("--drawio", help="write a draw.io diagram (physical and logical pages; opens in diagrams.net and converts to .vsdx)")
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
    p = argparse.ArgumentParser(prog="netmap", description="Inventory a network over SNMP (LLDP/CDP, routes, ARP, MAC tables, VLANs, hardware) and map its topology.")
    p.add_argument("--version", action="version", version=f"netmap {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info (default), -vv debug")
    p.add_argument("-q", "--quiet", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    cr = sub.add_parser("crawl", help="spider the network starting from seed devices")
    cr.add_argument("--seed", "-s", action="append", metavar="IP", help="starting device (core switch/router) to spider from. Repeatable. Optional if --target is given")
    cr.add_argument("--community", "-C", action="append", metavar="STR", help="SNMPv2c community to try (repeatable, tried in order). 'env:VAR' reads it from that environment variable so it stays out of shell history")
    cr.add_argument("--v1-community", action="append", metavar="STR", help="SNMPv1 community to try, for agents that only speak v1 (repeatable; 'env:VAR' form accepted)")
    cr.add_argument("--v3-user", help="SNMPv3 user name")
    cr.add_argument("--v3-auth", default="SHA", help="v3 authentication protocol: MD5, SHA, SHA224, SHA256, SHA384, SHA512 or NONE (default SHA)")
    cr.add_argument("--v3-auth-key", help="v3 authentication passphrase; 'env:VAR' reads it from that environment variable")
    cr.add_argument("--v3-priv", default="AES", help="v3 privacy protocol: DES, 3DES, AES, AES192, AES256 or NONE (default AES)")
    cr.add_argument("--v3-priv-key", help="v3 privacy passphrase (needs --v3-auth-key too); 'env:VAR' reads it from that environment variable")
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
    cr.add_argument("--repeat", type=int, metavar="SECONDS", help="keep rescanning on this interval (Ctrl-C to stop); implies --resume --refresh")
    cr.add_argument("--refresh", action="store_true", help="with --resume, poll devices already in the map again and replace what was collected (notes and layout are kept)")
    cr.add_argument("--retry-unreachable", action="store_true", help="with --resume, try again addresses that did not answer SNMP last time")
    cr.add_argument("--dns", action="store_true", help="name devices and hosts from reverse DNS (PTR) lookups")
    cr.add_argument("--identify", action="store_true", help="actively identify hosts by profiling them (NetBIOS, mDNS, SSDP, HTTP/TLS probes)")
    cr.add_argument("--port-scan", action="store_true", help="nmap service-version scan of every device and host found (open ports, service detail)")
    cr.add_argument("--os", dest="os_detect", action="store_true", help="nmap OS detection (-O; needs root/Administrator)")
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

    df = sub.add_parser("diff", help="what changed between two scans of the same network")
    df.add_argument("old", help="earlier map / project")
    df.add_argument("new", help="later map / project")
    df.add_argument("--csv", help="also write the changes to this CSV file")

    rc_ = sub.add_parser("check", help="compare a project with an asset list (CSV/XLSX) you were given")
    rc_.add_argument("--map", "-m", default="netmap.json")
    rc_.add_argument("assets", help="CSV or .xlsx file listing the devices that should be there")
    rc_.add_argument("--csv", help="write the comparison to this CSV file")

    cap = sub.add_parser("capture", help="capture device running-configs over SSH (read-only) and store them in the map")
    cap.add_argument("--map", "-m", default="netmap.json")
    cap.add_argument("--user", "-u", required=True, help="SSH username")
    cap.add_argument("--password", "-P", help="SSH password (omit to be prompted)")
    cap.add_argument("--key", help="SSH private key file")
    cap.add_argument("--port", type=int, default=22)
    cap.add_argument("--device", action="append", help="only capture this device IP (repeatable); default: all in the map")

    ins = sub.add_parser("inspect", help="collect OS/hardware/software/connections from hosts over SSH (Linux) and WinRM (Windows)")
    ins.add_argument("--map", "-m", default="netmap.json")
    ins.add_argument("--linux-user"), ins.add_argument("--linux-pass"), ins.add_argument("--linux-key")
    ins.add_argument("--win-user"), ins.add_argument("--win-pass")
    ins.add_argument("--config", "-c", help="netmap.toml with [crawl] scope/exclude")
    ins.add_argument("--scope", action="append", metavar="CIDR", help="only inspect hosts inside these networks (repeatable). Default: RFC1918")
    ins.add_argument("--exclude", action="append", metavar="CIDR", help="never inspect these networks (repeatable)")

    vm = sub.add_parser("vmware", help="read-only VMware vCenter/ESXi discovery folded into the map")
    vm.add_argument("--map", "-m", default="netmap.json")
    vm.add_argument("--host", required=True), vm.add_argument("--user", required=True), vm.add_argument("--password")
    vm.add_argument("--port", type=int, default=443), vm.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (self-signed vCenter)")

    sv = sub.add_parser("serve", help="serve a read-only REST API over a saved map (JSON + the query language)")
    sv.add_argument("--map", "-m", default="netmap.json")
    sv.add_argument("--bind", default="127.0.0.1"), sv.add_argument("--port", type=int, default=8088), sv.add_argument("--token", default="")

    gu = sub.add_parser("gui", help="open the desktop app (needs the 'gui' extra: pip install netmap[gui])")
    gu.add_argument("project", nargs="?", help="project to open")
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
        inv = _load_map(args.map)
        print(text_summary(inv, build_graph(inv)))
        rc = 0
    elif args.cmd == "diff":
        rc = cmd_diff(args)
    elif args.cmd == "check":
        rc = cmd_check(args)
    elif args.cmd == "capture":
        rc = cmd_capture(args)
    elif args.cmd == "inspect":
        rc = cmd_inspect(args)
    elif args.cmd == "serve":
        rc = cmd_serve(args)
    elif args.cmd == "vmware":
        rc = cmd_vmware(args)
    elif args.cmd == "gui":
        try:
            from .gui.app import main as gui_main
        except ImportError as e:
            log.error("the desktop app needs PySide6: pip install 'netmap[gui]' (%s)", e)
            sys.exit(2)
        sys.exit(gui_main([args.project] if args.project else []))
    else:
        rc = 2
    sys.exit(rc)
