# netmap

Spider a network you did not build and come back with a topology.

`netmap` starts from one or more seed devices (a core switch or router), reads them over SNMP, and follows
what they know about their neighbours: LLDP and CDP adjacencies, routing next-hops, subnet gateways, and
optionally every address in their ARP tables. Each device found is polled the same way until the scope is
exhausted. The result is an inventory (devices, interfaces, VLANs, subnets, hosts) plus a typed graph of
Layer-2 links, Layer-3 adjacencies, subnet membership and host-to-switch-port placement, rendered as an
interactive HTML map and exported to GraphML/DOT/CSV.

It was written for M&A due diligence: you get read-only SNMP credentials and a couple of core addresses,
you need a picture of what is actually there, and you must not wander outside the agreed ranges.

## What it collects per device

| Source (SNMP) | Gives you |
|---|---|
| system group, ENTITY-MIB | name, description, vendor, model, serial, location, uptime |
| IF-MIB, ipAddrTable | interfaces, speeds, MACs, descriptions, IPs and subnets |
| LLDP-MIB, CISCO-CDP-MIB | Layer-2 links, with local and remote port names and neighbour mgmt addresses |
| ipCidrRouteTable / ipRouteTable | routes and next-hops (Layer-3 adjacency, new subnets to explore) |
| ipNetToMediaTable | ARP: every IP/MAC the device has talked to |
| BRIDGE-MIB / Q-BRIDGE-MIB | MAC forwarding table: which switch port each host sits on, per VLAN |
| Q-BRIDGE / CISCO-VTP-MIB | VLAN ids and names |

Hosts that do not speak SNMP still appear: from ARP, from LLDP/CDP announcements (phones, APs), and from an
optional `nmap` ping sweep of every discovered subnet with light service fingerprinting.

## Install

```bash
cd netmap
python3 -m venv .venv && .venv/bin/pip install -e .
sudo apt install nmap          # optional, for --sweep (ARP/ICMP discovery needs root)
```

Requires Python 3.11+. Dependencies: `pysnmp`, `cryptography` (SNMPv3 privacy), `networkx`.

### Windows

1. Install Python 3.11+ from https://www.python.org/downloads/windows/ and tick **Add python.exe to PATH**.
2. Install Nmap for Windows from https://nmap.org/download.html (accept the bundled **Npcap** installer;
   it is what lets nmap do ARP/ICMP sweeps). Optional, but `--sweep` needs it.
3. Copy the `netmap` folder (or just `dist/netmap-*.whl` plus `netmap.toml.example`) to the PC. The
   release `netmap-src.zip` unpacks into its own `netmap\` folder, so extracting it to `C:\netmap` puts
   the project at `C:\netmap\netmap`. Run the steps below from the folder that contains `pyproject.toml`
   (if pip says "neither setup.py nor pyproject.toml found", you are one level too high). Then in PowerShell:

```powershell
cd C:\netmap\netmap                     # the folder with pyproject.toml in it
py -m venv .venv
.venv\Scripts\pip install -e .          # or: .venv\Scripts\pip install dist\netmap-0.1.0-py3-none-any.whl
$env:NETMAP_COMMUNITY = 'their-ro-string'
.venv\Scripts\netmap crawl --seed 10.10.0.1 --scope 10.10.0.0/16 -C $env:NETMAP_COMMUNITY --out acme.json --html acme.html
```

Run PowerShell **as Administrator** when using `--sweep` so nmap can use ARP and ICMP; unprivileged it
falls back to TCP pings. Windows Defender Firewall does not block outbound SNMP, but a corporate endpoint
agent might; if every device times out, run a single seed with `--max-depth 0 -vv` and check whether
replies arrive. WSL2 also works, but its NAT-ed network hides ARP, so prefer native Python for sweeps.

## Quick start

```bash
export NETMAP_COMMUNITY='their-ro-string'
netmap crawl --seed 10.10.0.1 --scope 10.10.0.0/16 --community "$NETMAP_COMMUNITY" \
             --out acme.json --html acme.html --csv out/acme-
```

Then open `acme.html`. Toggle hosts and FDB links on, search by name/IP/MAC/serial, click anything for
details, export a PNG. The JSON file is the source of truth and is written after every device, so a crawl
that is interrupted can be continued with `--resume`.

For anything real, use a config file (see `netmap.toml.example`) so scope, exclusions and SNMPv3 credentials
are explicit and reviewable:

```bash
netmap crawl -c acme.toml --sweep --fingerprint --out acme.json --html acme.html --csv out/acme- --graphml acme.graphml
netmap show  -m acme.json               # text summary: devices, links, subnets, unpolled neighbours
netmap render -m acme.json --html acme.html --dot acme.dot   # rebuild outputs without re-crawling
netmap sweep -m acme.json --subnet 10.10.50.0/24 --fingerprint  # sweep one more subnet later
```

## Scope and safety

* Nothing outside `--scope` is ever sent a packet. With no scope given the crawl is limited to RFC1918
  space and says so. `--exclude` always wins. Loopback, link-local, multicast and 0/8 are never probed.
* Everything is read-only: SNMP GET/GETBULK, ICMP/TCP pings and, with `--fingerprint`, a top-25-port
  connect scan of hosts that answered the sweep. No SNMP SET, no exploitation, no credential guessing beyond
  the list you supply.
* Credentials are tried in the order given; the first that works on a device is recorded by label in the
  inventory so you can see which population uses the legacy string. Put secrets in environment variables
  (`env:NAME` in the config) rather than in the file.
* Rate: `--workers` devices in parallel, one SNMP walk at a time per device, GETBULK with 25 repetitions.
  Lower `--workers` for fragile gear. Sweeps run four subnets at a time.

## How the graph is built

* **Device nodes** are things that answered SNMP. Identity is by management IP, but a box reached again via
  another of its addresses is merged, not duplicated.
* **LLDP/CDP edges** are matched to a known device by neighbour management address, chassis MAC, or system
  name (domain-stripped). One edge per port pair, whichever side reported it, with port names normalised
  (`GigabitEthernet1/0/2` = `Gi1/0/2`). A neighbour we could not poll becomes a grey *unpolled* stub, or,
  if its MAC/IP shows up in an ARP table, is attached to that host and typed from its LLDP capabilities
  (AP, phone, router, bridge).
* **L3 edges** connect a device to the device owning its route next-hop, labelled with the route count.
  They are suppressed where an L2 link already exists between the pair.
* **Subnet nodes** come from interface addresses; devices and hosts are members.
* **FDB edges** place a host on the access port where its MAC was learned. Ports carrying an LLDP/CDP
  neighbour or more than 8 MACs are treated as uplinks and skipped.
* **Host roles** come from LLDP capabilities, nmap MAC vendor and open ports (printer, phone, camera,
  windows, server, database, vm, workstation).

## Outputs

| File | Contents |
|---|---|
| `*.json` | full inventory; input for `render`, `show`, `sweep`, `--resume` |
| `*.html` | self-contained interactive map (vis-network embedded; works offline) |
| `*.graphml` | for yEd / Gephi / Cytoscape; every attribute carried as a property |
| `*.dot` | Graphviz: `dot -Tsvg map.dot > map.svg` or `sfdp` for big maps |
| `<prefix>devices.csv` | one row per device: role, vendor, model, serial, IPs, counts, credential used |
| `<prefix>links.csv` | L2/L3 links with both port names |
| `<prefix>hosts.csv` | every host: IP, name, MAC, vendor, role, subnet, switch, port, VLAN, open ports |
| `<prefix>subnets.csv` | subnets with gateways and host counts |
| `<prefix>interfaces.csv` | every interface on every device |

`examples/` holds the output of a crawl against the simulated lab used by the tests.

## Suggested M&A workflow

1. Get from the target: read-only SNMP (v3 preferred), the address plan they believe in, two or three core
   device addresses, and a written list of ranges you may and may not touch. Put all of it in the TOML.
2. Run from a jump host inside their network (SNMP is usually filtered at the edge). Start with a shallow
   crawl (`--max-depth 2`, no sweep) to confirm credentials and scope, then go deep.
3. Compare `subnets.csv` and the unpolled-neighbour list in `netmap show` against what they told you. Gaps
   are the interesting part: subnets with no known gateway, neighbours nobody has credentials for, devices
   whose sysDescr does not match the asset list, ARP entries from ranges outside the plan.
4. Add `--sweep --fingerprint` for a host census; `--probe-hosts` to discover SNMP-speaking APs, printers,
   UPSs and servers that are not in LLDP.
5. Re-run later with `--resume` to pick up devices that were down, and diff the JSON.

## Limits

* IPv4 only. IPv6 addresses and routes are not collected yet.
* Routes are read from the default routing table; VRFs are not enumerated.
* Cisco IOS per-VLAN bridge tables need `--cisco-vlan-fdb` (community@vlan indexing, or `vlan-N` contexts
  for v3). Q-BRIDGE-capable devices (IOS-XE, NX-OS, Junos, Arista, HP/Aruba) work without it.
* LLDP neighbours that advertise no management address and never appear in an ARP table stay as stubs.
* Devices behind NAT, or that answer SNMP on a non-standard port, need separate seeds/`--port`.

## Testing

```bash
.venv/bin/pip install pytest snmpsim pysmi
.venv/bin/python -m pytest -q
```

`tests/labnet.py` defines a simulated three-tier network (Cisco ISR, Catalyst 3850, HP 2530 plus an AP, a
phone, an out-of-scope firewall and a few hosts) as raw OID tables. The unit tests run the crawler against
an in-memory SNMP stand-in; the end-to-end tests serve the same data with `snmpsim` on loopback and drive
the real CLI over SNMPv2c and SNMPv3. Set `NETMAP_ALLOW_LOOPBACK=1` to crawl simulators bound on 127/8.
