# netmap

Inventory a network you did not build and come back with a topology.

`netmap` reads devices over SNMP and works out how they are wired together: LLDP and CDP adjacencies,
routing next-hops, subnet gateways, bridge tables and ARP. The result is an inventory (devices,
interfaces, VLANs, subnets, addresses in use, hosts) plus a typed graph of Layer-2 links, Layer-3
adjacencies, subnet membership and host-to-switch-port placement, rendered as an interactive HTML map and
exported to Excel, GraphML, DOT and CSV.

It was written for M&A due diligence: you get read-only SNMP credentials, a list of ranges you may touch,
you need a picture of what is actually there, and you must not wander outside those ranges.

**Point it at a network in either of two ways, or both at once:**

| | |
|---|---|
| **Targeted subnets** — you were given a list of ranges | `netmap crawl --target 10.20.0.0/24 --target 10.30.0.0/24` or `--target-file ranges.txt`. Every live address in those subnets is probed for SNMP; whatever answers is inventoried and whatever does not is still recorded as a host. The targets become the scope, so nothing outside them is touched. |
| **Spider from a seed** — you were given a core device | `netmap crawl --seed 10.10.0.1 --scope 10.10.0.0/16`. netmap follows LLDP/CDP neighbours, route next-hops and subnet gateways outwards, staying inside `--scope`. |

On Windows, [download `netmap.exe`](https://github.com/kerbe42/netmap/releases/latest) — one file, no
Python, no installer.

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

Every MAC address is matched against a bundled copy of the IEEE OUI registry, so a host known only from an
ARP table is still attributed to an organization and typed. That works offline and without `nmap`, and it is
usually what turns a bare address into "a Zebra label printer" or "a Synology NAS". Device types assigned:
router, l3switch, switch, firewall, wireless, server, vm, database, windows, workstation, printer, phone,
camera, nas, ups, host, and `unpolled` for something a neighbour announced that we could not get into.

## Install

```bash
cd netmap
python3 -m venv .venv && .venv/bin/pip install -e .
sudo apt install nmap          # optional, for --sweep (ARP/ICMP discovery needs root)
```

Requires Python 3.11+. Dependencies: `pysnmp`, `cryptography` (SNMPv3 privacy), `networkx`.

### Windows: the single executable

Download **`netmap.exe`** from the [latest release](https://github.com/kerbe42/netmap/releases/latest).
It is one self-contained file — Python, pysnmp, the OUI table and the map viewer are all inside it. Nothing
is installed, nothing is left behind, and it runs from a USB stick or a jump-box desktop:

```powershell
cd $env:USERPROFILE\Desktop
$env:NETMAP_COMMUNITY = 'their-ro-string'
.\netmap.exe crawl --target-file ranges.txt -C $env:NETMAP_COMMUNITY `
             --out acme.json --html acme.html --xlsx acme.xlsx
```

Verify the download against `SHA256SUMS.txt` on the release page:
`Get-FileHash .\netmap.exe -Algorithm SHA256`.

Notes for running it in the field:

* **Nmap is optional.** Without it, `--target` falls back to ICMP ping for host discovery and `--sweep`
  cannot fingerprint services; SNMP, LLDP/CDP, ARP, routing and the OUI-based typing all work regardless.
  With `--probe-all` no pinging happens at all. To get MAC addresses and service detail on sweeps, install
  [Nmap for Windows](https://nmap.org/download.html) and accept the bundled **Npcap** installer.
* **Run as Administrator** for `--sweep` and `--fingerprint` so nmap can use ARP and ICMP; unprivileged it
  falls back to TCP connect pings and finds fewer hosts.
* Windows Defender Firewall does not block outbound SNMP, but a corporate endpoint agent might. If
  everything times out, try one device with `--target 10.10.0.1/32 --probe-all -vv` and see whether replies
  arrive at all.
* SmartScreen may warn on a binary this new and unsigned — the release is built by the GitHub Actions
  workflow in this repo, and the checksums come from that run.
* WSL2 works too, but its NAT-ed network hides ARP, so prefer the native `.exe` for sweeps.

Prefer to run from source on Windows? Install Python 3.11+ (tick **Add python.exe to PATH**), then from the
folder holding `pyproject.toml`:

```powershell
py -m venv .venv
.venv\Scripts\pip install -e .
.venv\Scripts\netmap crawl --target-file ranges.txt -C $env:NETMAP_COMMUNITY --out acme.json --html acme.html
```

### Building the executable yourself

```bash
pip install -e . pyinstaller
pyinstaller netmap.spec          # -> dist/netmap  (or dist\netmap.exe on Windows)
```

The spec is the same on both platforms. A Windows `.exe` has to be built on Windows: pushing a tag runs
`.github/workflows/build.yml`, which builds both, smoke-tests each frozen binary and attaches them to the
release with checksums.

## Quick start

```bash
export NETMAP_COMMUNITY='their-ro-string'

# You were handed a list of ranges: inventory exactly those and nothing else.
netmap crawl --target 10.20.0.0/24 --target 10.30.0.0/24 --community "$NETMAP_COMMUNITY" \
             --out acme.json --html acme.html --xlsx acme.xlsx

# The same list, from a file (one subnet per line, '#' comments allowed).
netmap crawl --target-file ranges.txt -C "$NETMAP_COMMUNITY" --out acme.json --xlsx acme.xlsx

# ICMP is filtered: skip the ping and try SNMP on every address in the targets.
netmap crawl --target 10.20.0.0/24 --probe-all -C "$NETMAP_COMMUNITY" --out acme.json

# You were handed a core switch instead: spider outwards, bounded by --scope.
netmap crawl --seed 10.10.0.1 --scope 10.10.0.0/16 --community "$NETMAP_COMMUNITY" \
             --out acme.json --html acme.html --csv out/acme-
```

`ranges.txt` is meant to take the range list as it arrives — one subnet or address per line, or several
separated by commas, with `#` comments:

```
# Acme HQ, agreed 2026-09-20
10.20.0.0/24      # user VLANs
10.30.0.0/24, 10.31.0.0/24
192.168.5.10      # the one server in the DMZ we may touch
```

Then open `acme.html`. Toggle hosts and FDB links on, search by name/IP/MAC/serial, click anything for
details, export a PNG. The JSON file is the source of truth and is written after every device, so a crawl
that is interrupted can be continued with `--resume`.

For anything real, use a config file (see `netmap.toml.example`) so scope, exclusions and SNMPv3 credentials
are explicit and reviewable:

```bash
netmap crawl -c acme.toml --sweep --fingerprint --out acme.json --html acme.html --xlsx acme.xlsx --csv out/acme- --graphml acme.graphml
netmap show  -m acme.json               # text summary: devices, links, VLANs, IPAM, unpolled neighbours
netmap render -m acme.json --xlsx acme.xlsx --dot acme.dot   # rebuild outputs without re-crawling
netmap sweep -m acme.json --subnet 10.10.50.0/24 --fingerprint  # sweep one more subnet later
```

## Scope and safety

* Nothing outside `--scope` is ever sent a packet. `--target` subnets are added to the scope, and when no
  `--scope` is given they *are* the scope — so naming your ranges is enough to stay inside them. With
  neither, the crawl is limited to RFC1918 space and says so. `--exclude` always wins, including inside a
  target. Loopback, link-local, multicast and 0/8 are never probed.
* `--probe-all` is capped by `--sweep-max-size` (default /22) so a mistyped prefix cannot turn into tens of
  thousands of probes; it refuses the subnet and says so rather than proceeding.
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
| `*.xlsx` | Excel workbook, the hand-over artefact: Summary, Devices, IPAM, VLANs, Links, Hosts, Interfaces, Gaps |
| `<prefix>devices.csv` | one row per device: role, vendor, model, serial, IPs, counts, credential used |
| `<prefix>links.csv` | L2/L3 links with both port names |
| `<prefix>hosts.csv` | every host: IP, name, MAC, vendor, role, subnet, switch, port, VLAN, open ports |
| `<prefix>ipam.csv` | per-subnet address accounting: size, usable, in use, free, utilisation %, VLAN, gateways |
| `<prefix>vlans.csv` | VLAN id, every name seen for it, and which devices carry it |
| `<prefix>subnets.csv` | subnets with gateways and host counts |
| `<prefix>interfaces.csv` | every interface on every device |

The **IPAM** numbers count addresses actually observed in use — device interfaces, ARP and bridge-table
entries, sweep replies — so utilisation is evidence, not an estimate. A subnet that was never swept is
flagged, because its count is a floor rather than a total.

The workbook's **Gaps** sheet is the one to read first on a due-diligence job. It lists neighbours that were
announced but never polled (no credentials, or outside the handover), addresses that were probed and never
answered, and subnets whose utilisation cannot be trusted yet — which is usually where the undocumented part
of the estate turns out to be.

`examples/` holds the output of a crawl against the simulated lab used by the tests.

## Suggested M&A workflow

1. Get from the target: read-only SNMP (v3 preferred), the address plan they believe in, two or three core
   device addresses, and a written list of ranges you may and may not touch. Put the ranges in
   `ranges.txt` and the rest in the TOML.
2. Run from a VM or jump host inside their network — SNMP is almost always filtered at the edge.
3. Prove the credentials on one subnet before doing anything wide:
   `netmap crawl --target 10.20.0.0/24 -C "$NETMAP_COMMUNITY" --out probe.json`.
4. Then the real pass: `netmap crawl -c acme.toml --target-file ranges.txt --sweep --fingerprint
   --out acme.json --html acme.html --xlsx acme.xlsx`. Add `--seed` for their core devices as well, so
   LLDP/CDP fills in the wiring between the ranges.
5. Read the **Gaps** sheet and the IPAM table against what they told you. The interesting findings are the
   discrepancies: subnets with no known gateway, neighbours nobody has credentials for, devices whose
   sysDescr does not match the asset list, ARP entries from ranges that are not in the plan at all, and
   subnets they described as full that are 4% used.
6. Add `--probe-hosts` to find SNMP-speaking APs, printers, UPSs and servers that no switch announces.
7. Re-run later with `--resume` to pick up devices that were down, and diff the JSON.

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
