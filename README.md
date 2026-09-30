# NetMap

Inventory a network you look after — especially one you did not build — and see how it is wired.

NetMap reads the network's own devices over SNMP (read-only) and works out what is there and how it
connects: LLDP and CDP neighbours, routing tables, ARP and MAC address tables, VLANs, interfaces and
hardware. The result is an inventory (devices, hosts, subnets, VLANs, links, interfaces, serial numbers)
and a topology diagram, which you can document as you go, keep current with rescans, and export to
Excel, draw.io/Visio, PDF or CSV.

It comes as a **Windows desktop app** and as a **command-line tool** that share one project file.

![Overview](docs/screenshots/overview.png)

## Download

From the [latest release](https://github.com/kerbe42/netmap/releases/latest):

| File | What it is |
|---|---|
| `NetMap-<version>-setup.exe` | The desktop app, installed for your user account (no administrator rights needed). Start menu entry, optional desktop shortcut, opens `.netmap` files. |
| `NetMap-<version>-portable.zip` | The same app as a folder: unzip anywhere (a USB stick, a jump host) and run `NetMap.exe`. Keeps its settings in that folder. |
| `netmap.exe` | The command line as a single file, no Python needed. |
| `netmap-linux-x64` | The command line for Linux. |

Check a download against `SHA256SUMS.txt`: `Get-FileHash .\NetMap-0.3.0-setup.exe -Algorithm SHA256`.
The binaries are built by this repository's GitHub Actions workflow and are not code-signed, so SmartScreen
may ask for confirmation the first time.

To see what NetMap does before pointing it at anything, open **Help ▸ Explore the sample network**: a
simulated campus with a firewall, a core pair, floor and warehouse switches, a server room and about 500
endpoints.

## The desktop app

### 1. Credentials

**Scan ▸ SNMP credentials**: add the read-only SNMPv2c community or SNMPv3 user (SHA/SHA-2 and AES) for
the devices, and use *Test against a device* to check one. Credentials are tried in order on every
device and the one that worked is recorded against it. Secrets are encrypted with your Windows account
(DPAPI) and are never written into project files, so a project can be handed to someone else safely.

### 2. Scan

**Scan ▸ New scan** (Ctrl+R):

* **Address ranges to inventory** — the subnets you are responsible for, pasted as they come: CIDR,
  single addresses, or ranges like `10.20.0.10-60`, one per line or comma separated. Every live address in
  them is checked.
* **Start from devices** (optional) — a core switch or router. NetMap follows LLDP/CDP neighbours, routing
  next-hops and subnet gateways outwards from it.
* **Never touch** — ranges that must not be sent anything (OT, medical, partner links).

Nothing outside the ranges you gave is ever contacted; the dialog shows exactly what will be before you
start. If ping is blocked, choose *Query every address with SNMP*. Tick *Ping-sweep every subnet* for exact
address counts, and *Name devices and hosts from reverse DNS* to pick up PTR names.

Results appear while the scan runs. **Stop** keeps everything found so far. When the project has been
saved, it is saved again automatically at the end of every scan.

### 3. Understand it

**Topology map** — two views of the same network:

* **Physical** — what is cabled to what, from LLDP/CDP: firewalls and routers on top, then the core, then
  access switches, access points and anything announced but not polled. Turn on *Hosts* to see every
  endpoint on the switch port it is plugged into.
* **Logical** — how it routes: routers, L3 switches and firewalls with the subnets they have addresses in,
  each labelled with its VLAN.

![Physical map](docs/screenshots/map-physical.png)

Drag devices to tidy the diagram; positions are saved in the project for each view. Right-click a device
to focus on its neighbourhood, open its web page, SSH to it, ping it or rescan it. Port names are shown at
both ends of every cable. *Layout* switches between layered, organic and radial arrangements.

![Logical map](docs/screenshots/map-logical.png)

**Lists** — network devices, hosts (with the switch, port and VLAN each one is on), subnets with an IP
address map, VLANs (with every name each switch gives them), links with speeds at both ends, every
interface (status, speed, VLAN, access/trunk, LAG, neighbour, MACs learned), and hardware: chassis, stack
members, modules, power supplies, fans and transceivers with serial numbers. Filter any list with words, or
`column:value` — `role:switch vendor:cisco`, `vlan:20`, `status:down`. Select anything for its details.

![Device details](docs/screenshots/device.png)

![Subnet IP map](docs/screenshots/subnet.png)

![Hosts on their switch ports](docs/screenshots/map-hosts.png)

**Needs attention** — what to look at before relying on the inventory:

| Finding | Usually means |
|---|---|
| Neighbour not polled | A switch, router or AP announces itself over LLDP/CDP but no credential works: unmanaged, or missing from the handover |
| Link speed mismatch | The two ends of one cable report different speeds: a negotiation problem or a wrong patch |
| VLAN named differently | Switches disagree on what a VLAN is for |
| Address seen with several MACs | A first-hop redundancy address, a recent hardware swap, or an address conflict |
| Subnet with no gateway found | The router for a range you listed was not reached |
| Address outside every known subnet | In use, but in no subnet any device reported: missing from the address plan |
| Starting device did not answer | A device you named as a starting point: wrong address or credentials, or SNMP filtered |
| Next-hop router not polled | Traffic is routed through it but no credential worked |
| Device stopped answering | It answered before and was silent on the last rescan |
| Subnet not swept | Its utilisation is a floor, not a count |

![Needs attention](docs/screenshots/findings.png)

### 4. Document it

Select a device, host, subnet or VLAN and open the **Notes** tab in the details panel: name, role, site,
owner, asset tag, status (*Verified*, *Needs review*, *Unknown owner*, *To be replaced*, …), tags and free
notes. They are saved in the project, never overwritten by a rescan, shown on the map and in the lists,
and included in the Excel export. A role you set corrects a wrong automatic guess everywhere.

### 5. Keep it current

* **F5** re-polls every known device and follows any new links.
* Right-click a device ▸ *Rescan this device*, or a subnet ▸ *Find every live address in this subnet*.
* **Tools ▸ Compare with another scan** lists devices added, removed, moved (same serial, new address) or
  changed (model, serial, OS version, ports up/down, reboots), links and VLANs added or removed, and hosts
  that appeared, vanished or changed MAC address.
* **Scan history** records every scan: what was asked, how long it took, what it found.
* **Tools** (bottom panel): ping, traceroute, DNS (with a forward/reverse consistency check) and an SNMP
  test against any address.

### 6. Share it

**File ▸ Export**:

| Export | Contents |
|---|---|
| Excel workbook | Summary, Devices, IPAM, VLANs, Links, Hosts, Interfaces, Hardware and Gaps sheets, with your notes |
| draw.io diagram | Physical and logical pages with your layout, Cisco-style icons and port labels. Opens in [diagrams.net](https://app.diagrams.net) (desktop or web), which can save it as Visio `.vsdx` |
| Map as PDF / SVG / PNG / Print | The current view as you arranged it |
| Interactive HTML map | One offline web page anyone can open in a browser |
| CSV files, GraphML, DOT | For scripts, yEd/Gephi, Graphviz |

Every list also exports what it shows (after filtering) with *Export CSV*, and Ctrl+C copies the selected
rows in a form that pastes straight into Excel.

### Settings and files

* The project (`.netmap`) is a single JSON file holding the inventory, your notes, map layouts and scan
  history — never credentials.
* Settings live in the registry under `HKCU\Software\netmap\NetMap`, or beside the program in the portable
  build. The log is `%LOCALAPPDATA%\NetMap\netmap.log` (**Help ▸ Open the log folder**).
* **View ▸ Theme**: follow Windows, light or dark.

![Dark theme](docs/screenshots/dark.png)

## What it collects per device

| Source (SNMP) | Gives you |
|---|---|
| system group | name, description, vendor, OS version, location, contact, uptime |
| ENTITY-MIB | model and serial, plus stack members, modules, power supplies, fans and transceivers with serials, revisions and FRU flag |
| IF-MIB, ipAddrTable | interfaces, speeds, MACs, descriptions, last status change, IPs and subnets |
| LLDP-MIB, CISCO-CDP-MIB | Layer-2 links, with local and remote port names and neighbour management addresses |
| ipCidrRouteTable / ipRouteTable | routes and next-hops (Layer-3 adjacency, new subnets to explore) |
| ipNetToMediaTable | ARP: every IP/MAC the device has talked to |
| BRIDGE-MIB / Q-BRIDGE-MIB | MAC forwarding table: which switch port each host sits on, per VLAN |
| Q-BRIDGE / CISCO-VTP-MIB | VLAN ids and names |
| Q-BRIDGE / CISCO-VLAN-MEMBERSHIP-MIB | each switch port's access or native VLAN, and whether it is a trunk |
| IEEE8023-LAG-MIB | which ports are bundled into which LAG / port-channel |

Hosts that do not speak SNMP still appear: from ARP, from LLDP/CDP announcements (phones, APs), from
reverse DNS, and from an optional `nmap` ping sweep with light service identification.

Every MAC address is matched against a bundled copy of the IEEE OUI registry, so a host known only from an
ARP table is still attributed to a manufacturer and typed, offline and without `nmap`. Types assigned:
router, l3switch, switch, firewall, wireless, server, vm, database, windows, workstation, printer, phone,
camera, nas, ups, host, and *unpolled* for something a neighbour announced that could not be polled. An
access switch is only called an L3 switch with evidence that it routes (addresses on more than one
interface, or learned routes), not because sysServices says so.

## Identifying hosts (profiling)

For endpoints that don't answer SNMP, NetMap profiles them from many weak signals weighed together, with
the evidence kept. Turn on **Identify hosts** in the scan (on by default);
it sends a few small **read-only** probes to each host and needs no admin rights or nmap:

| Probe | Gives you |
|---|---|
| NetBIOS (UDP 137) | Windows/SMB name, logged-on domain/workgroup, domain-controller role, and the host's real MAC (works across a router, so it fixes MACs nmap can't get) |
| mDNS / Bonjour (UDP 5353) | `.local` name and advertised services — printers (IPP), Apple AV (AirPlay), Chromecast, HomeKit, file shares |
| SSDP / UPnP (UDP 1900) | device description: manufacturer, model, friendly name, device type (media, gateway, NAS, camera) |
| HTTP / TLS banner | web-UI Server header and the TLS certificate CN/SAN — identifies appliances, cameras, NAS, iLO/iDRAC |
| nmap (optional) | open ports and service/version detection |

Every host ends up with a **role, OS, vendor, model and a confidence** (high/medium/low), and its details
carry a **Why** tab listing each signal, what was seen, and what it implies — so you can trust or correct
the verdict. The best name is chosen from DNS, NetBIOS, mDNS, SSDP and LLDP, and every other name it goes by
is kept as "also known as".

## Routed topology

Beyond cabling, NetMap reads the things that decide how the network actually forwards, so you can
understand a routed estate you were handed:

* **First-hop redundancy (HSRP / VRRP)** — the *virtual* IP hosts really use as their gateway, and which
  router is active vs standby for it. A subnet's details show its virtual gateway, and a gateway with no
  standby is flagged.
* **Routing adjacencies (OSPF / BGP)** — each device's neighbours and whether they are up (OSPF *full*, BGP
  *established*), with the remote AS for BGP peers — the shape of the routed core.
* **Spanning tree** — the root bridge and this switch's root port, i.e. the active L2 forwarding shape, which
  can differ from the physical cabling.

## Path tracing

To understand how traffic actually reaches something, every device and host has a **Path** tab, and
right-clicking anything offers **Trace path to here**, which lights the path up on the map:

* the **switched path** follows LLDP/CDP cabling and the MAC-address tables — from the core, through the
  distribution and access switches, down to the exact port a host is on;
* the **routed path** is reconstructed from the collected routing tables hop by hop toward the destination
  (a traceroute rebuilt from SNMP, so it works even where ICMP is filtered), naming each router and egress.

## Staying inside your ranges

* Nothing outside the scope is ever sent a packet. Target ranges are always inside it; when no wider scope
  is given they *are* the scope. With neither, a scan is limited to RFC1918 space and says so. *Never
  touch* always wins, including inside a target. Loopback, link-local, multicast and 0/8 are never probed.
* Probing every address is capped (default: nothing larger than a /22 per range) so a mistyped prefix
  cannot turn into tens of thousands of probes; it refuses the range and says so.
* Everything is read-only: SNMP GET/GETBULK, ICMP/TCP pings, reverse DNS, and — only if you tick it — an
  `nmap` top-25-port service check of hosts that answered.
* Pace: *Devices polled at once* (default 12), one SNMP walk at a time per device, GETBULK with 25
  repetitions. Lower it for fragile gear.

## Command line

The same scanner and the same project file, for scripting and scheduled runs. `netmap.exe` on Windows,
`netmap-cli.exe` inside the installed app's folder, or from source:

```bash
python3 -m venv .venv && .venv/bin/pip install -e .          # command line only
.venv/bin/pip install -e ".[gui]"                            # plus the desktop app (netmap-gui)
```

Requires Python 3.11+.

```bash
export NETMAP_COMMUNITY='their-ro-string'

# Inventory the ranges you are responsible for, and nothing else.
netmap crawl --target 10.20.0.0/24 --target 10.30.0.0/24 -C "$NETMAP_COMMUNITY" \
             --dns --out site.netmap --xlsx site.xlsx --drawio site.drawio

# The same list from a file (one subnet per line, '#' comments allowed).
netmap crawl --target-file ranges.txt -C "$NETMAP_COMMUNITY" --out site.netmap

# ICMP is filtered: skip the ping and try SNMP on every address in the targets.
netmap crawl --target 10.20.0.0/24 --probe-all -C "$NETMAP_COMMUNITY" --out site.netmap

# Spider outwards from a core device, bounded by --scope.
netmap crawl --seed 10.10.0.1 --scope 10.10.0.0/16 -C "$NETMAP_COMMUNITY" --out site.netmap

# Later: re-poll everything already in the project and follow new links; notes and layout are kept.
netmap crawl --resume --refresh --seed 10.10.0.1 --scope 10.10.0.0/16 -C "$NETMAP_COMMUNITY" --out site.netmap

netmap show   -m site.netmap                                      # text summary
netmap render -m site.netmap --xlsx site.xlsx --drawio site.drawio --csv out/site-   # outputs, no network
netmap sweep  -m site.netmap --subnet 10.10.50.0/24               # ping-sweep one more subnet
netmap diff   last-month.netmap site.netmap --csv changes.csv     # what changed
netmap gui    site.netmap                                         # open it in the desktop app
```

For anything repeatable, keep scope, exclusions and SNMPv3 credentials in a config file (see
`netmap.toml.example`); secrets can be given as `env:VARIABLE` rather than written into it:

```bash
netmap crawl -c site.toml --sweep --fingerprint --out site.netmap --xlsx site.xlsx
```

`ranges.txt` takes the range list as it arrives — one subnet or address per line, or several separated by
commas, with `#` comments:

```
# Head office, agreed 2026-09-20
10.20.0.0/24      # user VLANs
10.30.0.0/24, 10.31.0.0/24
192.168.5.10      # the one server in the DMZ we look after
```

### Outputs

| Option | Contents |
|---|---|
| `--out` (`.netmap` / `.json`) | the project: full inventory, notes, layouts, scan history; written after every device, so `--resume` continues an interrupted scan |
| `--xlsx` | Excel workbook: Summary, Devices, IPAM, VLANs, Links, Hosts, Interfaces, Hardware, Gaps |
| `--drawio` | draw.io diagram, physical and logical pages |
| `--html` | self-contained interactive map (works offline) |
| `--csv PREFIX` | devices, links, hosts, subnets, IPAM, VLANs, interfaces and hardware as CSV |
| `--graphml`, `--dot` | for yEd / Gephi / Cytoscape, and Graphviz |

**IPAM** counts addresses actually observed in use — device interfaces, ARP and bridge-table entries, sweep
replies — so utilisation is evidence, not an estimate. A subnet that was never swept is flagged, because
its count is a floor rather than a total.

## How the topology is worked out

* **Devices** are things that answered SNMP. Identity is by management IP, but a box reached again via
  another of its addresses is merged, not duplicated.
* **LLDP/CDP links** are matched to a known device by neighbour management address, chassis MAC or system
  name (domain-stripped). One link per port pair, whichever side reported it, with port names normalised
  (`GigabitEthernet1/0/2` = `Gi1/0/2`). A neighbour that could not be polled becomes an *unpolled* device,
  or, if its address answers in ARP, is attached to that host and typed from its LLDP capabilities.
* **Routing links** connect a device to the device owning its route next-hop. They are not drawn where a
  cable between the pair is already known.
* **Subnets** come from interface addresses; devices and hosts are members. Their VLAN comes from the SVI
  that holds the address.
* **Hosts on ports** come from MAC tables: a host is placed on the access port where its MAC was learned.
  Ports carrying an LLDP/CDP neighbour, or more than 8 MACs, are treated as uplinks and skipped.

## Running it well

1. Run it from a machine inside the network (a jump host or a laptop on the management VLAN): SNMP is
   almost always filtered at the edge.
2. Prove the credentials on one device first: *Test against a device* in the credential dialog, or the
   SNMP test in Tools.
3. Scan the ranges, with one or two core devices as starting points so LLDP/CDP fills in the wiring
   between them. Tick *Ping-sweep every subnet* for exact address counts.
4. Read **Needs attention** and the IPAM figures against what you were told about the network.
5. Document as you go, tidy the diagram, export the workbook and the draw.io file for the team.
6. Rescan periodically (F5) and use *Compare with another scan* to see what moved.

## Windows notes

* **Nmap is optional.** Without it, target ranges are pinged with Windows' own `ping` and service
  identification is unavailable; SNMP, LLDP/CDP, ARP, routing, DNS and MAC-based typing all work regardless.
  NetMap finds Nmap in its default install folder even when it is not on `PATH`.
* **Run as Administrator** only if you use Nmap sweeps and want ARP/ICMP discovery; unprivileged, Nmap falls
  back to TCP connect pings and finds fewer hosts.
* Windows Defender Firewall does not block outbound SNMP, but a corporate endpoint agent might. If
  everything times out, try one device with the SNMP test in Tools and see whether an answer arrives at all.
* WSL2 works for the command line, but its NAT-ed network hides ARP, so prefer the native build for sweeps.

## Building

```bash
pip install -e ".[gui]" pyinstaller
pyinstaller packaging/netmap-gui.spec --noconfirm   # -> dist/NetMap/ (NetMap.exe + netmap-cli.exe)
pyinstaller netmap.spec --noconfirm                 # -> dist/netmap(.exe), the single-file command line
iscc /DAppVersion=0.3.0 packaging\netmap.iss        # -> dist/NetMap-0.3.0-setup.exe (Inno Setup, Windows)
```

A Windows build has to be made on Windows: pushing to `main` or a `v*` tag runs
`.github/workflows/build.yml`, which runs the tests on Linux and Windows, builds everything, starts the
frozen app with `--selftest` (every page, every export, screenshots) and, for a tag, attaches the installer,
the portable zip and the command-line binaries to the release with checksums.

## Testing

```bash
pip install -e ".[gui]" pytest snmpsim pysmi
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

* `tests/labnet.py` — a small three-tier network (Cisco ISR, Catalyst 3850 stack, HP 2530, an AP, a phone,
  an out-of-scope firewall) as raw SNMP tables.
* `tests/demonet.py` — a mid-sized campus (11 devices, ~470 hosts) with the untidiness real networks have;
  it is also the sample project shipped with the app (`python -m tests.demonet` regenerates it).
* Unit tests crawl both through an in-memory SNMP stand-in. End-to-end tests serve the lab with `snmpsim` on
  loopback and drive the real command line over SNMPv2c and SNMPv3, and the desktop app's scan worker
  thread (including stopping a scan and rescanning a device). The GUI tests run headless and exercise every
  page and export.

## Limits

* IPv4 only. IPv6 addresses and routes are not collected yet.
* Routes are read from the default routing table; VRFs are not enumerated.
* Cisco IOS per-VLAN bridge tables need *Read per-VLAN MAC tables* (`--cisco-vlan-fdb`): community@vlan
  indexing, or `vlan-N` contexts for v3. Q-BRIDGE-capable devices work without it.
* LLDP neighbours that advertise no management address and never appear in an ARP table stay as unpolled
  stubs.
* Devices behind NAT, or answering SNMP on a non-standard port, need their own scan with the right port.
