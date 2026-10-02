# Changelog

All notable changes to SubnetSleuth (called NetMap up to 0.12) are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) while the project is pre-1.0 (minor bumps may
change behaviour). The release workflow publishes the section for a tag as its release notes,
so every release needs its `## [x.y.z] - date` heading here before it is tagged.

## [0.14.0] - 2026-10-02

### Changed
- The overview no longer shows *Devices by role* and *Endpoints by type* as two lists that
  overlapped. It now splits everything by what it is: **Network infrastructure** — firewalls,
  routers, switches and access points, wherever they were found, with the lighter part of each
  bar the gear not yet polled over SNMP — and **Endpoints by type** — everything attached to the
  network, in broad kinds (PCs, phones, printers, servers, …), with servers grouped into one row
  since *Server functions* already breaks them down. *Network gear by vendor*, the spreadsheet
  summary and the command-line summary use the same split, and the device and host lists gain a
  hidden *Kind* column so you can filter with, for example, `group:servers`.

### Added
- An optional **try well-known default communities** step for a scan: after your own SNMP
  credentials, SubnetSleuth can try the handful of factory-default community strings (public,
  private, …) read-only, inside the same ranges as every other step. A device that answers one is
  reported under *Needs attention* so you can change it — useful when you are taking over a
  network with no documentation. In the New scan dialog, or `crawl --try-default-communities`.
- Authenticated Windows inspection now identifies the **device type**: reading the operating
  system's product type over WinRM tells a server, a domain controller and a workstation apart and
  sets the host's type with high confidence. The inspect dialog (now *Inspect hosts*) can also
  connect over HTTPS (WinRM 5986).

## [0.13.1] - 2026-10-01

### Changed
- The sample network (*Help > Explore the sample network*) includes a deep scan of its intranet
  web server, so the *Deep scan* and *Scripts* tabs can be seen without running one.
- A deep scan lists its ports from low to high.

### Added
- `tools/make_demo_video.py` renders the demo video from the app itself.

## [0.13.0] - 2026-10-01

NetMap is now **SubnetSleuth**: the desktop app is `SubnetSleuth.exe`, the command line
`subnetsleuth`, and the repository github.com/kerbe42/subnetsleuth (the old address redirects).

### Changed
- New projects are saved as `.sleuth`. `.netmap` projects open and save as they are, and the
  installer associates both extensions with SubnetSleuth.
- The installer upgrades a NetMap install in place: it installs into a *SubnetSleuth* folder and
  removes the old NetMap program folder, Start menu entry and desktop shortcut.
- On first start SubnetSleuth copies NetMap's settings: preferences, window layout, recent files
  and saved SNMP credentials, which still decrypt. The SSH host keys NetMap recorded are carried
  over too. A portable folder with `netmap-portable.ini` keeps working.
- Environment variables are now `SUBNETSLEUTH_*` (for example `SUBNETSLEUTH_COMMUNITY`); the old
  `NETMAP_*` names still work.
- The config example is `subnetsleuth.toml.example`; command-line defaults are `subnetsleuth.json`
  and `subnetsleuth.html`.

## [0.12.0] - 2026-10-01

### Added
- **Now:** line in the Activity panel: the subnets, /24 blocks, address batches, devices and hosts the
  scan is working on at that moment, with Nmap's current stage and how long anything slow has been
  running (hover for the full list). Scans also log a "working on: …" line once a minute, so the
  command line shows progress too.
- **Deep scan** of chosen addresses: right-click a device or host, *Tools ▸ Deep scan an address
  with Nmap…* (Ctrl+Shift+D), or `netmap deepscan IP… -m project`. All 65,535 TCP ports, full
  service-version detection, OS detection and traceroute (Administrator/root), optional common UDP
  services, and Nmap's `default and safe` information scripts. Results are kept in the project and
  shown on new *Deep scan* and *Scripts* tabs; ports and the OS guess also update the host.

### Changed
- Ranges you enter are scanned in full, whatever their size. Ranges larger than a /20 get a warning
  with a rough duration instead of being skipped. The size limit now applies only to subnets learned
  from devices (*Largest discovered subnet to sweep*, `--sweep-max-size`), and `netmap sweep
  --subnet` no longer applies it.
- Sweeps hand out /24 blocks from a shared queue, so a very large range does not create a task per
  block up front.

## [0.11.0] - 2026-10-01

Large networks (dozens of ranges, /16s) no longer lose results to `nmap timed out`.

### Changed
- Ping sweeps run one `nmap` per /24 of each range, eight at a time across all ranges, instead of
  one `nmap` for a whole subnet. A /16 is 256 short runs, not one run that has to finish in time.
- The port scan (*Scan ports & service versions*, `--port-scan`) only goes to addresses that answer
  a ping. Addresses already seen answering in the same scan (sweep results, devices that answered
  SNMP) are not pinged again; the rest get a quick `nmap -sn` check first. Addresses that answer
  nothing stay in the inventory but are not port-scanned, which is where `nmap -Pn` used to spend
  its whole time limit. Untick *Only port-scan addresses that answer a ping* or pass
  `--no-ping-first` (config: `ping_first = false`) to scan every address found.
- Every target ping sweep finishes before any fingerprinting starts.
- A target range larger than *Largest subnet to sweep/probe* is skipped with a warning (it was an
  info line), and the scan dialog lists such ranges before you start.

### Added
- *Nmap time limit per run* (Preferences and the scan dialog), `--nmap-timeout MINUTES` and
  `nmap_timeout` in the config file: how long one `nmap` run may take, default 30 minutes, 0 for no
  limit.
- A run that reaches its limit keeps every host `nmap` had already reported. For a sweep, the block
  is pinged again with twice the time. For a port scan, only the addresses it had not finished are
  scanned again, in smaller batches with twice the time. Anything still unfinished is named in the
  log, and a subnet whose sweep did not finish is not marked swept, so the next sweep retries it.
- Progress lines for long sweeps and port scans (blocks or addresses done so far).

### Fixed
- *Nmap ports per host* in Preferences now reaches the scan; scans always used 200.
- The *Scan ports & services* checkbox showed "ports _services".

## [0.10.0] - 2026-09-30

Fixes from a review of the whole codebase, grouped by what they mean for someone using the tool.

### Scope and read-only guarantees
- Every step that sends a packet - SNMP, ping sweeps, reverse DNS, host identification probes,
  the optional `nmap` service and OS scans, SSH/WinRM/vCenter collection - now checks the same
  scope and exclusion lists before contacting an address, so *Never touch* and the scope apply
  to the whole scan, not only to SNMP polling.
- Saved SNMP secrets on Linux/macOS are stored under a random identifier instead of one derived
  from the secret itself.
- The README now states exactly which steps send traffic, what each one sends, and how the
  scope, target ranges and exclusions bound them.
- Ping sweeps hand `nmap` only the part of a subnet that is inside the scope and outside every
  exclusion (an excluded range inside a swept subnet, or an excluded single address, used to be
  scanned and merely left out of the results). A target subnet wholly outside the scope is
  skipped with a warning.
- Hosts imported from DHCP leases or vCenter, or kept from an earlier wider scan, are no longer
  probed, resolved or logged into when they fall outside the current scope.
- Running-configuration capture never sends a configuration-mode command. The FortiOS profile
  used to change the console paging setting, which is a logged configuration change; paging
  prompts are now answered instead. Any configuration-mode command is refused outright.
- Captured running configurations are stored with secrets redacted (SNMP communities, local
  passwords and hashes, pre-shared keys, RADIUS/TACACS keys, certificate blocks); the line
  stays so diffs still line up.
- SSH collection (host facts and configuration capture) checks host keys: the system
  `known_hosts` plus a per-user store are consulted, a key is recorded on first sight, and a
  changed key stops the connection with a message naming the file to clear.
- vCenter connections verify the TLS certificate by default; `--insecure` (CLI) or the dialog's
  checkbox opts out for self-signed servers.
- Authenticated inspection only tries SSH or WinRM where the port is open, never against
  appliance roles (controllers, cameras, printers, phones, lights-out management), so a
  read-only service account is not locked out by failed logons.
- The SSDP description document is only fetched from the address that announced it.
- The local read-only API no longer allows cross-origin reads from other web pages and takes
  its token from the `Authorization` header only.
- Credential labels no longer embed any part of the community string (the default label used
  to carry its first characters into the project file, CSV and workbook exports).
- The syslog/trap listener records trap contents (trap name, interface, status) instead of the
  community string, and binds exclusively on Windows so it fails loudly rather than sharing a
  port with another listener.

### Topology and identification accuracy
- The topology graph cache introduced in 0.9.0 now actually works (a loop variable overwrote
  its key), so refreshing a page no longer rebuilds the graph and re-profiles every host.
  Model changes that the cache must see (adding or removing hosts, subnets, devices) all
  invalidate it.
- Subnet gateways are the devices that route for the subnet (routing role, routes to other
  networks, or the active first-hop-redundancy owner), not every switch with a management
  address in it.
- Path tracing reaches endpoints announced over LLDP/CDP (access points, phones, servers) on
  their real access port instead of stopping at the gateway.
- Ports named "Port 1", "Port 24" (common on small-business switches) are no longer mistaken
  for port-channels, so hosts are placed on them and the port panel shows them.
- Q-BRIDGE forwarding tables map the forwarding-database id to the VLAN id (they differ on
  several vendors); ARP rows of invalid type are dropped; per-VLAN forwarding walks on IOS skip
  suspended VLANs and report when the VLAN cap truncates them.
- Two devices that share an address in a virtual range (container bridges, hypervisor default
  switches, first-hop virtual addresses) are no longer merged into one; merging needs a
  matching serial, chassis id, or name plus object id.
- SNMP table walks stop on agents that return non-increasing OIDs, retry once from the last
  row after a mid-walk timeout, and record a truncated table in the device's error list
  instead of presenting a partial table as complete.
- Routes are read from the address-family-neutral route table first, then the CIDR table,
  then the legacy table, so routers that only populate the newer table contribute routes; a
  malformed mask no longer discards the rest of a route table.
- LLDP local ports identified by MAC address are decoded and matched; PoE per-port status is
  matched by stack member and port, not by interface index.
- SNMPv1 credentials for old UPSes, PDUs and printers; address ranges (`a.b.c.d-e`) in target
  files.
- A rescan without the optional phases keeps a device's ports, operating system, management
  planes, functions and DNS name instead of blanking them.
- Host identification: vendor and product words are matched as whole tokens and only in the
  fields that name a vendor (server header, certificate issuer), so "praxis" no longer means a
  camera vendor and "pilot" no longer means lights-out management; a name seen from three
  sources votes once; a NetBIOS answer without a unit id (file-sharing daemons on Linux and
  storage appliances) no longer classifies the host as Windows; lights-out controllers are
  `bmc`, cast and streaming devices are the new `media` role, and a Windows workstation with a
  web port is not promoted to a web server. BSD and hypervisor banners map to their own
  families.
- Identification probes no longer starve at scale: concurrency is bounded per probe, so every
  host's answers are recorded (about one in eight was, on a 60-host test with slow answers).
- New reads: BACnet object name/vendor/model, NTP mode-6 variables, Modbus device id with the
  broadcast unit id first and complete frames.
- Findings: "Neighbour not polled" no longer fires for phones and access points announced over
  LLDP (they are listed as endpoints); VLAN host counts are distinct MACs; "Subnet not yet
  scanned" ignores point-to-point links and prefixes a polled device sits in; IPv6 hosts are
  not flagged as outside the address plan; a MAC seen on several addresses is reported instead
  of silently dropped. New checks: switch with a single uplink, overlapping subnets from
  different devices, spanning-tree root on an access switch or disputed between switches, VLAN
  mismatch across a link. Devices list a free-port count.
- Compliance: the spanning-tree default-priority check understands extended system ids (32768
  + VLAN) and treats priority 0 as deliberate; the HTTP management finding is no longer hidden
  when Telnet is also open; the SNMP version check uses the protocol that answered, not the
  credential's label.
- Query language: quoted values may contain operators and the words and/or; `>` and `<`
  compare IP addresses, sizes, durations and dates by value; `port =` searches services only;
  malformed queries raise a query error instead of crashing.
- Compare: placeholder serials never produce a false "moved"; a host whose address changed is
  reported as readdressed rather than removed and added; the reboot check tolerates the
  497-day uptime wrap. Asset-list check: serial and annotated name are compared the same way
  they are matched, and a listed device found only as an unpolled address says so.
- Exports: cells that start with a formula character are written as text in CSV and .xlsx;
  draw.io tooltips and edge labels are escaped for their HTML rendering; the hand-over workbook
  uses display names and adds Site/Owner/Status/Asset tag/Notes columns plus Findings,
  Compliance, Hardware support and Dependencies sheets.
- Layered layout wraps very wide layers of hosts under their parent switch (a 15,000-host
  estate laid out 2.6 million pixels wide before).
- DHCP import: the last lease block per address wins, inactive leases update existing hosts
  only, inactive reservations are not reported active, and the `netsh` table, the DHCP server
  XML export and Kea JSON are now accepted; an unrecognised file is reported instead of
  importing nothing.

### Desktop app
- Nothing you typed or moved is lost any more: the last node drag before Save is written, the
  last half-second of Notes typing is kept when you click another item or close, and the
  project is no longer overwritten after a cancelled scan unless you had already saved it this
  session. Three rotating backups (`.bak1`-`.bak3`) are kept beside the project, with File ▸
  Revert to saved and Tools ▸ Compare with the previous saved version.
- Undo and redo (Ctrl+Z / Ctrl+Shift+Z) for note and role edits, Remove from project and
  Re-arrange.
- Crash recovery: while there are unsaved changes a recovery copy is written every two
  minutes and offered on the next start.
- Needs attention and Compliance rows can be acknowledged (right-click); acknowledged rows are
  hidden until you tick Show acknowledged, and the acknowledgement is saved with the project.
- Closing the window waits for every background job (scan, config capture, host inspection,
  vCenter discovery, update check) instead of tearing threads down mid-flight; starting a
  scan, opening or creating a project, or removing an item is blocked with a message while
  another job runs, and side jobs work on a copy of the inventory and merge on the UI thread.
- Large inventories: list sorting happens once in the model, saving, exporting and the scan's
  working copy run off the UI thread behind a wait cursor, and live scan updates are prepared
  in the background. On a 14,000-host project the Hosts page update went from about 5 s to
  0.2 s, a header sort from 2 s to 0.2 s, and the spreadsheet export no longer freezes the
  window.
- The map keeps its selection when it rebuilds, a traced path stays zoomed to the path, and
  exported images are capped at 8,192 px with a real error if writing fails.
- Lists: hosts sort by address by default, the Type column shows the same labels as the
  dashboard and details, percentage bars stay readable at every fill level, empty lists say
  what to do next, exports remember the export folder, and the navigation pane fits its
  longest label. The port panel shows "Port N" interfaces and sizes itself correctly for small
  switches.
- Query results use the same fast table as the other pages; large subnets build their address
  grid once and cap the address list.
- Credential labels default to "v2c credential N"; the credentials list explains how to add
  the first one. Menu and toolbar wording names file formats rather than products.
- Uninstalling offers to remove the settings and saved credentials from the registry, removes
  the log folder, and an upgrade clears the previous version's program files first so no stale
  libraries are left behind.

### Packaging and CI
- The hardware end-of-sale / end-of-support table is now included in the wheel, the single-file
  command line, the desktop app folder, the portable zip and the installer. It had shipped in
  none of them since the feature was added, so the end-of-support checks on the Compliance page
  and in the hardware list found nothing in released builds. A test now pins the package-data
  globs and both PyInstaller specs (which share one list in `packaging/bundle.py`) to the files
  on disk, and CI checks the frozen binaries for the data files.
- Project metadata: MIT licence file, licence/URL/classifier metadata, and the optional extras
  `netmap[keyring]` (secret storage on Linux) and `netmap[test]`.
- The Linux command-line binary is built on Ubuntu 22.04, so it runs on any distribution with
  glibc 2.35 or newer (Ubuntu 22.04+, Debian 12+, RHEL/Rocky/Alma 9+). Command-line release
  files carry the version in their name (`netmap-<version>-win-x64.exe`, `netmap-<version>-linux-x64`).
- CI: the real-SNMP end-to-end tests fail loudly with the simulator's output when the simulated
  agents do not start (they had been skipped silently on every run); tests run on Python 3.11
  and 3.12; actions are pinned to commit SHAs with Dependabot keeping them and the build
  tooling current; one build per tag instead of two; only the release job can write to the
  repository; release notes are taken from this file.
- Tests no longer bind fixed ports, so they run alongside anything else on the machine.
- `netmap.toml.example` documents the `[crawl]` keys the loader reads (`resolve_names`,
  `identify`, `port_scan`, `os_detect`) and which options are command-line only.
- `tools/make_sample.py` regenerates the bundled sample project; `tools/refresh_screenshots.py`
  refreshes the README screenshots from the app's self-test.

## [0.9.0] - 2026-09-30

A correctness pass over the parts of the tool that decide where a host sits and what a device
is, plus responsiveness at very large inventories.

### Topology and identification
- Host-to-switch-port placement: uplinks are recognised by what they are (trunk ports, LAG
  members and port-channel aggregators, not only ports with an LLDP/CDP neighbour), and a MAC
  learned by several switches along its path is placed on the access port that carries the
  fewest addresses - the leaf - instead of one switch picked arbitrarily. Hosts are no longer
  pinned to trunks behind unmanaged or LLDP-silent switches.
- First-hop redundancy: an HSRP/VRRP virtual address resolves to the active router, so routes
  whose next hop is the virtual gateway follow through and the real gateway is named.
- Path tracing labels ingress and egress ports correctly when a hop is traversed against the
  order the link was stored in.
- Device model is parsed from the system description for vendors that leave the standard
  hardware MIB blank (firewalls, wireless controllers, routers and many access switches), so
  the Model column is populated on far more real equipment. A model from the hardware MIB is
  never overwritten.
- An unauthenticated SSH banner read gives the operating system of hosts that offer SSH, with
  no privileges needed.
- MAC vendor lookup no longer reports registry placeholders as a manufacturer for addresses in
  shared IEEE blocks.
- Small unprivileged UDP checks confirm DNS and NTP servers, which a TCP scan cannot see, so the
  DNS / NTP server functions are populated on real scans.

### Scanning
- Progress is saved about every five seconds during a crawl instead of after every device,
  which removed a stall on large networks; the final save still captures everything.
- 32-bit interface counters that wrap between two polls are corrected instead of being reported
  as zero utilisation.
- `nmap` subprocesses are always reaped on timeout or cancel.

### Desktop app
- The topology graph is cached and rebuilt only when the inventory changes, list filtering and
  sorting reuse cached text and keys, and findings use the subnet index: a page switch, filter
  keystroke or selection at tens of thousands of hosts no longer rebuilds everything.

## [0.8.1] - 2026-09-30

### Fixed
- A single transient timeout while reading a device's system group no longer drops a device
  that had already answered SNMP; partial data is kept.
- A table walk that hits an error part-way through keeps the rows gathered so far instead of
  returning nothing (a device that returned forty interfaces then errored used to yield zero).
- Web servers running PHP are no longer mistaken for printers; port 3000 alone no longer
  implies a monitoring server.
- An interface with a 0.0.0.0 mask (tunnels, unnumbered links) no longer creates a catch-all
  subnet that matched every address.
- Probing every address in a /31 point-to-point range probes both addresses.
- Network devices no longer list their own management interfaces as served "functions".

## [0.8.0] - 2026-09-30

### Added
- Server functions from open ports: a host can fill several roles at once, so they are listed
  as functions (a Hosts column, a details row, and a Server functions breakdown on the
  overview) - web, database (named by engine), file, mail, DNS/DHCP/NTP, directory / domain
  controller, print, virtualization host, containers, message queue, proxy, backup.
- Where the ports are unambiguous the primary role is sharpened (web server, database, mail
  server, DNS server, domain controller, hypervisor, file server), each with its own icon on
  the map, the HTML map and the diagram export.
- Client machines are not mistyped: file sharing and remote desktop alone never make a PC a
  file server, and a host offering no real service stays a plain endpoint.
- Functions can be filtered and queried (`type:database`, `hosts where functions ~ "PostgreSQL"`).
- The sample network gained a realistic server fleet to show the classification.

## [0.7.0] - 2026-09-30

### Added
- Broad unauthenticated discovery as part of Identify hosts: WS-Discovery (printers, ONVIF
  cameras, Windows), IPMI (lights-out controllers) and OT/ICS protocols (Modbus/TCP, BACnet/IP,
  EtherNet/IP), with vendor and model where the protocol gives them.
- New device types with icons: PLC / controller, building automation, OT / industrial,
  lights-out (BMC).
- Coverage gaps: every private network the routing tables reference but the scan never reached
  is flagged as "Subnet not yet scanned".

## [0.6.0] - 2026-09-30

### Added
- Agentless server inspection over read-only SSH (Linux/Unix) and WinRM (Windows): OS,
  hardware, installed software, running services and active connections.
- Dependency mapping from the collected connections: a Dependencies page and a per-host tab.
- VMware discovery (vCenter/ESXi, read-only) folding hosts and VMs into the map.
- Switch faceplate view, scheduled rescans, a query language over the inventory, a read-only
  REST API on localhost, and a Preferences dialog.

## [0.5.0] - 2026-09-30

### Added
- Compliance page (management-plane configuration checks), offline hardware end-of-sale /
  end-of-support lookup, interface health (errors, discards, duplex, utilisation) and PoE.
- Configuration capture over SSH with revision history and diff.
- DHCP lease/scope import; a passive syslog and SNMP trap listener.

## [0.4.0] - 2026-09-30

### Added
- Host identification from many weak signals (NetBIOS, mDNS, SSDP, HTTP/TLS), with the
  evidence kept and a confidence per host.
- Routed topology: HSRP/VRRP gateways, OSPF/BGP neighbours, spanning-tree root.
- Path tracing (switched and routed) with the path lit up on the map.

## [0.3.0] - 2026-09-30

### Added
- The Windows desktop app: topology map (physical and logical), lists, details, notes,
  compare with another scan, exports; installer and portable zip built by CI.
- Check a project against an asset list you were given.
- Hardware inventory (chassis, modules, power supplies, transceivers), OS versions, per-port
  VLANs and LAGs.

## [0.2.0] - 2026-09-29

### Added
- Inventory named subnets directly (targets), offline device typing from the MAC vendor table,
  IPAM figures, and a single-file `netmap.exe` built by CI.

## [0.1.0] - 2026-09-22

### Added
- First release: SNMP/LLDP/CDP crawler with routes, ARP, MAC tables and VLANs, and an
  interactive topology map.

[0.14.0]: https://github.com/kerbe42/subnetsleuth/compare/v0.13.1...v0.14.0
[0.13.1]: https://github.com/kerbe42/subnetsleuth/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/kerbe42/subnetsleuth/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/kerbe42/subnetsleuth/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/kerbe42/subnetsleuth/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/kerbe42/netmap/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kerbe42/netmap/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/kerbe42/netmap/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/kerbe42/netmap/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kerbe42/netmap/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kerbe42/netmap/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kerbe42/netmap/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kerbe42/netmap/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kerbe42/netmap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kerbe42/netmap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kerbe42/netmap/releases/tag/v0.1.0
