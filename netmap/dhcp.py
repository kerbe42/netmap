"""Import DHCP leases and scopes exported from the servers that run the network.

When you inherit a network the DHCP server knows things SNMP does not: which addresses are
handed out, the names clients registered, and the MAC behind each. This reads the common
export formats and folds them into the inventory - naming hosts, filling MACs, and marking
which subnets are DHCP scopes:

* ISC dhcpd ``dhcpd.leases`` (the last block for an address is the current one)
* Kea memfile CSV, and Kea ``lease4-get-all`` JSON (the control-channel reply, or its list)
* Windows DHCP: ``Export-DhcpServer`` XML, ``netsh dhcp server ... show clients`` text, and
  CSV exports (``Get-DhcpServerv4Lease | Export-Csv``)

A lease that is free, expired, inactive, declined or merely offered never creates a host on
its own - the address is not known to be in use - but does update a host already seen.

Everything here is offline file parsing; nothing talks to a server.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .util import is_usable_ip, norm_mac, plausible_mac

# states that mean "nobody is confirmed at this address right now"
INACTIVE_STATES = frozenset({"free", "expired", "inactive", "declined", "offered", "abandoned", "released", "backup"})


class DhcpFormatError(ValueError):
    """The text is not a DHCP export format this module recognises."""


@dataclass
class Lease:
    ip: str
    mac: str = ""
    hostname: str = ""
    state: str = ""  # active | reserved | free | expired | inactive | declined | offered
    expires: str = ""
    scope: str = ""  # scope/subnet id if the export gave one


def _norm_state(raw: str) -> str:
    """Map a server's lease/address state to one of ours. Windows ``InactiveReservation`` is
    inactive (checked before 'active', which it contains); Offered/Declined are explicit."""
    s = (raw or "").strip().lower()
    if not s:
        return ""
    if "inactive" in s:
        return "inactive"
    if "declin" in s:
        return "declined"
    if "offer" in s:
        return "offered"
    if "expir" in s:
        return "expired"
    if "reserv" in s:
        return "reserved"
    if "active" in s or s in ("bound", "ok"):
        return "active"
    if s in ("free", "abandoned", "released"):
        return s
    return s


# --------------------------------------------------------------------------- #
# ISC dhcpd
# --------------------------------------------------------------------------- #
def parse_isc_leases(text: str) -> list[Lease]:
    """ISC dhcpd `dhcpd.leases`: blocks like `lease 10.0.0.5 { ... }`. The file is a journal -
    the *last* block for an address is its current state, so later blocks replace earlier
    ones (order of first appearance is kept)."""
    by_ip: dict[str, Lease] = {}
    for m in re.finditer(r"lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}", text, re.S):
        ip, body = m.group(1), m.group(2)
        if not is_usable_ip(ip):
            continue
        lease = Lease(ip=ip)
        hw = re.search(r"hardware\s+ethernet\s+([0-9a-fA-F:]+)", body)
        if hw:
            lease.mac = norm_mac(hw.group(1)) or ""
        hn = re.search(r'client-hostname\s+"([^"]*)"', body)
        if hn:
            lease.hostname = hn.group(1)
        st = re.search(r"(?<!next )binding state\s+(\w+)", body)
        if st:
            lease.state = {"active": "active", "free": "free", "expired": "expired", "backup": "backup",
                           "abandoned": "abandoned", "released": "released"}.get(st.group(1), st.group(1))
        ends = re.search(r"ends\s+\d+\s+([\d/]+\s+[\d:]+)", body)
        if ends:
            lease.expires = ends.group(1)
        elif re.search(r"ends\s+never", body):
            lease.expires = "never"
        by_ip[ip] = lease  # last block wins
    return list(by_ip.values())


# --------------------------------------------------------------------------- #
# Kea
# --------------------------------------------------------------------------- #
def parse_kea_csv(text: str) -> list[Lease]:
    """Kea memfile CSV: header includes address,hwaddr,client_id,valid_lifetime,expire,...,hostname,state."""
    rows = list(csv.DictReader(text.splitlines()))
    by_ip: dict[str, Lease] = {}
    for r in rows:
        ip = (r.get("address") or "").strip()
        if not is_usable_ip(ip):
            continue
        state = {"0": "active", "1": "declined", "2": "expired"}.get((r.get("state") or "").strip(), "active")
        exp = r.get("expire", "")
        if exp and exp.isdigit():
            exp = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(exp)))
        by_ip[ip] = Lease(ip=ip, mac=norm_mac(r.get("hwaddr")) or "", hostname=(r.get("hostname") or "").strip(), state=state, expires=exp)
    return list(by_ip.values())


def parse_kea_json(text: str) -> list[Lease]:
    """Kea ``lease4-get-all`` (or ``lease4-get-page``) reply: ``{"arguments": {"leases": [...]}}``,
    or a bare list of lease objects. Fields: ip-address, hw-address, hostname, state, cltt, valid-lft, subnet-id."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise DhcpFormatError(f"not valid JSON: {e}") from e
    if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "arguments" in doc[0]:
        doc = doc[0]  # the control agent wraps replies in a list
    leases = None
    if isinstance(doc, dict):
        leases = (doc.get("arguments") or {}).get("leases") if isinstance(doc.get("arguments"), dict) else doc.get("leases")
    elif isinstance(doc, list):
        leases = doc
    if not isinstance(leases, list):
        raise DhcpFormatError("JSON has no 'leases' list (expected a Kea lease4-get-all reply)")
    out: list[Lease] = []
    for lz in leases:
        if not isinstance(lz, dict):
            continue
        ip = str(lz.get("ip-address") or lz.get("address") or "").strip()
        if not is_usable_ip(ip):
            continue
        state = {0: "active", 1: "declined", 2: "expired"}.get(lz.get("state"), "active")
        expires = ""
        try:
            if lz.get("cltt") is not None and lz.get("valid-lft") is not None:
                expires = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(lz["cltt"]) + int(lz["valid-lft"])))
        except (TypeError, ValueError, OverflowError):
            pass
        out.append(Lease(ip=ip, mac=norm_mac(lz.get("hw-address") or lz.get("hwaddr")) or "",
                         hostname=str(lz.get("hostname") or "").strip().rstrip("."), state=state, expires=expires,
                         scope=str(lz.get("subnet-id") or "")))
    return out


# --------------------------------------------------------------------------- #
# Windows DHCP
# --------------------------------------------------------------------------- #
# Windows DHCP export column names (Export-DhcpServer / Get-DhcpServerv4Lease / netsh), case-insensitive
_WIN_COLS = {
    "ip": ["ipaddress", "ip address", "leaseip", "address", "ip"],
    "mac": ["clientid", "client id", "mac", "macaddress", "hardware address", "physical address"],
    "hostname": ["hostname", "name", "host name", "clienthostname", "computername"],
    "state": ["addressstate", "state", "status", "leasestate"],
    "expires": ["leaseexpirytime", "expiry", "expires", "lease expiration", "leaseexpires"],
    "scope": ["scopeid", "scope", "scope id"],
}


def _match_cols(headers: list[str]) -> dict:
    norm = [re.sub(r"[\s_]+", " ", (h or "").strip().lower()) for h in headers]
    out = {}
    for field_, names in _WIN_COLS.items():
        for i, h in enumerate(norm):
            if h in names:
                out[field_] = i
                break
    return out


def parse_windows_csv(text: str) -> list[Lease]:
    """Windows DHCP lease/scope export as CSV, with flexible column names."""
    # find the header row (first row naming an IP column), skipping any title lines
    reader = list(csv.reader(text.splitlines()))
    reader = [r for r in reader if any(c.strip() for c in r)]
    header_idx = next((i for i, r in enumerate(reader[:15]) if _match_cols(r).get("ip") is not None), None)
    if header_idx is None:
        return []
    cols = _match_cols(reader[header_idx])
    out = []
    for r in reader[header_idx + 1:]:
        if cols["ip"] >= len(r):
            continue
        ip = r[cols["ip"]].strip()
        if not is_usable_ip(ip):
            continue

        def g(k):
            i = cols.get(k)
            return r[i].strip() if i is not None and i < len(r) else ""
        mac = g("mac")
        # Windows ClientId is often the MAC with dashes
        out.append(Lease(ip=ip, mac=norm_mac(mac) or "", hostname=g("hostname").split(".")[0], state=_norm_state(g("state")),
                         expires=g("expires"), scope=g("scope")))
    return out


_NETSH_SCOPE = re.compile(r"scope context to\s+(\d+\.\d+\.\d+\.\d+)", re.I)
_NETSH_ROW = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+-\s+(\d+\.\d+\.\d+\.\d+)\s+-\s+([0-9a-fA-F-]{11,})\s+-\s+(.*?)\s+-\s*([A-Z]?)\s*-\s*(.*?)\s*$"
)


def parse_netsh_clients(text: str) -> list[Lease]:
    """``netsh dhcp server [\\\\server] scope <id> show clients [1]`` fixed-width text:

        IP Address - Subnet Mask - Unique ID - Lease Expires -Type -Name

    'NEVER EXPIRES' marks a reservation, 'INACTIVE' an inactive lease."""
    scope = ""
    out: list[Lease] = []
    for line in text.splitlines():
        sm = _NETSH_SCOPE.search(line)
        if sm:
            scope = sm.group(1)
            continue
        m = _NETSH_ROW.match(line)
        if not m:
            continue
        ip, _mask, uid, expires, _type, name = m.groups()
        if not is_usable_ip(ip):
            continue
        exp_l = expires.strip().lower()
        if "never" in exp_l:
            state, expires = "reserved", "never"
        elif "inactive" in exp_l:
            state, expires = "inactive", ""
        else:
            state = "active"
        out.append(Lease(ip=ip, mac=norm_mac(uid) or "", hostname=name.strip().split(".")[0], state=state,
                         expires=expires.strip(), scope=scope))
    return out


def _xml_text(el, *tags: str) -> str:
    for tag in tags:
        for child in el.iter():
            if child is not el and child.tag.rsplit("}", 1)[-1].lower() == tag.lower() and (child.text or "").strip():
                return child.text.strip()
    return ""


def parse_windows_xml(text: str) -> list[Lease]:
    """``Export-DhcpServer -Leases`` XML: ``<Lease>`` elements (IPAddress, ClientId, HostName,
    AddressState, LeaseExpiryTime, ScopeId) and ``<Reservation>`` elements under each scope."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise DhcpFormatError(f"not well-formed XML: {e}") from e
    out: list[Lease] = []
    seen: set[str] = set()
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1].lower()
        if tag not in ("lease", "reservation"):
            continue
        ip = _xml_text(el, "IPAddress")
        if not is_usable_ip(ip):
            continue
        scope = _xml_text(el, "ScopeId")
        if not scope:
            parent_scope = next((_xml_text(s, "ScopeId") for s in root.iter()
                                 if s.tag.rsplit("}", 1)[-1].lower() == "scope" and any(c is el for c in s.iter())), "")
            scope = parent_scope
        state = "reserved" if tag == "reservation" else _norm_state(_xml_text(el, "AddressState"))
        lease = Lease(ip=ip, mac=norm_mac(_xml_text(el, "ClientId", "MacAddress")) or "",
                      hostname=_xml_text(el, "HostName", "Name").split(".")[0],
                      state=state, expires=_xml_text(el, "LeaseExpiryTime"), scope=scope)
        key = f"{ip}/{tag}"
        if key in seen:
            continue
        seen.add(key)
        out.append(lease)
    return out


# --------------------------------------------------------------------------- #
# detection + import
# --------------------------------------------------------------------------- #
def detect_format(text: str) -> str:
    """Name the export format of `text`: isc | kea-csv | kea-json | windows-xml | netsh | windows-csv;
    '' if none matches."""
    stripped = (text or "").lstrip("﻿ \t\r\n")
    head = stripped[:4000].lower()
    if not head:
        return ""
    if stripped[0] == "<":
        return "windows-xml" if ("<dhcpserver" in head or "<lease" in head or "<reservation" in head) else ""
    if stripped[0] in "{[":
        return "kea-json"
    if re.search(r"\blease\s+\d+\.\d+\.\d+\.\d+\s*\{", head):
        return "isc"
    if "hwaddr" in head and "valid_lifetime" in head:
        return "kea-csv"
    if "unique id" in head and "lease expires" in head:
        return "netsh"
    rows = [r for r in csv.reader(stripped.splitlines()[:15]) if any(c.strip() for c in r)]
    if any(_match_cols(r).get("ip") is not None for r in rows):
        return "windows-csv"
    return ""


_PARSERS = {
    "isc": parse_isc_leases, "kea-csv": parse_kea_csv, "kea-json": parse_kea_json,
    "windows-xml": parse_windows_xml, "netsh": parse_netsh_clients, "windows-csv": parse_windows_csv,
}


def parse_leases(text: str) -> list[Lease]:
    """Auto-detect the export format and parse it. Raises :class:`DhcpFormatError` (a
    ``ValueError``) with the supported formats when the text is not a recognised export."""
    fmt = detect_format(text)
    if not fmt:
        raise DhcpFormatError(
            "unrecognised DHCP export format. Supported: ISC dhcpd.leases, Kea memfile CSV, Kea "
            "lease4-get-all JSON, Windows Export-DhcpServer XML, 'netsh dhcp server ... show clients' "
            "text, and Windows lease CSV (Get-DhcpServerv4Lease | Export-Csv)."
        )
    return _PARSERS[fmt](text)


def import_leases(inv, leases: list[Lease]) -> dict:
    """Fold leases into the inventory: name hosts, fill MACs, mark DHCP scopes. Returns a summary.

    Only an active or reserved lease may create a host; a free/expired/inactive/declined/
    offered lease updates a host the inventory already knows and is otherwise skipped."""
    named = filled = new = scopes = skipped = 0
    scope_ips: dict[str, list[str]] = {}
    for lz in leases:
        inactive = lz.state in INACTIVE_STATES
        if lz.ip in inv.ip_to_device:
            continue  # it's a polled device; don't downgrade it to a host
        h = inv.hosts.get(lz.ip)
        if h is None and inactive:
            skipped += 1
            continue  # no phantom hosts for addresses nobody currently holds
        cidr = inv.subnet_for_ip(lz.ip)
        if cidr:
            scope_ips.setdefault(cidr, []).append(lz.ip)
        if h is None:
            h = inv.touch_host(lz.ip, "dhcp", lz.mac if plausible_mac(lz.mac) else None)
            new += 1
        if "dhcp" not in h.sources:
            h.sources.append("dhcp")
        if lz.mac and plausible_mac(lz.mac) and not h.mac:
            h.mac, h.mac_source = lz.mac, "dhcp"
            filled += 1
        if lz.hostname and not h.hostname and not inactive:
            h.hostname = lz.hostname
            named += 1
        if lz.hostname:
            h.names["dhcp"] = lz.hostname
        h.probes["dhcp"] = {"mac": lz.mac, "hostname": lz.hostname, "state": lz.state, "expires": lz.expires, "scope": lz.scope}
    # record which subnets are DHCP scopes, with how many leases landed in each
    for cidr, ips in scope_ips.items():
        inv.dhcp_scopes[cidr] = {"leases": len(set(ips)), "imported_at": time.time()}
        scopes += 1
    return {"leases": len(leases), "new_hosts": new, "named": named, "macs_filled": filled, "scopes": scopes, "skipped": skipped}
