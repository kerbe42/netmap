"""Import DHCP leases and scopes exported from the servers that run the network.

When you inherit a network the DHCP server knows things SNMP does not: which addresses are
handed out, the names clients registered, and the MAC behind each. This reads the common
export formats (ISC/Kea dhcpd, and Windows DHCP CSV) and folds them into the inventory -
naming hosts, filling MACs, and marking which subnets are DHCP scopes.

Everything here is offline file parsing; nothing talks to a server.
"""
from __future__ import annotations

import csv
import ipaddress
import re
import time
from dataclasses import dataclass, field

from .util import is_usable_ip, norm_mac, plausible_mac


@dataclass
class Lease:
    ip: str
    mac: str = ""
    hostname: str = ""
    state: str = ""  # active | free | expired | reserved
    expires: str = ""
    scope: str = ""  # scope/subnet id if the export gave one


def parse_isc_leases(text: str) -> list[Lease]:
    """ISC dhcpd `dhcpd.leases`: blocks like `lease 10.0.0.5 { ... }`."""
    out = []
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
        st = re.search(r"binding state\s+(\w+)", body)
        if st:
            lease.state = {"active": "active", "free": "free", "expired": "expired", "backup": "active"}.get(st.group(1), st.group(1))
        ends = re.search(r"ends\s+\d+\s+([\d/]+\s+[\d:]+)", body)
        if ends:
            lease.expires = ends.group(1)
        out.append(lease)
    return out


def parse_kea_csv(text: str) -> list[Lease]:
    """Kea memfile CSV: header includes address,hwaddr,client_id,valid_lifetime,expire,...,hostname,state."""
    rows = list(csv.DictReader(text.splitlines()))
    out = []
    for r in rows:
        ip = (r.get("address") or "").strip()
        if not is_usable_ip(ip):
            continue
        state = {"0": "active", "1": "expired", "2": "expired"}.get((r.get("state") or "").strip(), "active")
        exp = r.get("expire", "")
        if exp and exp.isdigit():
            exp = time.strftime("%Y-%m-%d %H:%M", time.localtime(int(exp)))
        out.append(Lease(ip=ip, mac=norm_mac(r.get("hwaddr")) or "", hostname=(r.get("hostname") or "").strip(), state=state, expires=exp))
    return out


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
        state = g("state").lower()
        state = "active" if "active" in state else ("reserved" if "reserv" in state else ("expired" if state else ""))
        mac = g("mac")
        # Windows ClientId is often the MAC with dashes
        out.append(Lease(ip=ip, mac=norm_mac(mac) or "", hostname=g("hostname").split(".")[0], state=state, expires=g("expires"), scope=g("scope")))
    return out


def parse_leases(text: str) -> list[Lease]:
    """Auto-detect the export format and parse it."""
    head = text[:4000].lower()
    if "lease " in head and "{" in head:
        return parse_isc_leases(text)
    if "hwaddr" in head and "valid_lifetime" in head:
        return parse_kea_csv(text)
    return parse_windows_csv(text)


def import_leases(inv, leases: list[Lease]) -> dict:
    """Fold leases into the inventory: name hosts, fill MACs, mark DHCP scopes. Returns a summary."""
    named = filled = new = scopes = 0
    scope_ips: dict[str, list[str]] = {}
    for lz in leases:
        if lz.state in ("free", "expired") and not lz.hostname and not lz.mac:
            continue
        cidr = inv.subnet_for_ip(lz.ip)
        if cidr:
            scope_ips.setdefault(cidr, []).append(lz.ip)
        if lz.ip in inv.ip_to_device:
            continue  # it's a polled device; don't downgrade it to a host
        h = inv.hosts.get(lz.ip)
        if h is None:
            h = inv.touch_host(lz.ip, "dhcp", lz.mac if plausible_mac(lz.mac) else None)
            new += 1
        if "dhcp" not in h.sources:
            h.sources.append("dhcp")
        if lz.mac and plausible_mac(lz.mac) and not h.mac:
            h.mac, h.mac_source = lz.mac, "dhcp"
            filled += 1
        if lz.hostname and not h.hostname:
            h.hostname = lz.hostname
            named += 1
        if lz.hostname:
            h.names["dhcp"] = lz.hostname
        h.probes["dhcp"] = {"mac": lz.mac, "hostname": lz.hostname, "state": lz.state, "expires": lz.expires, "scope": lz.scope}
    # record which subnets are DHCP scopes, with how many leases landed in each
    for cidr, ips in scope_ips.items():
        inv.dhcp_scopes[cidr] = {"leases": len(set(ips)), "imported_at": time.time()}
        scopes += 1
    return {"leases": len(leases), "new_hosts": new, "named": named, "macs_filled": filled, "scopes": scopes}
