"""Check the network against common enterprise hardening standards.

When you take over a network you usually have a baseline you must bring it to. This reads
what the scan already knows - which SNMP version answered, whether management planes are
cleartext, certificate health, hardware support status, spanning-tree and interface hygiene -
and lists where the estate does not meet a sensible default standard, with the fix.

Every check is read-only and derived from collected data. Findings carry a severity
(high/medium/low), a category, the item, what was found and the standard it breaks.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass


@dataclass
class Check:
    severity: str  # high | medium | low
    category: str
    node: str
    item: str
    found: str
    standard: str


SEV = {"high": 0, "medium": 1, "low": 2}


_V12_LABEL = re.compile(r"(^|[^a-z0-9])v(1|2c?)([^a-z0-9]|$)", re.I)
_V3_LABEL = re.compile(r"(^|[^a-z0-9])v3([^a-z0-9]|$)", re.I)


def _is_community_snmp(dev) -> bool:
    """Did this device answer SNMPv1/v2c? ``Device.snmp_version`` is authoritative when the
    collector recorded it. Older maps only carry the credential *label*, which is free text
    ("v2c:pub***" by default, but anything the user typed), so the fallback looks for a
    v1/v2c token in it, or a bare community string used as its own label; a label that
    names neither version is taken as unknown, not as v2c."""
    ver = (getattr(dev, "snmp_version", "") or "").lower()
    if ver:
        return ver in ("v1", "v2c", "1", "2c", "2")
    label = (dev.credential or "").strip()
    if not label or _V3_LABEL.search(label):
        return False
    return bool(_V12_LABEL.search(label)) or label.lower() in ("public", "private", "env")


def compliance_checks(snapshot) -> list[Check]:
    inv = snapshot.inv
    out: list[Check] = []

    def add(sev, cat, node, item, found, standard):
        out.append(Check(sev, cat, node, item, found, standard))

    try:
        from .eol import annotate_device
    except Exception:  # noqa: BLE001
        annotate_device = None

    for d in inv.devices.values():
        name = d.name or d.id
        # --- SNMP version ---
        if _is_community_snmp(d):
            add("medium", "SNMPv2c in use", d.id, name, f"answered SNMP {getattr(d, 'snmp_version', '') or d.credential}",
                "Use SNMPv3 with authentication and privacy; v1/v2c sends the community in clear and has no integrity")
        if (d.credential or "") in ("public", "private"):
            add("high", "Default SNMP community", d.id, name, f"community '{d.credential}'",
                "Replace default communities; 'public'/'private' are world-known and often writable")
        # --- management planes (from the TCP check and any nmap ports) ---
        mgmt = dict(getattr(d, "mgmt", {}) or {})
        open_ports = {p.get("port") for p in getattr(d, "ports", [])}
        if 23 in open_ports:
            mgmt["telnet"] = True
        if 80 in open_ports:
            mgmt["http"] = True
        if mgmt.get("telnet"):
            add("high", "Telnet enabled", d.id, name, "TCP/23 open",
                "Disable Telnet and manage over SSH; Telnet carries credentials and sessions in clear")
        if mgmt.get("http"):
            add("medium", "Cleartext web management", d.id, name, "TCP/80 open",
                "Serve the management UI over HTTPS only and redirect or disable HTTP")
        # --- hardware support ---
        if annotate_device is not None:
            e = annotate_device(d)
            if e and e.get("status") == "end-of-support":
                add("high", "Past end-of-support", d.id, name, f"{e.get('family', d.model)} (EoL {e.get('eol', '?')})",
                    "Replace hardware that is past vendor end-of-support: no security fixes or TAC")
            elif e and e.get("status") == "end-of-sale":
                add("low", "Approaching end-of-life", d.id, name, f"{e.get('family', d.model)} (EoL {e.get('eol', '?')})",
                    "Plan replacement before end-of-support")
        # --- spanning tree left at defaults on an L2 core ---
        stp = getattr(d, "stp", {}) or {}
        if stp.get("is_root") and _default_stp_priority(stp.get("priority")) and d.role in ("switch", "l3switch"):
            add("low", "Spanning-tree root by default", d.id, name, f"root at default priority {stp.get('priority')}",
                "Set the root bridge deliberately (lower priority on the intended core) so a rogue switch cannot win the election")
        # --- interface hygiene ---
        idle = [i for i in d.interfaces if i.admin_up and not i.oper_up and not i.ips
                and not snapshot.port_neighbors.get((d.id, i.index)) and not snapshot.port_macs.get((d.id, i.index))]
        if len(idle) >= 8:
            add("low", "Unused ports left enabled", d.id, name, f"{len(idle)} admin-up ports with nothing connected",
                "Shut down unused access ports (or put them in a dead VLAN) to reduce the attack surface")

    # --- certificate health, from host web probes ---
    for ip, h in inv.hosts.items():
        if ip in inv.ip_to_device:
            continue
        for e in (h.probes.get("http") or {}).values() if isinstance(h.probes.get("http"), dict) else []:
            if not isinstance(e, dict) or not e.get("tls"):
                continue
            exp = e.get("cert_expires")
            if exp and _expired(exp):
                add("medium", "Expired TLS certificate", ip, snapshot.name(ip), f"certificate expired {exp}",
                    "Replace expired certificates on management interfaces")
    return sorted(out, key=lambda c: (SEV.get(c.severity, 9), c.category, c.item))


def _default_stp_priority(prio) -> bool:
    """32768 is the default; with the 802.1t extended system ID a switch reports
    32768 + VLAN (32769 for VLAN 1), so test the upper nibble. 0 is the lowest value there is:
    someone set it on purpose to make this the root, the opposite of a default."""
    try:
        p = int(prio)
    except (TypeError, ValueError):
        return False
    return p != 0 and (p & 0xF000) == 0x8000


def _expired(when: str) -> bool:
    for fmt in ("%Y-%m-%d", "%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            return time.mktime(time.strptime(when.strip(), fmt)) < time.time()
        except (ValueError, OverflowError):
            continue
    return False


def summary(checks: list[Check]) -> dict:
    out = {"high": 0, "medium": 0, "low": 0}
    for c in checks:
        out[c.severity] = out.get(c.severity, 0) + 1
    return out
