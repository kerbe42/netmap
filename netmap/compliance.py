"""Check the network against common enterprise hardening standards.

When you take over a network you usually have a baseline you must bring it to. This reads
what the scan already knows - which SNMP version answered, whether management planes are
cleartext, certificate health, hardware support status, spanning-tree and interface hygiene -
and lists where the estate does not meet a sensible default standard, with the fix.

Every check is read-only and derived from collected data. Findings carry a severity
(high/medium/low), a category, the item, what was found and the standard it breaks.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Check:
    severity: str  # high | medium | low
    category: str
    node: str
    item: str
    found: str
    standard: str


SEV = {"high": 0, "medium": 1, "low": 2}


def _cred_is_v2c(label: str) -> bool:
    return label.startswith("v2c") or label in ("public", "private", "env")


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
        if _cred_is_v2c(d.credential or ""):
            add("medium", "SNMPv2c in use", d.id, name, f"answered SNMP {d.credential}",
                "Use SNMPv3 with authentication and privacy; v1/v2c sends the community in clear and has no integrity")
        if (d.credential or "") in ("public", "private"):
            add("high", "Default SNMP community", d.id, name, f"community '{d.credential}'",
                "Replace default communities; 'public'/'private' are world-known and often writable")
        # --- management planes ---
        mgmt = getattr(d, "mgmt", {}) or {}
        if mgmt.get("telnet"):
            add("high", "Telnet enabled", d.id, name, "TCP/23 open",
                "Disable Telnet and manage over SSH; Telnet carries credentials and sessions in clear")
        if mgmt.get("http") and not mgmt.get("telnet"):
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
        if stp.get("is_root") and stp.get("priority") in (32768, 0) and d.role in ("switch", "l3switch"):
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
