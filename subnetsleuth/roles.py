"""How roles are grouped for the overview and the reports.

Every node SubnetSleuth knows has a fine-grained *role* (switch, webserver, printer, …). Two
coarser questions matter at a glance, and the dashboard used to answer them with two lists that
overlapped because both were keyed on the same roles:

* Is this part of the **network** itself (a firewall, router, switch or access point), or is it
  an **endpoint** attached to the network?
* For the endpoints, what broad **kind** are they (servers, PCs, phones, printers …) — without
  splitting servers into a dozen sub-types that are already shown under "Server functions"?

This module is the single source of truth for both groupings, so the overview, the spreadsheet
export and the CLI summary all agree. It is deliberately free of any GUI dependency.
"""
from __future__ import annotations

# The network fabric itself. These are counted under "Network infrastructure", wherever they
# were found - whether they answered SNMP or were only seen as an LLDP/CDP neighbour or a MAC.
NETWORK_ROLES = frozenset({"firewall", "router", "l3switch", "switch", "wireless"})

# Endpoint groups, in display order: (key, label, {roles}, representative role for the icon).
# The key is a single word used as a filter token ("group:servers"); keep them collision-free.
ENDPOINT_GROUPS: list[tuple[str, str, frozenset, str]] = [
    ("servers", "Servers", frozenset({"server", "webserver", "fileserver", "mailserver",
                                      "dnsserver", "dc", "database", "hypervisor", "vm"}), "server"),
    ("pcs", "PCs & laptops", frozenset({"workstation", "windows"}), "workstation"),
    ("phones", "Phones", frozenset({"phone"}), "phone"),
    ("printers", "Printers", frozenset({"printer"}), "printer"),
    ("cameras", "Cameras & AV", frozenset({"camera", "media"}), "camera"),
    ("storage", "Storage", frozenset({"nas"}), "nas"),
    ("facilities", "Facilities & OT", frozenset({"ups", "plc", "bms", "ot"}), "plc"),
    ("lightsout", "Lights-out (BMC)", frozenset({"bmc"}), "bmc"),
    ("other", "Other / unknown", frozenset({"host", "unknown", "unpolled", ""}), "host"),
]

_OTHER = "other"
# role -> group key / label / icon, built once from the table above.
_ROLE_GROUP: dict[str, tuple[str, str, str]] = {}
for _key, _label, _roles, _icon in ENDPOINT_GROUPS:
    for _r in _roles:
        _ROLE_GROUP[_r] = (_key, _label, _icon)

# group key -> (label, icon, order), for turning a stored `group` back into something to show.
GROUP_LABEL: dict[str, str] = {k: lbl for k, lbl, _, _ in ENDPOINT_GROUPS}
GROUP_ICON: dict[str, str] = {k: icon for k, _, _, icon in ENDPOINT_GROUPS}
GROUP_ORDER: dict[str, int] = {k: i for i, (k, _, _, _) in enumerate(ENDPOINT_GROUPS)}


def is_network_role(role: str) -> bool:
    """True for the network fabric itself (firewall/router/switch/L3 switch/wireless)."""
    return (role or "") in NETWORK_ROLES


def endpoint_group(role: str) -> tuple[str, str, str]:
    """(group key, group label, icon role) for an endpoint role. A network role, or any role
    this table doesn't list, falls into "Other / unknown"."""
    return _ROLE_GROUP.get(role or "", _ROLE_GROUP.get(_OTHER, (_OTHER, "Other / unknown", "host")))


def group_key(role: str) -> str:
    """The endpoint-group key for a role, e.g. the value stored in a row's hidden `group`
    column so ``group:servers`` filters the list. Network roles return ``"network"``."""
    if is_network_role(role):
        return "network"
    return endpoint_group(role)[0]
