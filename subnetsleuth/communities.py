"""Well-known factory-default SNMP community strings.

On a network you are taking over, the SNMP communities are rarely written down. Most
managed gear ships with SNMP turned off and *no* community, so you must set one; but a
great deal of equipment is left on the value it came with. The near-universal defaults are
``public`` (read) and ``private`` (read/write); beyond those only a handful of communities
turn up often enough in factory configurations and setup examples to be worth trying.

This module is that curated list. During a scan you can opt in to trying these *after* your
own credentials, read-only, inside the same ranges as every other step. A device that answers
one of them is reported as a finding ("still reachable on a factory-default community"): on an
inherited network that is exactly the sort of thing you want to find and change.

The list is deliberately short and documented, not a spraying word-list: each entry is a value
genuinely shipped as a default or used in vendors' own setup examples. Only the community label
is ever recorded with a device (via :data:`~subnetsleuth.model.Device.credential`); the string
itself is not written into project files.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid importing pysnmp (via .snmp) just to test a label
    from .snmp import Credential

# (community, access, note). `access` is what the value is a default *for*; we only ever GET,
# so a write-default community simply reveals a device that would also accept writes.
DEFAULT_COMMUNITIES: list[tuple[str, str, str]] = [
    ("public", "read", "Universal SNMP v1/v2c read-only default"),
    ("private", "write", "Universal SNMP v1/v2c read/write default"),
    ("cisco", "read", "Appears in Cisco setup examples and on some gear"),
    ("community", "read", "Common factory sample community"),
    ("snmp", "read", "Common factory sample community"),
    ("admin", "read", "Common on consumer and small-business network gear"),
    ("manager", "read", "Common management community"),
    ("monitor", "read", "Common read community used by monitoring setups"),
    ("read", "read", "Common read community"),
    ("write", "write", "Common read/write community"),
    ("default", "read", "Common factory sample community"),
    ("security", "read", "Shipped as a default on some devices"),
    ("ilmi", "read", "Historic Cisco Catalyst (CatOS) default community"),
    ("guest", "read", "Occasionally shipped as a default"),
]

# the label an auto-added default credential carries, e.g. "default community 'public'".
# Kept human-readable so it reads sensibly in the scan history and on a device's credential.
_LABEL_PREFIX = "default community"

# lower-cased set for fast membership tests (legacy projects stored the bare community as the
# credential label, so a device whose credential is simply "public" must still be recognised).
_DEFAULT_SET = {c.lower() for c, _, _ in DEFAULT_COMMUNITIES}


def default_label(community: str) -> str:
    """The credential label used for an auto-added default community."""
    return f"{_LABEL_PREFIX} '{community}'"


def default_community_creds(kinds: tuple[str, ...] = ("v2c",)) -> "list[Credential]":
    """Credentials for every curated default community, to append *after* the user's own.

    Tried in list order, so ``public``/``private`` come first. By default only v2c is tried;
    pass ``kinds=("v2c", "v1")`` to also try SNMPv1 for older agents that speak nothing else.
    """
    from .snmp import Credential

    out: list[Credential] = []
    for community, _access, _note in DEFAULT_COMMUNITIES:
        for kind in kinds:
            out.append(Credential(kind=kind, community=community, label=default_label(community)))
    return out


def is_default_community(credential_label: str) -> bool:
    """True if a device's recorded credential label is a factory-default community.

    Matches both an auto-added default credential ("default community 'public'") and a legacy
    or user credential whose label is itself a known default value ("public", "private", …).
    A credential the user named something of their own ("monitoring-ro") does not match.
    """
    label = (credential_label or "").strip().lower()
    if not label:
        return False
    return label.startswith(_LABEL_PREFIX) or label in _DEFAULT_SET
