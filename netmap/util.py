import ipaddress
import os
import sys
import re
from typing import Iterable, Optional


def resource_path(*parts: str) -> str:
    """Path to a bundled data file, working both from source and from a PyInstaller
    one-file binary (where data lives under sys._MEIPASS)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, "netmap", *parts)
    return os.path.join(os.path.dirname(__file__), *parts)

RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ALWAYS_EXCLUDED = [
    ipaddress.ip_network(n)
    for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32")
]
if os.environ.get("NETMAP_ALLOW_LOOPBACK"):  # lab/simulator testing against agents bound on 127/8
    ALWAYS_EXCLUDED = [n for n in ALWAYS_EXCLUDED if str(n) != "127.0.0.0/8"]


def oid_suffix(oid: str, base: str) -> list[int]:
    """Return the integer components of `oid` after `base` (empty list if not under base)."""
    if not oid.startswith(base + "."):
        return []
    return [int(x) for x in oid[len(base) + 1 :].split(".")]


def mac_from_bytes(b: Optional[bytes]) -> Optional[str]:
    if not b or len(b) != 6:
        return None
    return ":".join(f"{x:02x}" for x in b)


def mac_from_ints(parts: Iterable[int]) -> Optional[str]:
    parts = list(parts)
    if len(parts) != 6:
        return None
    return ":".join(f"{x:02x}" for x in parts)


def norm_mac(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    hexs = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(hexs) != 12:
        return None
    return ":".join(hexs[i : i + 2].lower() for i in range(0, 12, 2))


def ip_from_ints(parts: Iterable[int]) -> Optional[str]:
    parts = list(parts)
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return None
    return ".".join(str(p) for p in parts)


def mask_to_prefix(mask: str) -> int:
    return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen


def to_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace").strip("\x00").strip()
    return str(v).strip()


def is_usable_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version != 4:
        return False
    return not any(a in n for n in ALWAYS_EXCLUDED)


def in_scope(ip: str, allow: list, deny: list) -> bool:
    if not is_usable_ip(ip):
        return False
    a = ipaddress.ip_address(ip)
    if any(a in n for n in deny):
        return False
    return any(a in n for n in allow)


def short_name(name: str) -> str:
    """Lower-case, strip domain suffix and CDP '(serial)' decoration for fuzzy hostname matching."""
    n = (name or "").strip().lower()
    n = re.sub(r"\(.*?\)$", "", n)
    return n.split(".")[0] if n and not re.match(r"^\d+\.\d+\.\d+\.\d+$", n) else n


_OUI: Optional[dict] = None


def _load_oui() -> dict:
    global _OUI
    if _OUI is None:
        _OUI = {}
        path = resource_path("data", "oui.tsv")
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.startswith("#") or "\t" not in line:
                        continue
                    prefix, vendor = line.rstrip("\n").split("\t", 1)
                    _OUI[prefix.upper()] = vendor
        except OSError:
            pass
    return _OUI


def oui_vendor(mac: Optional[str]) -> str:
    """Organization that owns a MAC address's OUI, from the bundled IEEE table. '' if unknown."""
    if not mac:
        return ""
    hexs = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(hexs) < 6:
        return ""
    return _load_oui().get(hexs[:6], "")


def enterprise_from_sysobjectid(soid: str) -> Optional[int]:
    parts = soid.split(".")
    if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
        try:
            return int(parts[6])
        except ValueError:
            return None
    return None
