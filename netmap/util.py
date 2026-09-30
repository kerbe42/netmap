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


# MACs that are not a real endpoint's hardware address. `12:34:56:78:9a:bc` is a stock
# example that nmap on Windows can emit for hosts it cannot actually ARP (e.g. across a
# router or a VPN), which is why the same value turns up on many hosts at once.
BOGUS_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
    "12:34:56:78:9a:bc",
    "01:23:45:67:89:ab",
    "aa:bb:cc:dd:ee:ff",
    "de:ad:be:ef:de:ad",
    "11:22:33:44:55:66",
    "00:11:22:33:44:55",
    "88:88:88:88:88:88",
    "02:00:4c:4f:4f:50",  # Npcap Loopback Adapter ("LOOP")
}


def plausible_mac(mac: Optional[str]) -> bool:
    """True if `mac` could be a real host's hardware address.

    Rejects all-zero / broadcast, multicast (a source/host MAC is never multicast), the
    stock placeholders above, and single-octet-repeated values. It deliberately keeps
    locally-administered addresses: modern phones and laptops use randomised MACs.
    """
    m = norm_mac(mac)
    if not m or m in BOGUS_MACS:
        return False
    first = int(m[:2], 16)
    if first & 0x01:  # group/multicast bit set - not an endpoint's own address
        return False
    octets = m.split(":")
    if len(set(octets)) == 1:  # 11:11:11:11:11:11 and friends
        return False
    return True


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


def portlist_ports(b) -> set[int]:
    """Bridge port numbers set in a Q-BRIDGE PortList (the MSB of the first octet is port 1)."""
    if not isinstance(b, (bytes, bytearray)):
        return set()
    return {i * 8 + bit + 1 for i, byte in enumerate(b) if byte for bit in range(8) if byte & (0x80 >> bit)}


# First match wins, so specific shapes go before the generic "Version x.y": several of
# these texts also say "version" about something else, or not at all. Groups that matched
# are joined with a space ("6.3 Build 17763").
_OS_VERSION_RES = [
    re.compile(p, flags)
    for p, flags in (
        (r"\bWindows\b.*?\bVersion\s+(\d+\.\d+)\s*\((Build\s+\d+)", re.I),  # Windows Version 6.3 (Build 17763 ...)
        (r"\bJUNOS(?:\s+OS)?(?:\s+Evolved)?\s+\[?(\d+\.\d+[\w.\-]*)", re.I),  # kernel JUNOS 21.2R3-S2.9
        (r"\bv(\d+\.\d+\.\d+),\s*build\s*\d+", re.I),  # FortiGate-60F v7.2.5,build1517,230606 (GA.F)
        (r"\bFortiOS\s+v?(\d+\.\d+\.\d+)", re.I),
        (r"\bPAN-OS\s+(?:version\s+)?(\d+\.\d+[\w.\-]*)", re.I),
        (r"\bSonicOS\s+(?:Enhanced\s+)?v?(\d+\.\d+[\w.\-]*)", re.I),
        (r"\bRouterOS\s+v?(\d+\.\d+[\w.\-]*)", re.I),  # "RouterOS RB4011iGS+" is a model, not a version
        (r"\bEdgeOS\s+v?(\d+\.\d+\.\d+(?:-hotfix\.\d+)?)", re.I),  # drop the build id and date
        (r"^[^,]+,\s*v?(\d+\.\d+\.\d+(?:\.\d+)?),\s*Linux\b", 0),  # UniFi/EdgeSwitch: "USW-24-PoE, 6.5.59.14777, Linux 3.6.5"
        (r"\brevision\s+([A-Z]{1,2}\.\d{1,2}\.\d{1,2}(?:\.\d{1,4})?)", 0),  # ProCurve: revision YA.16.10.0016, ROM ...
        (r"\b([A-Z]{2}\.\d{2}\.\d{2}\.\d{4})\b", 0),  # AOS-CX: Aruba JL658A 6300M ... FL.10.08.1010
        (r"\bCumulus Linux\s+(?:version\s+)?(\d+\.\d+[\w.\-]*)", re.I),
        (r"\bVMware ESXi?\s+(\d+\.\d+(?:\.\d+)?)(?:\s+(build-\d+))?", re.I),
        (r"\b(?:pfSense|OPNsense)\s+\S+\s+(\d+\.\d+[\w.\-]*)", re.I),
        (r"\bversion\b\s*[:=]?\s*v?(\d+\.\d+[\w.()\-+]*)", re.I),  # IOS, IOS-XE, IOS-XR, NX-OS, ASA, EOS, ArubaOS, EXOS, OS10
    )
]
_KERNEL_RES = [re.compile(r"^Linux\s+\S+\s+(\d+\.\d+[\w.\-+~]*)"), re.compile(r"^FreeBSD\s+\S+\s+(\d+\.\d+[\w.\-]*)")]
# A kernel release is the OS version of a server, but not of an appliance that happens to
# run Linux (Check Point Gaia, Synology DSM): there it would be confidently wrong.
_KERNEL_IS_OS = {"", "linux", "net-snmp", "ucd-snmp", "freebsd/pfsense"}


def parse_os_version(sysdescr: str, vendor: str = "") -> str:
    """The software version a sysDescr announces, concise ("16.12.4", "9.3(8)", "20.4R3-S2"). '' if none."""
    text = (sysdescr or "").strip()
    if not text:
        return ""
    for rx in _OS_VERSION_RES:
        m = rx.search(text)
        if m:
            return " ".join(g for g in m.groups() if g).rstrip(".,;:-(")[:40]
    if (vendor or "").strip().lower() in _KERNEL_IS_OS:
        for rx in _KERNEL_RES:
            m = rx.search(text)
            if m:
                return m.group(1).rstrip(".,;:-")[:40]
    return ""


def enterprise_from_sysobjectid(soid: str) -> Optional[int]:
    parts = soid.split(".")
    if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
        try:
            return int(parts[6])
        except ValueError:
            return None
    return None
