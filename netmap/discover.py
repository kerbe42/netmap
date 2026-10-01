"""Active, read-only host-identification probes - pure Python, stdlib only.

These are the signals that let a tool tell a Windows workstation from a Chromecast from a
Cisco appliance without SNMP, without nmap and without administrator rights: what a host
volunteers when you knock politely on the discovery protocols it already speaks. Every probe
sends at most a packet or two, times out fast, only reads, and never writes or changes
anything on the target. A probe that cannot answer returns None and never raises out of the
orchestrator.

Each protocol is split into a *pure parser* over captured bytes and a thin socket wrapper, so
the wire format can be unit-tested without touching the network:

    NetBIOS node status (UDP 137)  parse_nbstat  / netbios_node_status
    mDNS / Bonjour     (UDP 5353)  parse_mdns    / mdns_query
    SSDP / UPnP        (UDP 1900)  parse_ssdp, parse_upnp_xml / ssdp_probe
    HTTP / TLS banner  (TCP)       parse_http_head, title_from_html, cert_fields / http_banner

`identify_hosts` runs the enabled probes concurrently over the inventory and records the raw
signals and discovered names on each Host. It does not decide role/os - a separate profiling
module reads what this one records.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import struct
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from . import activity
from .model import Inventory
from .util import is_usable_ip, norm_mac, plausible_mac

log = logging.getLogger("netmap.discover")

# Web ports we are willing to knock on for an HTTP banner, and which of them speak TLS.
WEB_PORTS = (80, 443, 8080, 8443, 8000, 8008, 8888, 8081, 4443, 9443)
TLS_PORTS = frozenset({443, 8443, 4443, 9443, 9091})
# A MAC learned any of these ways is weak: a NetBIOS adapter MAC (authoritative across L3)
# should overwrite it. An empty/never-set source counts as weak too.
WEAK_MAC_SOURCES = frozenset({"", "sweep", "guess", "dns", "mdns", "ssdp", "ssdp-guess"})

# NetBIOS suffixes worth naming (the last byte of a 16-byte NetBIOS name).
NB_WORKSTATION = 0x00
NB_MESSENGER = 0x03  # a unique <03> that is not the computer name is the logged-on user
NB_SERVER = 0x20
NB_DC_GROUP = 0x1C   # <domain><1C> is registered by domain controllers
NB_MASTER_BROWSER = 0x1D
NB_BROWSER_ELECTION = 0x1E


def _plausible_mac(mac: Optional[str]) -> Optional[str]:
    """Normalise a MAC and reject the ones that are not a real endpoint address."""
    m = norm_mac(mac)
    return m if m and plausible_mac(m) else None


# --------------------------------------------------------------------------- #
# 1. NetBIOS node status (UDP 137)
# --------------------------------------------------------------------------- #
def _encode_netbios_name(name: str = "*") -> bytes:
    """First-level NetBIOS name encoding: pad to 16 bytes, split each into two nibbles,
    add 'A' to each. The wildcard "*" is "*" then 15 NULs."""
    raw = name.encode("ascii", "replace")[:16]
    raw = raw + b"\x00" * (16 - len(raw))
    out = bytearray()
    for b in raw:
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


def _build_nbstat_query(txid: int = 0x4242) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)  # 1 question, query
    qname = bytes([0x20]) + _encode_netbios_name("*") + b"\x00"
    question = struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + qname + question


def _skip_dns_name(data: bytes, off: int) -> int:
    """Advance past a length-prefixed name (label list or a compression pointer)."""
    n = len(data)
    while off < n:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # pointer: two bytes, no terminator
            return off + 2
        off += 1 + length
    return off


def parse_nbstat(data: bytes) -> Optional[dict]:
    """Decode a NetBIOS node-status response: its registered names and the adapter MAC.

    Returns {"names":[{name,suffix,group}], "hostname", "domain", "user", "mac", "is_dc"}
    or None if the bytes are not a usable response.
    """
    if not data or len(data) < 12:
        return None
    try:
        _txid, _flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if ancount < 1:
            return None
        off = _skip_dns_name(data, 12)          # answer RR name
        if off + 10 > len(data):
            return None
        off += 2 + 2 + 4                         # type, class, ttl
        _rdlength = struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        num_names = data[off]
        off += 1

        names: list[dict] = []
        for _ in range(num_names):
            if off + 18 > len(data):
                break
            raw = data[off:off + 15]
            suffix = data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            name = raw.decode("ascii", "replace").rstrip(" \x00").strip()
            names.append({"name": name, "suffix": suffix, "group": bool(flags & 0x8000)})

        mac = None
        if off + 6 <= len(data):
            mac = _plausible_mac(":".join(f"{b:02x}" for b in data[off:off + 6]))
    except (struct.error, IndexError):
        return None

    hostname = domain = user = None
    is_dc = False
    for entry in names:
        s, nm, grp = entry["suffix"], entry["name"], entry["group"]
        if s == NB_WORKSTATION and not grp and hostname is None:
            hostname = nm
        elif s == NB_WORKSTATION and grp and domain is None:
            domain = nm
        elif s == NB_DC_GROUP:
            is_dc = True
            if domain is None:
                domain = nm
    for entry in names:
        if entry["suffix"] == NB_MESSENGER and not entry["group"] and entry["name"] and entry["name"] != hostname:
            user = entry["name"]
            break

    return {
        "names": names,
        "hostname": hostname,
        "domain": domain,
        "user": user,
        "mac": mac,
        "is_dc": is_dc,
    }


def netbios_node_status(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Send one NBSTAT request to UDP/137 and parse the reply. None on any failure."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_nbstat_query(), (ip, 137))
        data, _ = sock.recvfrom(4096)
        return parse_nbstat(data)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 2. mDNS / Bonjour (UDP 5353)
# --------------------------------------------------------------------------- #
# type numbers
_A, _PTR, _TXT, _AAAA, _SRV = 1, 12, 16, 28, 33

_MDNS_SERVICE_HINTS = {
    "_ipp": "printer", "_ipps": "printer", "_printer": "printer",
    "_pdl-datastream": "printer", "_scanner": "scanner", "_uscan": "scanner", "_uscans": "scanner",
    "_airplay": "apple-av", "_raop": "apple-av", "_airport": "apple",
    "_googlecast": "chromecast",
    "_homekit": "homekit", "_hap": "homekit",
    "_afpovertcp": "file", "_smb": "file", "_nfs": "file",
    "_ssh": "ssh", "_sftp-ssh": "ssh", "_http": "http", "_https": "http",
    "_workstation": "workstation", "_device-info": "device-info",
}
_MDNS_VENDOR = {
    "chromecast": "Google", "apple-av": "Apple", "apple": "Apple", "homekit": "Apple",
}


def _read_dns_name(data: bytes, off: int) -> tuple[str, int]:
    """Read a DNS name (labels with 0xC0 compression pointers). Returns (name, next_off)."""
    labels: list[str] = []
    n = len(data)
    jumped = False
    resume = off
    hops = 0
    while off < n:
        length = data[off]
        if length == 0:
            off += 1
            if not jumped:
                resume = off
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= n:
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                resume = off + 2
            jumped = True
            hops += 1
            if hops > 64 or ptr >= n:
                break
            off = ptr
            continue
        off += 1
        labels.append(data[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), resume


def parse_mdns(data: bytes) -> Optional[dict]:
    """Decode an mDNS response into advertised service types, a .local name, and model/vendor.

    Returns {"hostname", "services", "model", "vendor"} or None on unparseable input.
    """
    if not data or len(data) < 12:
        return None
    try:
        _id, _flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        off = 12
        for _ in range(qd):                       # skip questions
            _name, off = _read_dns_name(data, off)
            off += 4

        services: list[str] = []
        model = None
        hostname = None
        srv_target = None
        a_names: list[str] = []
        strings: list[str] = []

        for _ in range(an + ns + ar):
            if off + 1 > len(data):
                break
            name, off = _read_dns_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlength]
            rend = off + rdlength
            strings.append(name)
            if rtype == _PTR:
                target, _ = _read_dns_name(data, off)
                strings.append(target)
            elif rtype == _TXT:
                i = 0
                while i < len(rdata):
                    slen = rdata[i]
                    i += 1
                    chunk = rdata[i:i + slen].decode("utf-8", "replace")
                    i += slen
                    if "=" in chunk:
                        k, v = chunk.split("=", 1)
                        if k.strip().lower() in ("model", "md", "am") and v and model is None:
                            model = v.strip()
            elif rtype == _A and name.endswith(".local"):
                a_names.append(name)
            elif rtype == _SRV and rdlength >= 6:
                srv_target, _ = _read_dns_name(data, off + 6)
            off = rend

        # advertised service types: the "_foo._tcp" tokens seen anywhere in the message
        seen = set()
        for s in strings:
            m = re.search(r"(_[a-z0-9-]+)\._(?:tcp|udp)", s, re.I)
            if m:
                svc = m.group(0)
                if svc.lower() not in seen:
                    seen.add(svc.lower())
                    services.append(svc)

        for cand in (srv_target, *a_names):
            if cand and cand.endswith(".local"):
                hostname = cand
                break

        vendor = ""
        for svc in services:
            head = svc.split(".", 1)[0].lower()
            role = _MDNS_SERVICE_HINTS.get(head)
            if role and role in _MDNS_VENDOR:
                vendor = _MDNS_VENDOR[role]
                break
    except (struct.error, IndexError, UnicodeError):
        return None

    if not services and not hostname and model is None:
        return None
    return {"hostname": hostname, "services": services, "model": model, "vendor": vendor}


def _build_mdns_query(name: str = "_services._dns-sd._udp.local", qtype: int = _PTR) -> bytes:
    header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    q = bytearray()
    for label in name.split("."):
        q.append(len(label))
        q += label.encode("ascii", "replace")
    q.append(0)
    q += struct.pack(">HH", qtype, 0x8001)  # QU bit set (0x8000) => request a unicast reply
    return header + bytes(q)


def mdns_query(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Unicast an mDNS service-enumeration query to UDP/5353 and parse the reply."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_mdns_query(), (ip, 5353))
        data, _ = sock.recvfrom(9000)
        return parse_mdns(data)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 3. SSDP / UPnP (UDP 1900 + HTTP fetch of the device description)
# --------------------------------------------------------------------------- #
def parse_ssdp(data: bytes) -> Optional[dict]:
    """Parse an SSDP (HTTP-over-UDP) response's headers."""
    if not data:
        return None
    try:
        text = data.decode("iso-8859-1", "replace")
    except Exception:  # noqa: BLE001
        return None
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or "HTTP/" not in lines[0].upper():
        # some devices reply with a NOTIFY line; still parse the headers
        if not any(":" in ln for ln in lines):
            return None
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if not headers:
        return None
    return {
        "server": headers.get("server"),
        "st": headers.get("st"),
        "location": headers.get("location"),
        "usn": headers.get("usn"),
        "headers": headers,
    }


def parse_upnp_xml(text: str) -> dict:
    """Pull the identifying fields out of a UPnP device-description XML document."""
    out = {
        "friendly_name": None, "manufacturer": None, "model": None,
        "model_number": None, "device_type": None,
    }
    if not text:
        return out
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    wanted = {
        "friendlyName": "friendly_name",
        "manufacturer": "manufacturer",
        "modelName": "model",
        "modelNumber": "model_number",
        "deviceType": "device_type",
    }
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]  # drop XML namespace
        key = wanted.get(tag)
        if key and out[key] is None and el.text and el.text.strip():
            out[key] = el.text.strip()
    return out


def _build_msearch(ip: str, st: str = "ssdp:all", mx: int = 1) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {mx}\r\n"
        f"ST: {st}\r\n"
        "\r\n"
    ).encode("ascii", "replace")


def _fetch_upnp_description(location: str, timeout: float = 2.0, cap: int = 64 * 1024,
                            ip: Optional[str] = None) -> dict:
    """GET the LOCATION XML (short timeout, small body cap) and parse it. {} on failure.

    When `ip` (the probed address) is given the URL must point at that same address: a
    device may advertise any LOCATION it likes, and following it elsewhere would send
    traffic to an address that was never in scope. Such a LOCATION is recorded raw only."""
    import http.client
    from urllib.parse import urlsplit

    try:
        u = urlsplit(location)
        if u.scheme not in ("http", "https") or not u.hostname:
            return {}
        if ip is not None and u.hostname != ip:
            log.debug("ssdp %s: LOCATION %s points elsewhere; not fetched", ip, location)
            return {}
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        kwargs = {"timeout": timeout}
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            kwargs["context"] = ctx
        conn = conn_cls(u.hostname, u.port or (443 if u.scheme == "https" else 80), **kwargs)
        try:
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            conn.request("GET", path, headers={"Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(cap).decode("utf-8", "replace")
        finally:
            conn.close()
        return parse_upnp_xml(body)
    except (OSError, http.client.HTTPException, ValueError):
        return {}


def ssdp_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Unicast M-SEARCH to UDP/1900, then fetch and parse the device description if offered."""
    if not is_usable_ip(ip):
        return None
    sock = None
    result: Optional[dict] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_msearch(ip), (ip, 1900))
        data, _ = sock.recvfrom(4096)
        result = parse_ssdp(data)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not result:
        return None
    out = {
        "server": result.get("server"),
        "st": result.get("st"),
        "location": result.get("location"),
        "usn": result.get("usn"),
        "friendly_name": None,
        "manufacturer": None,
        "model": None,
        "model_number": None,
        "device_type": None,
    }
    if result.get("location"):
        try:
            out.update({k: v for k, v in _fetch_upnp_description(result["location"], timeout, ip=ip).items() if v})
        except Exception:  # noqa: BLE001  - a bad description must never sink the probe
            pass
    return out


# --------------------------------------------------------------------------- #
# 4. HTTP / TLS banner (TCP)
# --------------------------------------------------------------------------- #
def parse_http_head(data: bytes) -> dict:
    """Parse an HTTP response's status line and headers (Server, WWW-Authenticate realm, ...)."""
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("iso-8859-1", "replace")
    else:
        text = data or ""
    head = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    lines = head.replace("\r\n", "\n").split("\n")
    status = None
    if lines:
        parts = lines[0].split(None, 2)
        if len(parts) >= 2 and parts[1].isascii() and parts[1].isdigit():
            status = int(parts[1])
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    realm = None
    wa = headers.get("www-authenticate", "")
    if wa:
        m = re.search(r'realm\s*=\s*"?([^",]+)"?', wa, re.I)
        if m:
            realm = m.group(1).strip().strip('"')
    return {
        "status": status,
        "server": headers.get("server"),
        "realm": realm,
        "www_authenticate": wa or None,
        "headers": headers,
    }


def title_from_html(text) -> Optional[str]:
    """The <title> of a (partial) HTML document, whitespace-collapsed. None if absent."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    if not text:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title or None


def _rdn_value(rdns, keys) -> Optional[str]:
    """Find the first value in an RFC-2459 name (tuple of RDNs) whose attribute is in `keys`."""
    for rdn in rdns or ():
        for attr, value in rdn:
            if attr in keys:
                return value
    return None


def cert_subject_org(cert: Optional[dict]) -> Optional[str]:
    """The subject organizationName of a getpeercert()-style dict (the vendor of an appliance's
    self-signed certificate, typically). None if absent."""
    if not cert:
        return None
    return _rdn_value(cert.get("subject"), ("organizationName", "O"))


def cert_fields(cert: Optional[dict]) -> dict:
    """Reduce a getpeercert()-style dict to CN / SANs / issuer / expiry."""
    out = {"cert_cn": None, "cert_san": [], "cert_issuer": None, "cert_expires": None}
    if not cert:
        return out
    out["cert_cn"] = _rdn_value(cert.get("subject"), ("commonName", "CN")) or cert_subject_org(cert)
    out["cert_issuer"] = _rdn_value(cert.get("issuer"), ("commonName", "CN")) or _rdn_value(
        cert.get("issuer"), ("organizationName", "O")
    )
    out["cert_san"] = [v for _t, v in cert.get("subjectAltName", ()) if v]
    out["cert_expires"] = cert.get("notAfter")
    return out


# X.509 name attribute OIDs -> the names ssl.getpeercert() uses
_X509_ATTR_NAMES = {
    "2.5.4.3": "commonName", "2.5.4.10": "organizationName", "2.5.4.11": "organizationalUnitName",
    "2.5.4.6": "countryName", "2.5.4.7": "localityName", "2.5.4.8": "stateOrProvinceName",
    "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress",
}


def _x509_name(name) -> tuple:
    """A cryptography Name as getpeercert()'s tuple-of-RDN-tuples."""
    out = []
    for rdn in name.rdns:
        out.append(tuple((_X509_ATTR_NAMES.get(a.oid.dotted_string, a.oid.dotted_string), str(a.value)) for a in rdn))
    return tuple(out)


def decode_der_cert(der: Optional[bytes]) -> Optional[dict]:
    """Decode a DER certificate to a getpeercert()-style dict without verifying it.

    ssl.getpeercert() returns {} under CERT_NONE, so the binary form is parsed with the
    ``cryptography`` package (no private stdlib hooks, no temp files). None if unparseable.
    """
    if not der:
        return None
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        cert = x509.load_der_x509_certificate(der)
        out: dict = {"subject": _x509_name(cert.subject), "issuer": _x509_name(cert.issuer)}
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:  # cryptography < 42
            not_after = cert.not_valid_after
        out["notAfter"] = not_after.strftime("%b %d %H:%M:%S %Y GMT")
        try:
            not_before = cert.not_valid_before_utc
        except AttributeError:
            not_before = cert.not_valid_before
        out["notBefore"] = not_before.strftime("%b %d %H:%M:%S %Y GMT")
        out["serialNumber"] = format(cert.serial_number, "X")
        sans: list = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            for dns in ext.get_values_for_type(x509.DNSName):
                sans.append(("DNS", dns))
            for ipa in ext.get_values_for_type(x509.IPAddress):
                sans.append(("IP Address", str(ipa)))
        except Exception:  # noqa: BLE001 - no SAN extension
            pass
        out["subjectAltName"] = tuple(sans)
        return out
    except Exception:  # noqa: BLE001
        return None


_decode_peer_cert = decode_der_cert


def http_banner(ip: str, port: int, timeout: float = 2.0, tls: Optional[bool] = None) -> Optional[dict]:
    """Connect to ip:port, read the HTTP banner (and TLS cert for TLS ports). None on failure."""
    if not is_usable_ip(ip):
        return None
    if tls is None:
        tls = port in TLS_PORTS
    sock = None
    tls_sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        cert = None
        stream = sock
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except (NotImplementedError, ssl.SSLError):
                pass
            tls_sock = ctx.wrap_socket(sock, server_hostname=ip if _looks_like_hostname(ip) else None)
            stream = tls_sock
            try:
                cert = _decode_peer_cert(tls_sock.getpeercert(binary_form=True))
            except (ssl.SSLError, OSError, ValueError):
                cert = None
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        stream.sendall(req.encode("ascii", "replace"))
        chunks = bytearray()
        while len(chunks) < 32768:
            try:
                buf = stream.recv(4096)
            except (socket.timeout, ssl.SSLError):
                break
            if not buf:
                break
            chunks += buf
        raw = bytes(chunks)
    except (OSError, ValueError):
        return None
    finally:
        for s in (tls_sock, sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    head = parse_http_head(raw)
    body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
    cf = cert_fields(cert)
    return {
        "port": port,
        "tls": bool(tls),
        "server": head.get("server"),
        "title": title_from_html(body),
        "realm": head.get("realm"),
        "status": head.get("status"),
        "cert_cn": cf["cert_cn"],
        "cert_org": cert_subject_org(cert),
        "cert_san": cf["cert_san"],
        "cert_issuer": cf["cert_issuer"],
        "cert_expires": cf["cert_expires"],
    }


def _looks_like_hostname(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return False
    except OSError:
        return True


def _http_probe_ports(host) -> list[int]:
    """The web ports worth trying for a host: its known-open ones, else 80 and 443. Capped."""
    ports: list[int] = []
    for p in getattr(host, "ports", None) or []:
        try:
            num = int(p.get("port")) if isinstance(p, dict) else int(p)
        except (TypeError, ValueError):
            continue
        if num in WEB_PORTS and num not in ports:
            ports.append(num)
    if not ports:
        ports = [80, 443]
    return ports[:2]


def _http_probe_host(ip: str, host, timeout: float) -> Optional[dict]:
    """Try the host's web ports in turn, returning the first banner that answers."""
    for port in _http_probe_ports(host):
        try:
            res = http_banner(ip, port, timeout=timeout, tls=None)
        except Exception:  # noqa: BLE001
            res = None
        if res:
            return res
    return None


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def _set_dict_attr(host, attr: str, key: str, value) -> None:
    """Store value under host.<attr>[key], creating the dict if the field is absent/blank."""
    d = getattr(host, attr, None)
    if not isinstance(d, dict):
        d = {}
        setattr(host, attr, d)
    d[key] = value


def _add_name(host, source: str, name: Optional[str]) -> None:
    if name:
        _set_dict_attr(host, "names", source, name)


def _add_source(host, source: str) -> None:
    srcs = getattr(host, "sources", None)
    if isinstance(srcs, list):
        if source not in srcs:
            srcs.append(source)
    else:
        setattr(host, "sources", [source])


# software token -> (os_family, note) for the SSH banner. Unauthenticated, read-only:
# the server sends its identification string before any auth, and it often names the
# distro/OS outright ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5").
_SSH_OS = [
    ("ubuntu", "linux", "Ubuntu"), ("debian", "linux", "Debian"), ("raspbian", "linux", "Raspberry Pi OS"),
    ("el7", "linux", "RHEL/CentOS 7"), ("el8", "linux", "RHEL/CentOS 8"), ("el9", "linux", "RHEL/CentOS 9"),
    ("freebsd", "bsd", "FreeBSD"), ("openbsd", "bsd", "OpenBSD"), ("netbsd", "bsd", "NetBSD"),
    ("windows", "windows", "Windows (OpenSSH)"), ("cisco", "ios", "Cisco"), ("mikrotik", "routeros", "MikroTik"),
    ("dropbear", "embedded", "embedded (Dropbear)"), ("rosssh", "routeros", "MikroTik"),
]


def _ssh_ident_line(data: bytes) -> str:
    """The identification line out of what an SSH server sent first. RFC 4253 lets the
    server precede it with other lines (a banner, a warning); the first line starting with
    'SSH-' within the first few lines is the ident. '' if none."""
    for raw in data.split(b"\n")[:8]:
        line = raw.decode("latin-1", "replace").strip()
        if line.startswith("SSH-"):
            return line
    return ""


def _read_ssh_ident(s, max_bytes: int = 4096) -> bytes:
    """Read from a connected socket until an 'SSH-' line has arrived (or a few lines / bytes)."""
    buf = bytearray()
    while len(buf) < max_bytes:
        try:
            chunk = s.recv(512)
        except (OSError, socket.timeout):
            break
        if not chunk:
            break
        buf += chunk
        if _ssh_ident_line(bytes(buf)) or buf.count(b"\n") >= 8:
            break
    return bytes(buf)


def ssh_banner(ip: str, timeout: float) -> Optional[dict]:
    """Read a host's SSH identification banner (read-only; we send our own ident then
    close, never attempt auth). Returns {banner, software, os, os_family} or None."""
    import socket

    try:
        with socket.create_connection((ip, 22), timeout) as s:
            s.settimeout(timeout)
            data = _read_ssh_ident(s)
            try:
                s.sendall(b"SSH-2.0-NetMap\r\n")  # polite ident so the server doesn't log a scan-abort
            except OSError:
                pass
    except (OSError, socket.timeout):
        return None
    line = _ssh_ident_line(data)
    if not line:
        return None
    parts = line.split("-", 2)
    software = parts[2] if len(parts) > 2 else ""
    low = line.lower()
    os_txt = os_fam = ""
    for token, fam, label in _SSH_OS:
        if token in low:
            os_txt, os_fam = label, fam
            break
    return {"banner": line[:120], "software": software[:80], "os": os_txt, "os_family": os_fam}


async def identify_hosts(
    inv: Inventory,
    hosts: Optional[list] = None,
    do_netbios: bool = True,
    do_mdns: bool = True,
    do_ssdp: bool = True,
    do_http: bool = True,
    do_ssh: bool = True,
    workers: int = 64,
    timeout: float = 2.0,
    probes: Optional[dict] = None,
) -> int:
    """Run the enabled identification probes over the inventory's hosts, concurrently.

    For each targeted host each enabled probe runs in a thread (the sockets block), bounded by
    a semaphore. What answers is recorded on the Host: the raw dict under host.probes[name];
    discovered names under host.names[source]; the probe name in host.sources; and, when
    NetBIOS returns a plausible adapter MAC and the host has no MAC or only a weak one, that
    MAC with mac_source="netbios". Role/OS are deliberately not computed here.

    `probes` may map a probe name ("netbios"/"mdns"/"ssdp"/"http") to a callable(ip)->dict|None
    to bypass real network I/O in tests. Returns the number of hosts that answered any probe.
    """
    default = hosts is None
    if default:
        targets = [ip for ip in list(inv.hosts) if ip not in inv.ip_to_device]
    else:
        targets = list(hosts)
    targets = [ip for ip in targets if is_usable_ip(ip) and ip in inv.hosts]
    if not targets:
        return 0

    enabled = [
        name for name, on in (
            ("netbios", do_netbios), ("mdns", do_mdns), ("ssdp", do_ssdp), ("http", do_http), ("ssh", do_ssh)
        ) if on
    ]
    if not enabled:
        return 0

    log.info("identifying %d hosts with probes: %s", len(targets), ", ".join(enabled))
    loop = asyncio.get_running_loop()
    # Concurrency is bounded per *probe call*, not per host: `workers` probes may be in
    # flight at once and the pool has exactly that many threads, so a submitted probe
    # starts immediately and the safety ceiling below counts from when it actually runs.
    # (Bounding per host while fanning each host into several probes in a same-size pool
    # queued most probes behind the pool and their timers expired while waiting.)
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netmap-id")
    sem = asyncio.Semaphore(workers)
    # Each probe bounds itself with socket timeouts (the HTTP probe may try two ports);
    # this ceiling only catches a probe that ignores them.
    ceiling = max(timeout, 0.5) * 4 + 2.0
    answered = 0

    def _call_for(name: str, ip: str, host):
        if probes and name in probes:
            fn = probes[name]
            return lambda: fn(ip)
        if name == "netbios":
            return lambda: netbios_node_status(ip, timeout)
        if name == "mdns":
            return lambda: mdns_query(ip, timeout)
        if name == "ssdp":
            return lambda: ssdp_probe(ip, timeout)
        if name == "http":
            return lambda: _http_probe_host(ip, host, timeout)
        if name == "ssh":
            return lambda: ssh_banner(ip, timeout)
        return lambda: None

    async def _run(name: str, ip: str, host):
        call = _call_for(name, ip, host)
        async with sem:
            try:
                with activity.working("identify", f"{ip} {name}"):
                    return await asyncio.wait_for(loop.run_in_executor(pool, call), ceiling)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001 - a probe never sinks the run
                return None

    async def one(ip: str):
        nonlocal answered
        host = inv.hosts[ip]
        results = await asyncio.gather(*(_run(name, ip, host) for name in enabled))
        got = False
        for name, res in zip(enabled, results):
            if not res or not isinstance(res, dict):
                continue
            got = True
            _set_dict_attr(host, "probes", name, res)
            _add_source(host, name)
            if name == "netbios":
                _add_name(host, "netbios", res.get("hostname"))
                mac = _plausible_mac(res.get("mac"))
                cur_src = (getattr(host, "mac_source", "") or "")
                if mac and (not getattr(host, "mac", None) or cur_src in WEAK_MAC_SOURCES):
                    host.mac = mac
                    setattr(host, "mac_source", "netbios")
            elif name == "mdns":
                _add_name(host, "mdns", res.get("hostname"))
            elif name == "ssdp":
                _add_name(host, "ssdp", res.get("friendly_name"))
        if got:
            answered += 1

    try:
        await asyncio.gather(*(one(ip) for ip in targets))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    log.info("identification: %d of %d hosts answered a probe", answered, len(targets))
    return answered


async def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    """True if a TCP connection to ip:port completes. Read-only: connect then close."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


MGMT_PORTS = {"telnet": 23, "ssh": 22, "http": 80, "https": 443}


async def probe_management(inv, device_ids=None, timeout: float = 1.5, workers: int = 64) -> int:
    """Check which management planes each polled device exposes (Telnet/SSH/HTTP/HTTPS).

    A read-only TCP connect to a handful of ports, so a compliance check can flag cleartext
    management (Telnet, HTTP). Sets device.mgmt = {telnet, ssh, http, https: bool}. Returns
    how many devices exposed anything.
    """
    ids = list(device_ids if device_ids is not None else inv.devices)
    sem = asyncio.Semaphore(workers)
    found = 0

    async def one(did):
        nonlocal found
        dev = inv.devices.get(did)
        if dev is None:
            return
        result = {}
        async with sem:
            with activity.working("management check", did):
                for name, port in MGMT_PORTS.items():
                    result[name] = await _tcp_open(did, port, timeout)
        dev.mgmt = result
        if any(result.values()):
            found += 1

    await asyncio.gather(*(one(d) for d in ids))
    return found
