"""Additional unauthenticated discovery probes - broad protocol fingerprinting, stdlib only.

Where `discover.py` covers the general-IT discovery protocols (NetBIOS, mDNS, SSDP, HTTP/TLS),
this module knocks on the protocols that identify the harder devices: OT/ICS controllers and
lights-out server management. The approach throughout: send one small, well-formed request to a
protocol's port, read whatever the device volunteers, and never write or change anything on the
target. A probe that cannot answer returns None and never raises out of the
orchestrator.

Like `discover.py`, each protocol is a *pure parser* over captured bytes plus a thin socket
wrapper, so the wire format can be unit-tested without touching the network:

    WS-Discovery  (UDP 3702)  parse_wsd          / wsd_probe     printers, ONVIF cameras, Windows
    IPMI / RMCP   (UDP 623)   parse_ipmi         / ipmi_probe    BMC / lights-out controllers
    Modbus/TCP    (TCP 502)   parse_modbus_id    / modbus_probe  PLCs / industrial controllers
    BACnet/IP     (UDP 47808) parse_bacnet       / bacnet_probe  building-automation controllers
    EtherNet/IP   (UDP 44818) parse_enip_identity/ enip_probe    Rockwell/Allen-Bradley-style CIP

`probe_extra` runs the enabled probes concurrently over the inventory and records the raw signals
on each Host. Like `identify_hosts`, it does not decide role/os - a separate profiling module
reads what this one records under host.probes.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from . import activity
from .model import Inventory
from .util import is_usable_ip

log = logging.getLogger("netmap.probes_extra")


# --------------------------------------------------------------------------- #
# 1. WS-Discovery (UDP 3702)
# --------------------------------------------------------------------------- #
# A minimal SOAP-over-UDP Probe. The MessageID only needs to be a URI; a fixed one is fine for a
# single unicast round-trip. We ask for no specific Types so every WSD responder matches.
_WSD_PROBE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope '
    'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    "<soap:Header>"
    "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
    "<wsa:MessageID>urn:uuid:2a4e6b18-4f3c-4b7a-9c1e-000000000001</wsa:MessageID>"
    "</soap:Header>"
    "<soap:Body><wsd:Probe/></soap:Body>"
    "</soap:Envelope>"
)


def _wsd_kind(types_text: str) -> str:
    """Guess a device class from the WS-Discovery Types list."""
    t = (types_text or "").lower()
    if "networkvideotransmitter" in t or "onvif" in t:
        return "camera"
    if "print" in t:
        return "printer"
    if "computer" in t or "pnpx" in t or "wsdp:device" in t or ":device" in t:
        return "windows"
    return "device"


def parse_wsd(data: bytes) -> dict:
    """Decode a WS-Discovery ProbeMatch(es) SOAP reply.

    Returns {"types":[...], "xaddrs":[...], "scopes":[...], "kind": "printer|camera|windows|device"}
    or {} if the bytes are not a usable ProbeMatch.
    """
    if not data:
        return {}
    text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else data
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {}

    types: list[str] = []
    xaddrs: list[str] = []
    scopes: list[str] = []
    saw_match = False
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]  # drop the XML namespace
        low = tag.lower()
        if low == "probematch":
            saw_match = True
            continue
        val = (el.text or "").strip()
        if not val:
            continue
        if low == "types":
            types.extend(v for v in val.split() if v)
        elif low == "xaddrs":
            xaddrs.extend(v for v in val.split() if v)
        elif low == "scopes":
            scopes.extend(v for v in val.split() if v)

    if not (saw_match or types or xaddrs):
        return {}
    return {
        "types": types,
        "xaddrs": xaddrs,
        "scopes": scopes,
        "kind": _wsd_kind(" ".join(types)),
    }


def wsd_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Unicast a WS-Discovery Probe to UDP/3702 and parse the ProbeMatch. None on any failure."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_WSD_PROBE.encode("utf-8"), (ip, 3702))
        data, _ = sock.recvfrom(9000)
        res = parse_wsd(data)
        return res or None
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 2. IPMI / RMCP (UDP 623)
# --------------------------------------------------------------------------- #
def _build_ipmi_request() -> bytes:
    """RMCP-wrapped IPMI 'Get Channel Authentication Capabilities' (netFn App, cmd 0x38)."""
    rmcp = bytes([0x06, 0x00, 0xFF, 0x07])              # version 6, reserved, seq 0xFF, class IPMI
    session = bytes([0x00]) + b"\x00" * 4 + b"\x00" * 4  # auth none, seq 0, session id 0
    rs_addr, net_fn = 0x20, 0x18                          # BMC, App request (0x06 << 2)
    csum1 = (-(rs_addr + net_fn)) & 0xFF
    rq_addr, rq_seq, cmd = 0x81, 0x00, 0x38              # remote console, seq 0, Get Chan Auth Cap
    d1, d2 = 0x0E, 0x04                                  # current channel, request admin privilege
    body = bytes([rq_addr, rq_seq, cmd, d1, d2])
    csum2 = (-sum(body)) & 0xFF
    msg = bytes([rs_addr, net_fn, csum1]) + body + bytes([csum2])
    return rmcp + session + bytes([len(msg)]) + msg


def parse_ipmi(data: bytes) -> Optional[dict]:
    """Confirm an RMCP/IPMI response and pull the version and supported auth types.

    Returns {"ipmi": True, "version": "1.5|2.0", "auth": [...], "channel": int|None} or None if
    the bytes are not an RMCP IPMI-class message.
    """
    if not data or len(data) < 8:
        return None
    try:
        if data[0] != 0x06 or data[3] != 0x07:  # RMCP version 6, message class 0x07 = IPMI
            return None
        off = 4
        auth_type = data[off]
        off += 1
        off += 4  # session sequence number
        off += 4  # session id
        if auth_type != 0x00:
            off += 16  # 16-byte auth code when the session is authenticated
        if off >= len(data):
            return None
        msg_len = data[off]
        off += 1
        msg = data[off:off + msg_len] if msg_len else data[off:]
    except (IndexError, struct.error):
        return None

    result: dict = {"ipmi": True, "version": "1.5", "auth": [], "channel": None}
    # IPMI message: rqAddr, netFn/LUN, csum1, rsAddr, seq/LUN, cmd, completion, [data...]
    if len(msg) >= 10 and msg[5] == 0x38 and msg[6] == 0x00:
        result["channel"] = msg[7] & 0x0F
        auth_support = msg[8]
        names: list[str] = []
        if auth_support & 0x01:
            names.append("none")
        if auth_support & 0x02:
            names.append("md2")
        if auth_support & 0x04:
            names.append("md5")
        if auth_support & 0x10:
            names.append("password")
        if auth_support & 0x20:
            names.append("oem")
        result["auth"] = names
        v20 = bool(auth_support & 0x80)  # bit 7: IPMI v2.0+ extended capabilities available
        if len(msg) >= 11 and (msg[10] & 0x02):  # extended-cap byte, bit1: v2.0 connections
            v20 = True
        result["version"] = "2.0" if v20 else "1.5"
    return result


def ipmi_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Send one RMCP Get-Channel-Auth request to UDP/623 and parse the reply. None on failure."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_ipmi_request(), (ip, 623))
        data, _ = sock.recvfrom(1024)
        return parse_ipmi(data)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 3. Modbus/TCP (TCP 502)
# --------------------------------------------------------------------------- #
# Read Device Identification object IDs (function 0x2B / MEI type 0x0E).
_MODBUS_OBJ = {
    0x00: "vendor", 0x01: "product_code", 0x02: "version",
    0x03: "vendor_url", 0x04: "product_name", 0x05: "model", 0x06: "app_name",
}


def _build_modbus_request(unit: int = 0x01, txid: int = 0x0001) -> bytes:
    """MBAP + Read Device Identification (basic, object 0x00) request."""
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])  # fn 0x2B, MEI 0x0E, read basic, start object 0
    # MBAP: transaction id, protocol id 0, length (unit + pdu), unit id
    mbap = struct.pack(">HHHB", txid, 0x0000, len(pdu) + 1, unit)
    return mbap + pdu


def parse_modbus_id(data: bytes) -> dict:
    """Confirm a Modbus/TCP response and decode any Read-Device-Identification objects.

    Returns {"modbus": True, "vendor":..., "product":..., "version":..., "objects": {...}} when the
    bytes are a valid Modbus response (even an exception reply confirms the protocol), else {}.
    """
    if not data or len(data) < 8:
        return {}
    try:
        _txid, pid, _length, _uid = struct.unpack(">HHHB", data[:7])
    except struct.error:
        return {}
    if pid != 0x0000:  # Modbus/TCP protocol identifier is always 0
        return {}
    pdu = data[7:]
    if not pdu:
        return {}

    empty = {"modbus": True, "vendor": None, "product": None, "version": None, "objects": {}}
    fn = pdu[0]
    if fn & 0x80:          # exception response - still speaks Modbus, just not this function
        return empty
    if fn != 0x2B or len(pdu) < 8 or pdu[1] != 0x0E:
        return empty      # some other Modbus function answered; confirmed Modbus, no ID objects

    num = pdu[6]
    off = 7
    objects: dict[int, str] = {}
    for _ in range(num):
        if off + 2 > len(pdu):
            break
        oid, olen = pdu[off], pdu[off + 1]
        off += 2
        objects[oid] = pdu[off:off + olen].decode("iso-8859-1", "replace")
        off += olen

    named = {_MODBUS_OBJ[k]: v for k, v in objects.items() if k in _MODBUS_OBJ}
    return {
        "modbus": True,
        "vendor": named.get("vendor"),
        "product": named.get("product_name") or named.get("product_code") or named.get("model"),
        "version": named.get("version"),
        "objects": named,
    }


def _recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes (or fewer at EOF/timeout)."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _modbus_exchange(sock, unit: int, txid: int) -> bytes:
    """One Read-Device-Identification round trip: send, then read the 7-byte MBAP header and
    the `length-1` PDU bytes it announces (bounded to a Modbus ADU)."""
    sock.sendall(_build_modbus_request(unit=unit, txid=txid))
    head = _recv_exact(sock, 7)
    if len(head) < 7:
        return head
    length = struct.unpack(">H", head[4:6])[0]
    remaining = max(0, min(length - 1, 253))
    return head + (_recv_exact(sock, remaining) if remaining else b"")


def modbus_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Connect to TCP/502, send a Read-Device-ID request (function 43/14, read-only), parse the
    reply. Unit id 0xFF (the Modbus/TCP convention for 'the device itself') is tried first,
    then 0x01 if that produced no identification objects. None on failure."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.create_connection((ip, 502), timeout=timeout)
        sock.settimeout(timeout)
        best: Optional[dict] = None
        for txid, unit in ((1, 0xFF), (2, 0x01)):
            try:
                res = parse_modbus_id(_modbus_exchange(sock, unit, txid))
            except OSError:
                res = {}
            if res and res.get("objects"):
                return res
            best = best or (res or None)
        return best
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 4. BACnet/IP (UDP 47808)
# --------------------------------------------------------------------------- #
def _build_bacnet_whois() -> bytes:
    """A BACnet/IP Who-Is (unicast). BVLC + NPDU + unconfirmed-request APDU."""
    apdu = bytes([0x10, 0x08])                 # unconfirmed request (0x1_), service Who-Is (0x08)
    npdu = bytes([0x01, 0x00])                 # version 1, control 0
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body))  # type 0x81, Original-Unicast
    return bvlc + body


def _bacnet_tags(data: bytes, off: int) -> list:
    """Walk BACnet application/context tags from `off`. Returns [(tag_number, is_context, value)]."""
    tags: list = []
    n = len(data)
    while off < n:
        tag = data[off]
        off += 1
        tag_num = (tag >> 4) & 0x0F
        is_context = bool(tag & 0x08)
        lvt = tag & 0x07
        if tag_num == 0x0F:              # extended tag number
            if off >= n:
                break
            tag_num = data[off]
            off += 1
        if lvt == 6 or lvt == 7:         # opening / closing context tag - no value payload
            tags.append((tag_num, is_context, b""))
            continue
        if lvt == 5:                     # extended length
            if off >= n:
                break
            length = data[off]
            off += 1
            if length == 254:
                length = struct.unpack(">H", data[off:off + 2])[0]
                off += 2
            elif length == 255:
                length = struct.unpack(">I", data[off:off + 4])[0]
                off += 4
        else:
            length = lvt
        tags.append((tag_num, is_context, data[off:off + length]))
        off += length
    return tags


def parse_bacnet(data: bytes) -> Optional[dict]:
    """Decode a BACnet/IP I-Am and pull the device instance and vendor id.

    Returns {"bacnet": True, "device_id": int, "vendor_id": int|None} or None if the bytes are not
    a usable I-Am.
    """
    if not data or len(data) < 6 or data[0] != 0x81:  # BVLC type BACnet/IP
        return None
    try:
        off = 4                              # skip BVLC type, function, length
        if data[1] == 0x04:                  # Forwarded-NPDU (via a BBMD): 6-byte original source address
            off += 6
        off += 1                             # NPDU version
        control = data[off]
        off += 1
        if control & 0x20:                   # destination specifier present
            off += 2                         # DNET
            dlen = data[off]
            off += 1 + dlen                  # DLEN + DADR
        if control & 0x08:                   # source specifier present
            off += 2                         # SNET
            slen = data[off]
            off += 1 + slen                  # SLEN + SADR
        if control & 0x20:
            off += 1                         # hop count (only with a destination)
        if off + 2 > len(data):
            return None
        if (data[off] & 0xF0) != 0x10:       # unconfirmed-request PDU
            return None
        off += 1
        if data[off] != 0x00:                # service choice 0x00 = I-Am
            return None
        off += 1

        device_id = None
        unsigned_vals: list[int] = []
        for tag_num, is_context, val in _bacnet_tags(data, off):
            if is_context:
                continue
            if tag_num == 12 and len(val) == 4:              # BACnetObjectIdentifier
                objid = struct.unpack(">I", val)[0]
                if (objid >> 22) != BACNET_OBJ_DEVICE:        # an I-Am names the *device* object
                    return None
                device_id = objid & 0x3FFFFF                  # low 22 bits = instance number
            elif tag_num == 2 and val:                       # application unsigned integer
                unsigned_vals.append(int.from_bytes(val, "big"))
    except (IndexError, struct.error):
        return None

    if device_id is None:
        return None
    # In an I-Am the unsigned tags are max-APDU then vendor-id; vendor is the last one.
    vendor_id = unsigned_vals[-1] if unsigned_vals else None
    return {"bacnet": True, "device_id": device_id, "vendor_id": vendor_id}


BACNET_OBJ_DEVICE = 8
# device-object properties worth reading after an I-Am (all read-only ReadProperty)
BACNET_PROPS = {"name": 77, "vendor": 121, "model": 70}  # object-name, vendor-name, model-name
_BACNET_READPROP = 0x0C


def _build_bacnet_readprop(device_instance: int, prop: int, invoke_id: int = 1) -> bytes:
    """A confirmed ReadProperty request for one property of the device object.

    ReadProperty only reads; it cannot alter anything on the controller."""
    objid = (BACNET_OBJ_DEVICE << 22) | (device_instance & 0x3FFFFF)
    apdu = bytes([0x00, 0x05, invoke_id & 0xFF, _BACNET_READPROP])   # confirmed req, max APDU 1476, invoke, service
    apdu += bytes([0x0C]) + struct.pack(">I", objid)                 # context tag 0, len 4: object identifier
    apdu += bytes([0x19, prop & 0xFF])                               # context tag 1, len 1: property id
    npdu = bytes([0x01, 0x04])                                       # version 1, expecting reply
    body = npdu + apdu
    return bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body)) + body


def parse_bacnet_readprop(data: bytes) -> Optional[str]:
    """The character-string value out of a ReadProperty Complex-ACK. None if not one."""
    if not data or len(data) < 8 or data[0] != 0x81:
        return None
    try:
        off = 4
        if data[1] == 0x04:
            off += 6
        off += 1
        control = data[off]
        off += 1
        if control & 0x20:
            off += 2
            off += 1 + data[off]
        if control & 0x08:
            off += 2
            off += 1 + data[off]
        if control & 0x20:
            off += 1
        if (data[off] & 0xF0) != 0x30:      # Complex-ACK
            return None
        off += 2                             # PDU type byte, invoke id
        if data[off] != _BACNET_READPROP:
            return None
        off += 1
        inside = False
        for tag_num, is_context, val in _bacnet_tags(data, off):
            if is_context and tag_num == 3 and not val:
                inside = not inside          # opening/closing tag 3 wraps the value
                continue
            if inside and not is_context and tag_num == 7 and val:   # application tag 7: CharacterString
                charset, text = val[0], val[1:]
                enc = {0: "utf-8", 1: "utf-16-be", 3: "utf-32-be", 4: "iso-8859-1", 5: "iso-8859-1"}.get(charset, "utf-8")
                return text.decode(enc, "replace").strip("\x00").strip() or None
    except (IndexError, struct.error):
        return None
    return None


def bacnet_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Send a BACnet Who-Is to UDP/47808 and parse the I-Am reply; then read the device's
    object-name, vendor-name and model-name with ReadProperty (read-only). None on failure."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_bacnet_whois(), (ip, 47808))
        data, _ = sock.recvfrom(1500)
        res = parse_bacnet(data)
        if not res:
            return None
        for i, (key, prop) in enumerate(BACNET_PROPS.items(), start=1):
            res[key] = None
            try:
                sock.sendto(_build_bacnet_readprop(res["device_id"], prop, invoke_id=i), (ip, 47808))
                reply, _ = sock.recvfrom(1500)
                res[key] = parse_bacnet_readprop(reply)
            except OSError:
                break  # a controller that does not answer ReadProperty: keep the I-Am facts
        return res
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 5. EtherNet/IP (UDP 44818)
# --------------------------------------------------------------------------- #
_ENIP_LIST_IDENTITY = 0x0063


def _build_enip_list_identity() -> bytes:
    """A 24-byte EtherNet/IP encapsulation header for List Identity (command 0x0063, no data)."""
    return struct.pack(
        "<HHII8sI",
        _ENIP_LIST_IDENTITY,   # command
        0,                     # length of the (empty) command-specific data
        0,                     # session handle
        0,                     # status
        b"netmap\x00\x00",     # sender context (8 bytes)
        0,                     # options
    )


def parse_enip_identity(data: bytes) -> Optional[dict]:
    """Decode an EtherNet/IP List Identity reply's CIP Identity item.

    Returns {"enip": True, "product":..., "vendor_id":..., "device_type":..., "product_code":...,
    "revision":..., "serial":...} or None if the bytes are not a List Identity reply.
    """
    if not data or len(data) < 24:
        return None
    try:
        command, length = struct.unpack("<HH", data[0:4])
        if command != _ENIP_LIST_IDENTITY:
            return None
        payload = data[24:24 + length] if length else data[24:]
        if len(payload) < 4:
            return None
        item_count = struct.unpack("<H", payload[0:2])[0]
        if item_count < 1:
            return None
        item_type, item_len = struct.unpack("<HH", payload[2:6])
        item = payload[6:6 + item_len]
        if item_type != 0x000C or len(item) < 33:  # 0x000C = CIP Identity item
            return None

        p = 2                                        # skip encapsulation protocol version
        p += 16                                      # skip the sockaddr structure
        vendor_id, device_type, product_code = struct.unpack("<HHH", item[p:p + 6])
        p += 6
        rev_major, rev_minor = item[p], item[p + 1]
        p += 2
        _status = struct.unpack("<H", item[p:p + 2])[0]
        p += 2
        serial = struct.unpack("<I", item[p:p + 4])[0]
        p += 4
        name_len = item[p]
        p += 1
        product = item[p:p + name_len].decode("iso-8859-1", "replace").strip()
    except (struct.error, IndexError):
        return None

    return {
        "enip": True,
        "product": product or None,
        "vendor_id": vendor_id,
        "device_type": device_type,
        "product_code": product_code,
        "revision": f"{rev_major}.{rev_minor}",
        "serial": serial,
    }


def enip_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Send a CIP List Identity to UDP/44818 and parse the Identity item. None on failure."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_enip_list_identity(), (ip, 44818))
        data, _ = sock.recvfrom(4096)
        return parse_enip_identity(data)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# 6. Infra services over UDP (DNS 53, NTP 123)
#
# TCP-only nmap never sees these, so DNS/NTP servers - core infrastructure on an
# inherited network - would otherwise be missed. Both are tiny unprivileged UDP
# request/reply exchanges (no auth, read-only): a valid answer proves the service.
# --------------------------------------------------------------------------- #
def _build_dns_query() -> bytes:
    """A standard DNS query for the root NS record (id 0x1a2b, RD set)."""
    return struct.pack(">HHHHHH", 0x1A2B, 0x0100, 1, 0, 0, 0) + b"\x00" + struct.pack(">HH", 2, 1)


def parse_dns(data: bytes) -> Optional[dict]:
    if len(data) < 12 or data[0:2] != b"\x1a\x2b":
        return None
    flags = (data[2] << 8) | data[3]
    if not (flags & 0x8000):  # QR (response) bit
        return None
    return {"dns": True, "recursion": bool(flags & 0x0080)}


def dns_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Send a DNS query to UDP/53; a well-formed response means a DNS server."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_dns_query(), (ip, 53))
        data, _ = sock.recvfrom(1500)
        return parse_dns(data)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _build_ntp_readvar() -> bytes:
    """An NTP mode-6 control message, opcode 2 READVAR for the system variables (assoc 0).
    Read-only: it asks the daemon to print its variables, nothing more."""
    return struct.pack(">BBHHHHH", 0x16, 0x02, 1, 0, 0, 0, 0)  # LI=0 VN=2 Mode=6; R/E/M=0 op=2; seq 1


def parse_ntp_readvar(data: bytes) -> dict:
    """Decode a mode-6 READVAR response's 'key=value, ...' payload into a dict (quotes dropped)."""
    if not data or len(data) < 12 or (data[0] & 0x07) != 6 or not (data[1] & 0x80):  # mode 6, response bit
        return {}
    try:
        count = struct.unpack(">H", data[10:12])[0]
    except struct.error:
        return {}
    payload = data[12:12 + count].decode("utf-8", "replace")
    out: dict = {}
    for part in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", payload):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        if k:
            out[k] = v.strip().strip('"')
    return out


def ntp_probe(ip: str, timeout: float = 2.0) -> Optional[dict]:
    """Send an NTP client request to UDP/123; a 48-byte reply means an NTP server. Then ask
    for the system variables with a mode-6 readvar (version, refid, OS) - many servers
    refuse mode 6 (noquery), in which case only the stratum is recorded."""
    if not is_usable_ip(ip):
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x1b" + b"\x00" * 47, (ip, 123))  # LI=0 VN=3 Mode=3 (client)
        data, _ = sock.recvfrom(256)
        if len(data) < 48 or (data[0] & 0x07) not in (2, 4, 5):  # server/broadcast mode in reply
            return None
        res = {"ntp": True, "stratum": data[1]}
        try:
            sock.sendto(_build_ntp_readvar(), (ip, 123))
            reply, _ = sock.recvfrom(2048)
            var = parse_ntp_readvar(reply)
            for key in ("version", "system", "refid", "processor"):
                if var.get(key):
                    res[key] = var[key][:120]
        except OSError:
            pass
        return res
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


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


async def probe_extra(
    inv: Inventory,
    hosts: Optional[list] = None,
    do_wsd: bool = True,
    do_ipmi: bool = True,
    do_ot: bool = True,
    do_infra: bool = True,
    workers: int = 48,
    timeout: float = 2.0,
    probes: Optional[dict] = None,
) -> int:
    """Run the enabled broad-fingerprinting probes over the inventory's hosts, concurrently.

    For each targeted host each enabled probe runs in a thread (the sockets block), bounded by a
    semaphore. What answers is recorded on the Host: the raw dict under host.probes[name] (name is
    one of wsd/ipmi/modbus/bacnet/enip); the probe name in host.sources; and, for WS-Discovery, the
    management URL under host.names["wsd"] when one is offered. Role/OS are deliberately not set -
    a separate profiling module reads what this records.

    `do_wsd` and `do_ipmi` toggle those probes; `do_ot` toggles the three OT/ICS probes (Modbus,
    BACnet, EtherNet/IP) together. `probes` may map a probe name to a callable(ip)->dict|None to
    bypass real network I/O in tests. Returns the number of hosts that answered any probe.
    """
    if hosts is None:
        targets = [ip for ip in list(inv.hosts) if ip not in inv.ip_to_device]
    else:
        targets = list(hosts)
    targets = [ip for ip in targets if is_usable_ip(ip) and ip in inv.hosts]
    if not targets:
        return 0

    enabled = []
    if do_wsd:
        enabled.append("wsd")
    if do_ipmi:
        enabled.append("ipmi")
    if do_ot:
        enabled.extend(("modbus", "bacnet", "enip"))
    if do_infra:
        enabled.extend(("dns", "ntp"))
    if not enabled:
        return 0

    _fetchers = {
        "wsd": wsd_probe, "ipmi": ipmi_probe, "modbus": modbus_probe,
        "bacnet": bacnet_probe, "enip": enip_probe, "dns": dns_probe, "ntp": ntp_probe,
    }
    # a confirmed UDP service is recorded as an open port too, so the port->function
    # classifier reports it as a DNS/NTP server (TCP-only nmap can't see these)
    _infra_port = {"dns": (53, "domain"), "ntp": (123, "ntp")}

    log.info("extra-probing %d hosts with: %s", len(targets), ", ".join(enabled))
    loop = asyncio.get_running_loop()
    # Bounded per probe call (see discover.identify_hosts): `workers` probes in flight, a
    # pool of exactly that many threads, and a ceiling that counts from when the probe runs.
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netmap-xid")
    sem = asyncio.Semaphore(workers)
    ceiling = max(timeout, 0.5) * 4 + 2.0  # BACnet/NTP make up to four bounded round trips
    answered = 0

    def _call_for(name: str, ip: str):
        if probes and name in probes:
            fn = probes[name]
            return lambda: fn(ip)
        fetch = _fetchers[name]
        return lambda: fetch(ip, timeout)

    async def _run(name: str, ip: str):
        call = _call_for(name, ip)
        async with sem:
            try:
                with activity.working("protocol probes", f"{ip} {name}"):
                    return await asyncio.wait_for(loop.run_in_executor(pool, call), ceiling)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001 - a probe never sinks the run
                return None

    async def one(ip: str):
        nonlocal answered
        host = inv.hosts[ip]
        results = await asyncio.gather(*(_run(name, ip) for name in enabled))
        got = False
        for name, res in zip(enabled, results):
            if not res or not isinstance(res, dict):
                continue
            got = True
            _set_dict_attr(host, "probes", name, res)
            _add_source(host, name)
            if name == "wsd":
                xaddrs = res.get("xaddrs") or []
                if xaddrs:
                    _add_name(host, "wsd", xaddrs[0])  # a management URL for the device
            elif name in _infra_port:
                port, svc = _infra_port[name]
                if not any(p.get("port") == port for p in host.ports):
                    host.ports.append({"port": port, "proto": "udp", "service": svc, "product": ""})
        if got:
            answered += 1

    try:
        await asyncio.gather(*(one(ip) for ip in targets))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    log.info("extra probes: %d of %d hosts answered", answered, len(targets))
    return answered
