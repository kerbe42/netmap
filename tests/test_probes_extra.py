"""Unit tests for the broad-fingerprinting probes in subnetsleuth.probes_extra.

Every parser is exercised against hand-built, realistic captured bytes; the orchestrator is driven
through injected `probes=` callables so nothing here touches the real network.
"""
import asyncio
import struct

from subnetsleuth import probes_extra as px
from subnetsleuth.model import Inventory


# --------------------------------------------------------------------------- #
# 1. WS-Discovery
# --------------------------------------------------------------------------- #
WSD_CAMERA = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    "<soap:Header>"
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>"
    "</soap:Header><soap:Body><wsd:ProbeMatches><wsd:ProbeMatch>"
    "<wsa:EndpointReference><wsa:Address>urn:uuid:cam-1234</wsa:Address></wsa:EndpointReference>"
    "<wsd:Types>dn:NetworkVideoTransmitter tds:Device</wsd:Types>"
    "<wsd:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/AcmeCam</wsd:Scopes>"
    "<wsd:XAddrs>http://192.168.1.64/onvif/device_service</wsd:XAddrs>"
    "<wsd:MetadataVersion>1</wsd:MetadataVersion>"
    "</wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>"
).encode("utf-8")

WSD_PRINTER = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:pnpx="http://schemas.microsoft.com/windows/pnpx/2005/10" '
    'xmlns:print="http://schemas.microsoft.com/windows/2006/08/wdp/print">'
    "<soap:Body><wsd:ProbeMatches><wsd:ProbeMatch>"
    "<wsd:Types>print:PrintDeviceType pnpx:X_PnPX_Device</wsd:Types>"
    "<wsd:XAddrs>http://192.168.1.77:80/wsd/device</wsd:XAddrs>"
    "</wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>"
).encode("utf-8")


def test_parse_wsd_onvif_camera():
    r = px.parse_wsd(WSD_CAMERA)
    assert r["kind"] == "camera"
    assert "dn:NetworkVideoTransmitter" in r["types"]
    assert r["xaddrs"] == ["http://192.168.1.64/onvif/device_service"]
    assert any("video_encoder" in s for s in r["scopes"])


def test_parse_wsd_printer():
    r = px.parse_wsd(WSD_PRINTER)
    assert r["kind"] == "printer"
    assert r["xaddrs"] == ["http://192.168.1.77:80/wsd/device"]


def test_parse_wsd_garbage_returns_empty():
    assert px.parse_wsd(b"not xml at all") == {}
    assert px.parse_wsd(b"") == {}


# --------------------------------------------------------------------------- #
# 2. IPMI
# --------------------------------------------------------------------------- #
def build_ipmi_response(auth_support=0x95, ext_cap=0x02, channel=0x01) -> bytes:
    """A valid RMCP Get-Channel-Auth-Capabilities response.

    auth_support 0x95 = bit7 (v2.0) | bit4 (straight password) | bit2 (MD5) | bit0 (none).
    """
    rmcp = bytes([0x06, 0x00, 0xFF, 0x07])
    session = bytes([0x00]) + b"\x00" * 4 + b"\x00" * 4
    # IPMI message: rqAddr, netFn(resp 0x1C), csum1, rsAddr, seq, cmd, completion, data...
    data = bytes([channel, auth_support, 0x04, ext_cap, 0x00, 0x00, 0x00, 0x00])
    head = bytes([0x81, 0x1C, 0x00, 0x20, 0x00, 0x38, 0x00])
    msg = head + data
    return rmcp + session + bytes([len(msg)]) + msg


def test_parse_ipmi_confirms_bmc_v20():
    r = px.parse_ipmi(build_ipmi_response())
    assert r["ipmi"] is True
    assert r["version"] == "2.0"
    assert "md5" in r["auth"]
    assert "none" in r["auth"]
    assert "password" in r["auth"]
    assert r["channel"] == 0x01


def test_parse_ipmi_v15_when_no_v20_bits():
    r = px.parse_ipmi(build_ipmi_response(auth_support=0x14, ext_cap=0x01))  # md5 + straight, v1.5
    assert r["version"] == "1.5"
    assert "md5" in r["auth"]


def test_parse_ipmi_rejects_non_rmcp():
    assert px.parse_ipmi(b"\x00\x00\x00\x00\x00\x00\x00\x00") is None
    assert px.parse_ipmi(b"") is None


# --------------------------------------------------------------------------- #
# 3. Modbus/TCP
# --------------------------------------------------------------------------- #
def _modbus_obj(oid, text: bytes) -> bytes:
    return bytes([oid, len(text)]) + text


def build_modbus_id_response(txid=0x0001, unit=0x01) -> bytes:
    objs = (
        _modbus_obj(0x00, b"Schneider Electric")
        + _modbus_obj(0x01, b"BMXP342020")
        + _modbus_obj(0x02, b"V2.70")
        + _modbus_obj(0x04, b"Modicon M340")
    )
    pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x04]) + objs  # read basic, conf, no-more, next0, 4 objs
    mbap = struct.pack(">HHHB", txid, 0x0000, len(pdu) + 1, unit)
    return mbap + pdu


def build_modbus_exception() -> bytes:
    pdu = bytes([0xAB, 0x01])  # 0x2B | 0x80 exception, code illegal function
    mbap = struct.pack(">HHHB", 0x0001, 0x0000, len(pdu) + 1, 0x01)
    return mbap + pdu


def test_parse_modbus_id_extracts_vendor_product_version():
    r = px.parse_modbus_id(build_modbus_id_response())
    assert r["modbus"] is True
    assert r["vendor"] == "Schneider Electric"
    assert r["product"] == "Modicon M340"     # product name (0x04) preferred over product code
    assert r["version"] == "V2.70"
    assert r["objects"]["product_code"] == "BMXP342020"


def test_parse_modbus_exception_still_confirms_modbus():
    r = px.parse_modbus_id(build_modbus_exception())
    assert r["modbus"] is True
    assert r["vendor"] is None


def test_parse_modbus_rejects_bad_protocol_id():
    bad = struct.pack(">HHHB", 1, 0x1234, 2, 1) + b"\x2b"
    assert px.parse_modbus_id(bad) == {}
    assert px.parse_modbus_id(b"") == {}


# --------------------------------------------------------------------------- #
# 4. BACnet/IP
# --------------------------------------------------------------------------- #
def build_bacnet_iam(instance=260001, vendor_id=8) -> bytes:
    # I-Am APDU: unconfirmed request (0x10), service I-Am (0x00), then application tags:
    #   object id (device, type 8), max-apdu, segmentation, vendor id
    objid = (8 << 22) | (instance & 0x3FFFFF)
    apdu = bytes([0x10, 0x00])
    apdu += bytes([0xC4]) + struct.pack(">I", objid)   # tag 12, len 4: BACnetObjectIdentifier
    apdu += bytes([0x22]) + struct.pack(">H", 1476)    # tag 2, len 2: max APDU accepted
    apdu += bytes([0x91, 0x00])                         # tag 9, len 1: segmentation (enumerated)
    apdu += bytes([0x21, vendor_id & 0xFF])            # tag 2, len 1: vendor id
    npdu = bytes([0x01, 0x00])
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body))
    return bvlc + body


def test_parse_bacnet_iam():
    r = px.parse_bacnet(build_bacnet_iam(instance=260001, vendor_id=8))
    assert r["bacnet"] is True
    assert r["device_id"] == 260001
    assert r["vendor_id"] == 8


def test_parse_bacnet_rejects_non_bacnet():
    assert px.parse_bacnet(b"\x00\x01\x02\x03\x04\x05") is None
    assert px.parse_bacnet(b"") is None


# --------------------------------------------------------------------------- #
# 5. EtherNet/IP
# --------------------------------------------------------------------------- #
def build_enip_list_identity(product=b"1756-EN2T/B", vendor_id=1, device_type=12) -> bytes:
    sockaddr = struct.pack(">HHI", 2, 44818, 0xC0A80105) + b"\x00" * 8  # AF_INET, port, ip, zero
    item = struct.pack("<H", 1)                    # encapsulation protocol version
    item += sockaddr
    item += struct.pack("<HHH", vendor_id, device_type, 0x00B1)  # vendor, device type, product code
    item += bytes([1, 5])                          # revision major.minor
    item += struct.pack("<H", 0x0030)              # status
    item += struct.pack("<I", 0x11223344)          # serial number
    item += bytes([len(product)]) + product        # product name (length-prefixed)
    item += bytes([0x03])                          # state
    payload = struct.pack("<H", 1)                 # item count
    payload += struct.pack("<HH", 0x000C, len(item)) + item  # item type CIP Identity, length, data
    header = struct.pack("<HHII8sI", 0x0063, len(payload), 0, 0, b"\x00" * 8, 0)
    return header + payload


def test_parse_enip_identity():
    r = px.parse_enip_identity(build_enip_list_identity())
    assert r["enip"] is True
    assert r["product"] == "1756-EN2T/B"
    assert r["vendor_id"] == 1
    assert r["device_type"] == 12
    assert r["revision"] == "1.5"
    assert r["serial"] == 0x11223344


def test_parse_enip_rejects_wrong_command():
    bad = struct.pack("<HHII8sI", 0x0004, 0, 0, 0, b"\x00" * 8, 0)  # List Services, not Identity
    assert px.parse_enip_identity(bad) is None
    assert px.parse_enip_identity(b"") is None


# --------------------------------------------------------------------------- #
# orchestrator (injected probes, no sockets)
# --------------------------------------------------------------------------- #
def _run(coro):
    return asyncio.run(coro)


def test_probe_extra_fills_probes_and_sources():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")   # answers Modbus
    inv.touch_host("10.0.0.2", "sweep")   # answers WS-Discovery
    inv.touch_host("10.0.0.3", "sweep")   # answers nothing

    def modbus(ip):
        if ip == "10.0.0.1":
            return {"modbus": True, "vendor": "Siemens", "product": "S7-1200",
                    "version": "4.2", "objects": {}}
        return None

    def wsd(ip):
        if ip == "10.0.0.2":
            return {"types": ["dn:NetworkVideoTransmitter"], "kind": "camera",
                    "xaddrs": ["http://10.0.0.2/onvif/device_service"], "scopes": []}
        return None

    n = _run(px.probe_extra(
        inv, do_infra=False,
        probes={"modbus": modbus, "wsd": wsd,
                "ipmi": lambda ip: None, "bacnet": lambda ip: None, "enip": lambda ip: None},
    ))
    assert n == 2

    h1 = inv.hosts["10.0.0.1"]
    assert h1.probes["modbus"]["vendor"] == "Siemens"
    assert "modbus" in h1.sources

    h2 = inv.hosts["10.0.0.2"]
    assert h2.probes["wsd"]["kind"] == "camera"
    assert "wsd" in h2.sources
    assert h2.names["wsd"] == "http://10.0.0.2/onvif/device_service"

    h3 = inv.hosts["10.0.0.3"]
    assert "wsd" not in h3.sources and "modbus" not in h3.sources
    assert h3.probes == {}


def test_probe_extra_infra_records_dns_ntp_as_ports():
    from subnetsleuth.profile import profile_host
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")  # answers DNS
    inv.touch_host("10.0.0.2", "sweep")  # answers NTP
    n = _run(px.probe_extra(
        inv, do_ot=False, do_wsd=False, do_ipmi=False,
        probes={"dns": lambda ip: {"dns": True, "recursion": True} if ip == "10.0.0.1" else None,
                "ntp": lambda ip: {"ntp": True, "stratum": 3} if ip == "10.0.0.2" else None},
    ))
    assert n == 2
    h1 = inv.hosts["10.0.0.1"]
    assert any(p["port"] == 53 and p["proto"] == "udp" for p in h1.ports)
    assert "DNS server" in profile_host(h1).functions
    h2 = inv.hosts["10.0.0.2"]
    assert any(p["port"] == 123 for p in h2.ports)


def test_probe_extra_do_ot_toggle_disables_ot_probes():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")
    called = []

    def modbus(ip):
        called.append(ip)
        return {"modbus": True}

    n = _run(px.probe_extra(
        inv, do_ot=False, do_wsd=False, do_ipmi=True, do_infra=False,
        probes={"modbus": modbus, "ipmi": lambda ip: None},
    ))
    assert n == 0
    assert called == []  # OT probes were not run at all


def test_probe_extra_skips_devices_and_unusable_ips():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")
    inv.touch_host("127.0.0.1", "sweep")       # not a usable IP
    inv.touch_host("10.0.0.5", "sweep")
    inv.ip_to_device["10.0.0.5"] = "10.0.0.5"  # already a polled device -> skipped by default
    seen = []
    n = _run(px.probe_extra(
        inv, do_infra=False,
        probes={"wsd": lambda ip: seen.append(ip) or None,
                "ipmi": lambda ip: None, "modbus": lambda ip: None,
                "bacnet": lambda ip: None, "enip": lambda ip: None},
    ))
    assert n == 0
    assert seen == ["10.0.0.1"]


def test_probe_extra_never_raises_on_probe_exception():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")

    def boom(ip):
        raise RuntimeError("probe blew up")

    n = _run(px.probe_extra(
        inv, do_infra=False,
        probes={"wsd": boom, "ipmi": boom, "modbus": boom, "bacnet": boom, "enip": boom},
    ))
    assert n == 0
