"""Unit tests for the active host-identification probes in subnetsleuth.discover.

Every parser is exercised against hand-built, realistic captured bytes; the orchestrator is
driven through injected `probes=` callables so nothing here touches the real network.
"""
import asyncio
import struct

import pytest

from subnetsleuth import discover
from subnetsleuth.model import Host, Inventory


# --------------------------------------------------------------------------- #
# builders for wire-format bytes
# --------------------------------------------------------------------------- #
def _nb_name(name: str, suffix: int, flags: int) -> bytes:
    field = name.encode("ascii").ljust(15, b" ")[:15]
    return field + bytes([suffix]) + struct.pack(">H", flags)


def build_nbstat_response(names, mac=b"\x00\x0c\x29\xab\xcd\xef", txid=0x4242) -> bytes:
    """names: list of (name, suffix, flags). Returns a valid NBSTAT response with a MAC."""
    header = struct.pack(">HHHHHH", txid, 0x8400, 0, 1, 0, 0)  # 1 answer
    qname = bytes([0x20]) + discover._encode_netbios_name("*") + b"\x00"
    rdata = bytearray([len(names)])
    for nm, suf, fl in names:
        rdata += _nb_name(nm, suf, fl)
    rdata += mac
    rdata += b"\x00" * 40  # remainder of the statistics block (ignored)
    rr = qname + struct.pack(">HHIH", 0x0021, 0x0001, 0, len(rdata)) + bytes(rdata)
    return header + rr


def _dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    return bytes(out)


def _dns_rr(name: str, rtype: int, rdata: bytes, ttl: int = 120) -> bytes:
    return _dns_name(name) + struct.pack(">HHIH", rtype, 0x0001, ttl, len(rdata)) + rdata


def build_mdns_response() -> bytes:
    header = struct.pack(">HHHHHH", 0x0000, 0x8400, 0, 3, 0, 0)
    ans = b""
    ans += _dns_rr("_services._dns-sd._udp.local", discover._PTR, _dns_name("_ipp._tcp.local"))
    txt = b"".join(bytes([len(s)]) + s for s in (b"ty=OfficeJet Pro", b"model=OJP-8710", b"note="))
    ans += _dns_rr("MyPrinter._ipp._tcp.local", discover._TXT, txt)
    ans += _dns_rr("myprinter.local", discover._A, bytes([192, 168, 1, 77]))
    return header + ans


SSDP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"CACHE-CONTROL: max-age=1800\r\n"
    b"LOCATION: http://192.168.1.50:80/desc.xml\r\n"
    b"SERVER: Linux/3.14 UPnP/1.0 Roku/9.4.0\r\n"
    b"ST: upnp:rootdevice\r\n"
    b"USN: uuid:roku:ecp:1GU48T017973\r\n"
    b"\r\n"
)

UPNP_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Living Room TV</friendlyName>
    <manufacturer>Acme Corp</manufacturer>
    <modelName>SmartTV 3000</modelName>
    <modelNumber>ST-3000</modelNumber>
  </device>
</root>
"""

HTTP_RESPONSE = (
    b"HTTP/1.1 401 Unauthorized\r\n"
    b"Server: lighttpd/1.4.35\r\n"
    b'WWW-Authenticate: Basic realm="RouterOS Admin"\r\n'
    b"Content-Type: text/html\r\n"
    b"\r\n"
    b"<html><head><title>  RB4011  Login </title></head><body>hi</body></html>"
)


# --------------------------------------------------------------------------- #
# 1. NetBIOS
# --------------------------------------------------------------------------- #
def test_parse_nbstat_names_and_mac():
    data = build_nbstat_response([
        ("WORKSTATION1", 0x00, 0x0400),   # unique workstation
        ("WORKGROUP", 0x00, 0x8400),      # group domain/workgroup
        ("JDOE", 0x03, 0x0400),           # logged-on user (messenger, unique)
    ])
    res = discover.parse_nbstat(data)
    assert res is not None
    assert res["hostname"] == "WORKSTATION1"
    assert res["domain"] == "WORKGROUP"
    assert res["user"] == "JDOE"
    assert res["mac"] == "00:0c:29:ab:cd:ef"
    assert res["is_dc"] is False
    assert len(res["names"]) == 3
    ws = next(n for n in res["names"] if n["name"] == "WORKSTATION1")
    assert ws["suffix"] == 0x00 and ws["group"] is False
    wg = next(n for n in res["names"] if n["name"] == "WORKGROUP")
    assert wg["group"] is True


def test_parse_nbstat_domain_controller():
    data = build_nbstat_response([
        ("DC01", 0x00, 0x0400),
        ("CORP", 0x1C, 0x8400),   # domain controllers group
    ])
    res = discover.parse_nbstat(data)
    assert res["hostname"] == "DC01"
    assert res["is_dc"] is True
    assert res["domain"] == "CORP"


def test_parse_nbstat_all_zero_mac_rejected():
    data = build_nbstat_response([("HOST", 0x00, 0x0400)], mac=b"\x00\x00\x00\x00\x00\x00")
    res = discover.parse_nbstat(data)
    assert res["mac"] is None


def test_parse_nbstat_rejects_junk():
    assert discover.parse_nbstat(b"") is None
    assert discover.parse_nbstat(b"\x00\x01\x02") is None
    # a header with zero answers is not a usable node-status reply
    assert discover.parse_nbstat(struct.pack(">HHHHHH", 1, 0x8400, 0, 0, 0, 0)) is None


def test_build_nbstat_query_shape():
    q = discover._build_nbstat_query()
    assert q[12] == 0x20                      # length of the encoded name
    assert q[13:15] == b"CK"                  # "*" encodes to "CK"
    assert q[-4:] == struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT / IN


# --------------------------------------------------------------------------- #
# 2. mDNS
# --------------------------------------------------------------------------- #
def test_parse_mdns_printer():
    res = discover.parse_mdns(build_mdns_response())
    assert res is not None
    assert "_ipp._tcp" in res["services"]
    assert res["model"] == "OJP-8710"
    assert res["hostname"] == "myprinter.local"


def test_parse_mdns_vendor_guess_chromecast():
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0)
    ans = _dns_rr("_services._dns-sd._udp.local", discover._PTR, _dns_name("_googlecast._tcp.local"))
    ans += _dns_rr("Chromecast._googlecast._tcp.local", discover._A, bytes([10, 0, 0, 5]))
    res = discover.parse_mdns(header + ans)
    assert "_googlecast._tcp" in res["services"]
    assert res["vendor"] == "Google"


def test_read_dns_name_compression_pointer():
    # "local" at offset 12, then "myhost" + pointer-to-12 at offset 18
    buf = bytearray(b"\x00" * 12)
    buf += _dns_name("local")                 # offset 12: 05 'local' 00
    start = len(buf)
    buf += bytes([6]) + b"myhost" + b"\xc0\x0c"  # 'myhost' then pointer to offset 12
    name, off = discover._read_dns_name(bytes(buf), start)
    assert name == "myhost.local"
    assert off == start + 1 + 6 + 2


def test_parse_mdns_rejects_empty():
    assert discover.parse_mdns(b"") is None
    assert discover.parse_mdns(b"\x00" * 4) is None


# --------------------------------------------------------------------------- #
# 3. SSDP / UPnP
# --------------------------------------------------------------------------- #
def test_parse_ssdp_headers():
    res = discover.parse_ssdp(SSDP_RESPONSE)
    assert res is not None
    assert res["server"] == "Linux/3.14 UPnP/1.0 Roku/9.4.0"
    assert res["location"] == "http://192.168.1.50:80/desc.xml"
    assert res["st"] == "upnp:rootdevice"
    assert res["usn"].startswith("uuid:roku")


def test_parse_ssdp_rejects_junk():
    assert discover.parse_ssdp(b"") is None
    assert discover.parse_ssdp(b"not headers at all") is None


def test_parse_upnp_xml():
    res = discover.parse_upnp_xml(UPNP_XML)
    assert res["friendly_name"] == "Living Room TV"
    assert res["manufacturer"] == "Acme Corp"
    assert res["model"] == "SmartTV 3000"
    assert res["model_number"] == "ST-3000"
    assert res["device_type"].endswith("MediaRenderer:1")


def test_parse_upnp_xml_bad_input():
    assert discover.parse_upnp_xml("")["friendly_name"] is None
    assert discover.parse_upnp_xml("<not-xml")["model"] is None


def test_build_msearch():
    pkt = discover._build_msearch("192.168.1.50").decode()
    assert pkt.startswith("M-SEARCH * HTTP/1.1\r\n")
    assert "HOST: 192.168.1.50:1900" in pkt
    assert 'MAN: "ssdp:discover"' in pkt
    assert "ST: ssdp:all" in pkt


# --------------------------------------------------------------------------- #
# 4. HTTP / TLS banner helpers
# --------------------------------------------------------------------------- #
def test_parse_http_head():
    res = discover.parse_http_head(HTTP_RESPONSE)
    assert res["status"] == 401
    assert res["server"] == "lighttpd/1.4.35"
    assert res["realm"] == "RouterOS Admin"
    assert res["headers"]["content-type"] == "text/html"


def test_title_from_html():
    body = HTTP_RESPONSE.split(b"\r\n\r\n", 1)[1]
    assert discover.title_from_html(body) == "RB4011 Login"
    assert discover.title_from_html("<html>no title</html>") is None
    assert discover.title_from_html(b"") is None


def test_cert_fields():
    cert = {
        "subject": ((("commonName", "fw.example.com"),), (("organizationName", "Example"),)),
        "issuer": ((("commonName", "Example Root CA"),),),
        "subjectAltName": (("DNS", "fw.example.com"), ("DNS", "*.example.com"), ("IP Address", "10.0.0.1")),
        "notAfter": "Dec 31 23:59:59 2030 GMT",
    }
    cf = discover.cert_fields(cert)
    assert cf["cert_cn"] == "fw.example.com"
    assert cf["cert_issuer"] == "Example Root CA"
    assert cf["cert_san"] == ["fw.example.com", "*.example.com", "10.0.0.1"]
    assert cf["cert_expires"].endswith("2030 GMT")


def test_cert_fields_none():
    cf = discover.cert_fields(None)
    assert cf == {"cert_cn": None, "cert_san": [], "cert_issuer": None, "cert_expires": None}


def test_cert_fields_org_fallback():
    cert = {"subject": ((("organizationName", "OnlyOrg"),),), "issuer": ()}
    assert discover.cert_fields(cert)["cert_cn"] == "OnlyOrg"


def test_http_probe_ports_prefers_known_web_ports():
    h = Host(ip="10.0.0.9")
    h.ports = [{"port": 22}, {"port": 8443}, {"port": 80}, {"port": 3306}]
    ports = discover._http_probe_ports(h)
    assert ports == [8443, 80]  # only web ports, capped at 2
    h2 = Host(ip="10.0.0.10")
    assert discover._http_probe_ports(h2) == [80, 443]  # nothing known -> defaults


# --------------------------------------------------------------------------- #
# orchestrator (injected probes, no sockets)
# --------------------------------------------------------------------------- #
def _run(coro):
    return asyncio.run(coro)


def test_identify_hosts_fills_names_mac_sources_probes():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")           # no MAC at all
    inv.touch_host("10.0.0.2", "sweep")
    inv.touch_host("10.0.0.3", "sweep")

    def nb(ip):
        if ip == "10.0.0.1":
            return {"hostname": "PC-ACCT-01", "domain": "CORP", "user": "jdoe",
                    "mac": "00:0c:29:11:22:33", "is_dc": False, "names": []}
        return None

    def md(ip):
        if ip == "10.0.0.2":
            return {"hostname": "printer.local", "services": ["_ipp._tcp"], "model": "OJP", "vendor": ""}
        return None

    def sd(ip):
        if ip == "10.0.0.3":
            return {"server": "Roku/9", "st": "upnp:rootdevice", "location": None,
                    "friendly_name": "Bedroom Roku"}
        return None

    n = _run(discover.identify_hosts(
        inv, do_http=False,
        probes={"netbios": nb, "mdns": md, "ssdp": sd},
    ))
    assert n == 3

    h1 = inv.hosts["10.0.0.1"]
    assert h1.mac == "00:0c:29:11:22:33"
    assert getattr(h1, "mac_source") == "netbios"
    assert h1.names["netbios"] == "PC-ACCT-01"
    assert "netbios" in h1.sources
    assert h1.probes["netbios"]["domain"] == "CORP"

    h2 = inv.hosts["10.0.0.2"]
    assert h2.names["mdns"] == "printer.local"
    assert "mdns" in h2.sources
    assert h2.probes["mdns"]["model"] == "OJP"

    h3 = inv.hosts["10.0.0.3"]
    assert h3.names["ssdp"] == "Bedroom Roku"
    assert "ssdp" in h3.sources
    assert h3.probes["ssdp"]["server"] == "Roku/9"


def test_identify_hosts_netbios_mac_fills_missing_mac():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")
    assert inv.hosts["10.0.0.1"].mac is None
    _run(discover.identify_hosts(
        inv, do_mdns=False, do_ssdp=False, do_http=False,
        probes={"netbios": lambda ip: {"hostname": "H", "mac": "3c:52:82:1a:2b:3c", "is_dc": False}},
    ))
    assert inv.hosts["10.0.0.1"].mac == "3c:52:82:1a:2b:3c"
    assert getattr(inv.hosts["10.0.0.1"], "mac_source") == "netbios"


def test_identify_hosts_does_not_clobber_strong_mac():
    inv = Inventory()
    h = inv.touch_host("10.0.0.1", "arp", mac="11:22:33:44:55:66")
    setattr(h, "mac_source", "arp")   # a strong, on-link MAC
    _run(discover.identify_hosts(
        inv, do_mdns=False, do_ssdp=False, do_http=False,
        probes={"netbios": lambda ip: {"hostname": "H", "mac": "3c:52:82:1a:2b:3c", "is_dc": False}},
    ))
    assert inv.hosts["10.0.0.1"].mac == "11:22:33:44:55:66"   # unchanged
    assert getattr(inv.hosts["10.0.0.1"], "mac_source") == "arp"


def test_identify_hosts_overwrites_weak_sweep_mac():
    inv = Inventory()
    h = inv.touch_host("10.0.0.1", "sweep", mac="11:22:33:44:55:66")
    setattr(h, "mac_source", "sweep")
    _run(discover.identify_hosts(
        inv, do_mdns=False, do_ssdp=False, do_http=False,
        probes={"netbios": lambda ip: {"hostname": "H", "mac": "3c:52:82:1a:2b:3c", "is_dc": False}},
    ))
    assert inv.hosts["10.0.0.1"].mac == "3c:52:82:1a:2b:3c"
    assert getattr(inv.hosts["10.0.0.1"], "mac_source") == "netbios"


def test_identify_hosts_no_answer_records_nothing():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")
    n = _run(discover.identify_hosts(
        inv, probes={"netbios": lambda ip: None, "mdns": lambda ip: None,
                     "ssdp": lambda ip: None, "http": lambda ip: None},
    ))
    assert n == 0
    h = inv.hosts["10.0.0.1"]
    assert h.sources == ["sweep"]
    assert not getattr(h, "probes", {})


def test_identify_hosts_skips_devices_and_unusable_ips():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")
    inv.touch_host("127.0.0.1", "sweep")          # not a usable IP
    inv.touch_host("10.0.0.5", "sweep")
    inv.ip_to_device["10.0.0.5"] = "10.0.0.5"     # already a polled device -> skipped by default

    seen = []
    _run(discover.identify_hosts(
        inv, do_mdns=False, do_ssdp=False, do_http=False,
        probes={"netbios": lambda ip: seen.append(ip) or None},
    ))
    assert seen == ["10.0.0.1"]


def test_identify_hosts_http_probe_injected():
    inv = Inventory()
    inv.touch_host("10.0.0.7", "sweep")
    n = _run(discover.identify_hosts(
        inv, do_netbios=False, do_mdns=False, do_ssdp=False,
        probes={"http": lambda ip: {"port": 443, "tls": True, "server": "nginx",
                                    "title": "Appliance", "cert_cn": "fw.local"}},
    ))
    assert n == 1
    h = inv.hosts["10.0.0.7"]
    assert "http" in h.sources
    assert h.probes["http"]["cert_cn"] == "fw.local"
    # http answers are not turned into a host name
    assert "http" not in getattr(h, "names", {})


def test_identify_hosts_explicit_host_list():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")
    inv.touch_host("10.0.0.2", "sweep")
    seen = []
    _run(discover.identify_hosts(
        inv, hosts=["10.0.0.2"], do_mdns=False, do_ssdp=False, do_http=False,
        probes={"netbios": lambda ip: seen.append(ip) or None},
    ))
    assert seen == ["10.0.0.2"]


def test_identify_hosts_probe_exception_is_swallowed():
    inv = Inventory()
    inv.touch_host("10.0.0.1", "sweep")

    def boom(ip):
        raise RuntimeError("network on fire")

    n = _run(discover.identify_hosts(
        inv, do_mdns=False, do_ssdp=False, do_http=False, probes={"netbios": boom},
    ))
    assert n == 0  # exception became a None result, no crash


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
