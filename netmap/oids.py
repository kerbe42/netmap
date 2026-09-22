"""Raw OIDs used by the collector. No MIB files needed."""

# SNMPv2-MIB system group
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECTID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

# IF-MIB ifTable / ifXTable
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HIGHSPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# IP-MIB ipAddrTable (IPv4)
IP_AD_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_AD_NETMASK = "1.3.6.1.2.1.4.20.1.3"

# ipNetToMediaTable (ARP)
ARP_PHYS = "1.3.6.1.2.1.4.22.1.2"
ARP_TYPE = "1.3.6.1.2.1.4.22.1.4"

# Routing: ipCidrRouteTable (RFC 2096) preferred, ipRouteTable (RFC 1213) fallback
CIDR_ROUTE_IFINDEX = "1.3.6.1.2.1.4.24.4.1.5"
CIDR_ROUTE_TYPE = "1.3.6.1.2.1.4.24.4.1.6"
CIDR_ROUTE_PROTO = "1.3.6.1.2.1.4.24.4.1.7"
ROUTE_DEST = "1.3.6.1.2.1.4.21.1.1"
ROUTE_IFINDEX = "1.3.6.1.2.1.4.21.1.2"
ROUTE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"
ROUTE_TYPE = "1.3.6.1.2.1.4.21.1.8"
ROUTE_PROTO = "1.3.6.1.2.1.4.21.1.9"
ROUTE_MASK = "1.3.6.1.2.1.4.21.1.11"

# LLDP-MIB
LLDP_LOC_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.3.1.0"
LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"
LLDP_LOC_SYSNAME = "1.0.8802.1.1.2.1.3.3.0"
LLDP_LOC_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.7.1.2"
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.6"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYSDESC = "1.0.8802.1.1.2.1.4.1.1.10"
LLDP_REM_CAPS_ENABLED = "1.0.8802.1.1.2.1.4.1.1.12"
LLDP_REM_MAN_ADDR_IFSUBTYPE = "1.0.8802.1.1.2.1.4.2.1.3"

# CISCO-CDP-MIB cdpCacheTable
CDP_ADDR_TYPE = "1.3.6.1.4.1.9.9.23.1.2.1.1.3"
CDP_ADDR = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
CDP_CAPS = "1.3.6.1.4.1.9.9.23.1.2.1.1.9"

# BRIDGE-MIB / Q-BRIDGE-MIB
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1D_FDB_STATUS = "1.3.6.1.2.1.17.4.3.1.3"
DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
DOT1Q_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
DOT1Q_VLAN_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"

# CISCO-VTP-MIB
VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
VTP_VLAN_NAME = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"

# ENTITY-MIB
ENT_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"

# Enterprise numbers -> vendor (sysObjectID prefix 1.3.6.1.4.1.<n>)
ENTERPRISES = {
    9: "Cisco", 2636: "Juniper", 11: "HP", 25506: "HPE/H3C", 4526: "Netgear",
    14988: "MikroTik", 12356: "Fortinet", 2620: "Check Point", 3224: "Juniper/NetScreen",
    8072: "Net-SNMP", 311: "Microsoft", 41112: "Ubiquiti", 1916: "Extreme", 674: "Dell",
    43: "3Com", 171: "D-Link", 30065: "Arista", 25461: "Palo Alto", 14823: "Aruba",
    6027: "Dell/Force10", 1991: "Brocade/Foundry", 3375: "F5", 2011: "Huawei", 1588: "Brocade",
    8741: "SonicWall", 12325: "FreeBSD/pfSense", 6486: "Alcatel-Lucent", 2272: "Avaya",
    45: "Nortel", 890: "Zyxel", 3955: "Linksys", 4413: "Broadcom", 6889: "Avaya",
    5951: "Netscaler", 10002: "Frogfoot", 14179: "Cisco Wireless", 9303: "Ruckus", 25053: "Ruckus",
    17163: "Riverbed", 2021: "UCD-SNMP", 318: "APC", 232: "HPE/Compaq", 24681: "QNAP", 6574: "Synology",
    21317: "Aerohive", 10418: "Avocent", 3097: "Adtran", 35265: "Eltex", 40418: "Silver Peak",
    47196: "Meraki",
}
