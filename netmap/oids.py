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
IF_LAST_CHANGE = "1.3.6.1.2.1.2.2.1.9"  # TimeTicks: sysUpTime at the last oper-status change
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HIGHSPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# IP-MIB ipAddrTable (IPv4)
IP_AD_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_AD_NETMASK = "1.3.6.1.2.1.4.20.1.3"

# ipNetToMediaTable (ARP)
ARP_PHYS = "1.3.6.1.2.1.4.22.1.2"
ARP_TYPE = "1.3.6.1.2.1.4.22.1.4"

# Routing: inetCidrRouteTable (RFC 4292) first, ipCidrRouteTable (RFC 2096) next, ipRouteTable (RFC 1213) last.
# inetCidrRoute index: DestType.Dest(len+octets).PfxLen.Policy(len+subids).NextHopType.NextHop(len+octets)
INET_CIDR_ROUTE_IFINDEX = "1.3.6.1.2.1.4.24.7.1.7"
INET_CIDR_ROUTE_TYPE = "1.3.6.1.2.1.4.24.7.1.8"
INET_CIDR_ROUTE_PROTO = "1.3.6.1.2.1.4.24.7.1.9"
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
DOT1Q_VLAN_FDB_ID = "1.3.6.1.2.1.17.7.1.4.2.1.3"  # dot1qVlanFdbId, index TimeMark.VlanIndex -> the FDB id used in dot1qTpFdbTable
DOT1Q_VLAN_CUR_EGRESS = "1.3.6.1.2.1.17.7.1.4.2.1.4"  # PortList, index TimeMark.VlanIndex
DOT1Q_VLAN_CUR_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.2.1.5"  # PortList, index TimeMark.VlanIndex
DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"  # access/native VLAN, index dot1dBasePort

# CISCO-VTP-MIB
VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
VTP_VLAN_NAME = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"
CISCO_TRUNK_NATIVE = "1.3.6.1.4.1.9.9.46.1.6.1.1.5"  # vlanTrunkPortNativeVlan, index ifIndex
CISCO_TRUNK_STATUS = "1.3.6.1.4.1.9.9.46.1.6.1.1.14"  # vlanTrunkPortDynamicStatus: 1 trunking, 2 not

# CISCO-VLAN-MEMBERSHIP-MIB
CISCO_VM_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"  # vmVlan: access VLAN, index ifIndex

# IEEE8023-LAG-MIB
LAG_ATTACHED_AGG = "1.2.840.10006.300.43.1.2.1.1.13"  # dot3adAggPortAttachedAggID, index member ifIndex

# ENTITY-MIB entPhysicalTable
ENT_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
ENT_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
ENT_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_NAME = "1.3.6.1.2.1.47.1.1.1.1.7"
ENT_HW_REV = "1.3.6.1.2.1.47.1.1.1.1.8"
ENT_FW_REV = "1.3.6.1.2.1.47.1.1.1.1.9"
ENT_SW_REV = "1.3.6.1.2.1.47.1.1.1.1.10"
ENT_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
ENT_IS_FRU = "1.3.6.1.2.1.47.1.1.1.1.16"  # TruthValue: 1 true, 2 false
ENT_CLASSES = {
    1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container", 6: "powerSupply", 7: "fan", 8: "sensor",
    9: "module", 10: "port", 11: "stack", 12: "cpu", 13: "energyObject", 14: "battery", 15: "storageDrive",
}

# OS version from the vendor's own MIB, for platforms whose sysDescr carries only the model
OS_VERSION_OIDS = {
    "Fortinet": "1.3.6.1.4.1.12356.101.4.1.1.0",  # fgSysVersion: "v7.2.5,build1517,230606 (GA.F)"
    "Palo Alto": "1.3.6.1.4.1.25461.2.1.2.1.1.0",  # panSysSwVersion: "10.2.4-h4"
    "MikroTik": "1.3.6.1.4.1.14988.1.1.4.4.0",  # mtxrLicVersion: "7.12"
}

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

# --- First-hop redundancy, routing adjacencies and spanning tree (topology understanding) ---
# CISCO-HSRP-MIB cHsrpGrpEntry, indexed by ifIndex.group
HSRP_STATE = "1.3.6.1.4.1.9.9.106.1.2.1.1.15"  # 1 initial 2 learn 3 listen 4 speak 5 standby 6 active
HSRP_VIP = "1.3.6.1.4.1.9.9.106.1.2.1.1.11"  # cHsrpGrpVirtualIpAddr
HSRP_PRIORITY = "1.3.6.1.4.1.9.9.106.1.2.1.1.3"

# VRRP-MIB vrrpOperEntry, indexed by ifIndex.vrId
VRRP_STATE = "1.3.6.1.2.1.68.1.3.1.3"  # 1 initialize 2 backup 3 master
VRRP_PRIORITY = "1.3.6.1.2.1.68.1.3.1.5"
VRRP_ASSOIP = "1.3.6.1.2.1.68.1.4.1.1"  # vrrpAssoIpAddr, VIP carried in the index

# OSPF-MIB ospfNbrTable
OSPF_NBR_STATE = "1.3.6.1.2.1.14.10.1.6"  # index nbrIp.addrlessIf; 8 = full
# BGP4-MIB bgpPeerTable
BGP_PEER_STATE = "1.3.6.1.2.1.15.3.1.2"  # 6 = established
BGP_PEER_REMADDR = "1.3.6.1.2.1.15.3.1.7"
BGP_PEER_REMAS = "1.3.6.1.2.1.15.3.1.9"

# BRIDGE-MIB spanning tree
STP_DESIGNATED_ROOT = "1.3.6.1.2.1.17.2.5.0"  # 8 bytes: priority(2) + root bridge MAC(6)
STP_ROOT_PORT = "1.3.6.1.2.1.17.2.7.0"
STP_PRIORITY = "1.3.6.1.2.1.17.2.2.0"
BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1.0"  # dot1dBaseBridgeAddress

# --- Interface health counters (IF-MIB / EtherLike-MIB) ---
IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
DOT3_DUPLEX = "1.3.6.1.2.1.10.7.2.1.19"  # 1 unknown 2 half 3 full, indexed by ifIndex

# --- Power over Ethernet (POWER-ETHERNET-MIB + Cisco ext) ---
PETH_PORT_ADMIN = "1.3.6.1.2.1.105.1.1.1.3"  # pethPsePortAdminEnable, index group.port
PETH_PORT_STATUS = "1.3.6.1.2.1.105.1.1.1.6"  # 1 disabled 2 searching 3 deliveringPower 4 fault 5 test 6 otherFault
PETH_PORT_CLASS = "1.3.6.1.2.1.105.1.1.1.10"  # pethPsePortPowerClassifications 1..5 = class0..4
PETH_MAIN_POWER = "1.3.6.1.2.1.105.1.3.1.1.2"  # pethMainPsePower, watts (budget), index pse
PETH_MAIN_CONSUMPTION = "1.3.6.1.2.1.105.1.3.1.1.4"  # pethMainPseConsumptionPower, watts (used)
CISCO_PETH_PORT_POWER = "1.3.6.1.4.1.9.9.402.1.2.1.7"  # cpeExtPsePortPwrConsumption, milliwatts, index group.port
