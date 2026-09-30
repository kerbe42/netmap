"""Read-only VMware discovery, tested against a fake managed-object tree (no vCenter).

The fakes are plain classes / SimpleNamespaces that mimic the shape of the pyVmomi managed
objects the extractors read - a HostSystem with .summary/.datastore/.vm/.config.network, a
VirtualMachine with .guest.net / .runtime / .config.hardware.device - so every assertion
runs offline. discover() is exercised through an injected fake ServiceInstance whose content
serves those objects via a fake container view; connect() is never called.
"""
from types import SimpleNamespace

from pyVmomi import vim

from netmap import vmware
from netmap.model import Inventory


# --------------------------------------------------------------------------- #
# fake managed objects
# --------------------------------------------------------------------------- #
def fake_nic(mac, ips):
    return SimpleNamespace(macAddress=mac, ipAddress=list(ips), ipConfig=None)


def fake_eth(mac, portgroup):
    """A VirtualEthernetCard-like device: carries a MAC and a network backing."""
    return SimpleNamespace(
        macAddress=mac,
        backing=SimpleNamespace(network=SimpleNamespace(name=portgroup), deviceName=portgroup),
        deviceInfo=SimpleNamespace(summary=portgroup),
    )


def fake_portgroup(name, vlan):
    return SimpleNamespace(spec=SimpleNamespace(name=name, vlanId=vlan))


def fake_datastore(name, cap_bytes, free_bytes):
    return SimpleNamespace(
        name=name,
        summary=SimpleNamespace(name=name, capacity=cap_bytes, freeSpace=free_bytes),
    )


def fake_host(name="esx-01", mgmt_ip="10.0.0.10", vms=None):
    return SimpleNamespace(
        name=name,
        summary=SimpleNamespace(
            hardware=SimpleNamespace(
                model="PowerEdge R740",
                vendor="Dell Inc.",
                cpuModel="Intel(R) Xeon(R) Gold 6248",
                numCpuCores=40,
                memorySize=512 * 1024 * 1024 * 1024,  # 512 GiB
            ),
            config=SimpleNamespace(product=SimpleNamespace(version="8.0.2", build="21813344")),
            quickStats=SimpleNamespace(uptime=123456),
            managementServerIp=None,
        ),
        config=SimpleNamespace(
            network=SimpleNamespace(
                vnic=[SimpleNamespace(spec=SimpleNamespace(ip=SimpleNamespace(ipAddress=mgmt_ip)))],
                portgroup=[fake_portgroup("VM Network", 0), fake_portgroup("Servers", 100)],
            )
        ),
        datastore=[fake_datastore("datastore1", 2 * 1024 ** 4, 1 * 1024 ** 4)],  # 2TB / 1TB
        vm=[SimpleNamespace(name=n) for n in (vms or ["web01", "db01"])],
        parent=SimpleNamespace(name="Cluster-A"),
    )


def fake_vm(
    name="web01",
    hostname="web01.corp.local",
    guest_os="Ubuntu Linux (64-bit)",
    power="poweredOn",
    ips=("10.0.0.50",),
    mac="00:50:56:aa:bb:cc",
    esxi="esx-01",
    tools="guestToolsRunning",
):
    guest = SimpleNamespace(
        hostName=hostname,
        guestFullName=guest_os,
        net=[fake_nic(mac, ips)] if ips else [],
        toolsRunningStatus=tools,
    )
    return SimpleNamespace(
        name=name,
        guest=guest,
        runtime=SimpleNamespace(
            powerState=power,
            host=SimpleNamespace(name=esxi),
        ),
        config=SimpleNamespace(
            guestFullName=guest_os,
            annotation="managed by netmap test",
            hardware=SimpleNamespace(
                numCPU=4,
                memoryMB=8192,
                device=[fake_eth(mac, "Servers")] if mac else [],
            ),
        ),
    )


class FakeView:
    def __init__(self, objs):
        self.view = list(objs)
        self.destroyed = False

    def Destroy(self):
        self.destroyed = True


class FakeViewManager:
    """Serves HostSystem or VirtualMachine objects depending on the requested vim type."""

    def __init__(self, hosts, vms):
        self._hosts = hosts
        self._vms = vms
        self.created = []

    def CreateContainerView(self, root, types, recursive):
        self.created.append((root, tuple(types), recursive))
        if vim.HostSystem in types:
            return FakeView(self._hosts)
        if vim.VirtualMachine in types:
            return FakeView(self._vms)
        return FakeView([])


class FakeContent:
    def __init__(self, hosts, vms):
        self.rootFolder = SimpleNamespace(name="Datacenters")
        self.viewManager = FakeViewManager(hosts, vms)


class FakeSI:
    """A ServiceInstance-shaped object: discover() reads .content off it."""

    def __init__(self, hosts, vms):
        self.content = FakeContent(hosts, vms)


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #
def test_parse_guest_nics_ips_and_macs():
    nics = [
        fake_nic("00:50:56:aa:bb:cc", ["10.0.0.50", "127.0.0.1", "fe80::1", "10.0.0.50"]),
        fake_nic("00:50:56:dd:ee:ff", ["192.168.1.5"]),
    ]
    out = vmware.parse_guest_nics(nics)
    assert out["ips"] == ["10.0.0.50", "192.168.1.5"]  # loopback/link-local/dupes dropped
    assert out["macs"] == ["00:50:56:aa:bb:cc", "00:50:56:dd:ee:ff"]


def test_parse_guest_nics_newer_ipconfig_shape():
    nic = SimpleNamespace(
        macAddress="00:50:56:12:34:56",
        ipAddress=None,
        ipConfig=SimpleNamespace(ipAddress=[SimpleNamespace(ipAddress="172.16.0.9")]),
    )
    out = vmware.parse_guest_nics([nic])
    assert out["ips"] == ["172.16.0.9"]
    assert out["macs"] == ["00:50:56:12:34:56"]


def test_parse_guest_nics_empty():
    assert vmware.parse_guest_nics(None) == {"ips": [], "macs": []}


def test_map_portgroup_spec_shape():
    assert vmware.map_portgroup(fake_portgroup("Servers", 100)) == {"name": "Servers", "vlan": 100}


def test_map_portgroup_native_vlan_zero():
    assert vmware.map_portgroup(fake_portgroup("VM Network", 0)) == {"name": "VM Network", "vlan": 0}


def test_map_portgroup_flat_shape_and_unknown_vlan():
    pg = SimpleNamespace(name="DVS-PG", vlanId=None, spec=None)
    assert vmware.map_portgroup(pg) == {"name": "DVS-PG", "vlan": None}


def test_normalise_version():
    assert vmware.normalise_version(SimpleNamespace(version="8.0.2", build="21813344")) == "8.0.2 build-21813344"
    assert vmware.normalise_version(SimpleNamespace(version="7.0.3", build=None)) == "7.0.3"
    assert vmware.normalise_version(SimpleNamespace(version=None, build=None)) == ""


def test_os_family_from_guest():
    assert vmware.os_family_from_guest("Microsoft Windows Server 2022 (64-bit)") == "windows"
    assert vmware.os_family_from_guest("Ubuntu Linux (64-bit)") == "linux"
    assert vmware.os_family_from_guest("Red Hat Enterprise Linux 9 (64-bit)") == "linux"
    assert vmware.os_family_from_guest("CentOS 7 (64-bit)") == "linux"
    assert vmware.os_family_from_guest("VMware Photon OS (64-bit)") == "linux"
    assert vmware.os_family_from_guest("Other (32-bit)") == ""
    assert vmware.os_family_from_guest("") == ""


# --------------------------------------------------------------------------- #
# collect_hosts / collect_vms
# --------------------------------------------------------------------------- #
def test_collect_hosts_fields():
    hosts = vmware.collect_hosts([fake_host()])
    assert len(hosts) == 1
    h = hosts[0]
    assert h["name"] == "esx-01"
    assert h["mgmt_ip"] == "10.0.0.10"
    assert h["model"] == "PowerEdge R740"
    assert h["vendor"] == "Dell Inc."
    assert h["cpu_model"].startswith("Intel")
    assert h["cores"] == 40
    assert h["memory_mb"] == 512 * 1024
    assert h["version"] == "8.0.2 build-21813344"
    assert h["uptime_s"] == 123456
    assert h["cluster"] == "Cluster-A"
    assert h["vms"] == ["web01", "db01"]
    assert h["datastores"][0] == {"name": "datastore1", "capacity_gb": 2048.0, "free_gb": 1024.0}
    assert {"name": "Servers", "vlan": 100} in h["portgroups"]
    assert {"name": "VM Network", "vlan": 0} in h["portgroups"]


def test_collect_hosts_from_content_via_view():
    content = FakeContent([fake_host()], [])
    hosts = vmware.collect_hosts(content)
    assert [h["name"] for h in hosts] == ["esx-01"]
    # the container view must have been asked for HostSystem objects
    assert any(vim.HostSystem in types for _, types, _ in content.viewManager.created)


def test_collect_vms_fields():
    vms = vmware.collect_vms([fake_vm()])
    assert len(vms) == 1
    v = vms[0]
    assert v["name"] == "web01"
    assert v["guest_hostname"] == "web01.corp.local"
    assert v["guest_os"] == "Ubuntu Linux (64-bit)"
    assert v["power_state"] == "poweredOn"
    assert v["ips"] == ["10.0.0.50"]
    assert v["macs"] == ["00:50:56:aa:bb:cc"]
    assert v["host"] == "esx-01"
    assert v["cpu"] == 4
    assert v["memory_mb"] == 8192
    assert v["portgroups"] == [{"name": "Servers", "vlan": None}]
    assert v["tools_running"] is True
    assert v["annotation"] == "managed by netmap test"


def test_collect_vms_poweredoff_no_guest_ip_still_has_config_mac():
    vm = fake_vm(name="db01", ips=(), power="poweredOff", tools="guestToolsNotRunning")
    v = vmware.collect_vms([vm])[0]
    assert v["ips"] == []
    assert v["macs"] == ["00:50:56:aa:bb:cc"]  # from config.hardware.device
    assert v["power_state"] == "poweredOff"
    assert v["tools_running"] is False


def test_collect_vms_guest_os_falls_back_to_config():
    vm = fake_vm()
    vm.guest.guestFullName = None  # force fallback to config.guestFullName
    v = vmware.collect_vms([vm])[0]
    assert v["guest_os"] == "Ubuntu Linux (64-bit)"


# --------------------------------------------------------------------------- #
# discover(): fold into an Inventory through an injected fake SI
# --------------------------------------------------------------------------- #
def test_discover_folds_vm_and_host_into_inventory():
    inv = Inventory()
    si = FakeSI([fake_host()], [fake_vm()])

    summary = vmware.discover(inv, "vcenter.local", "u", "p", si=si)

    assert summary == {"esxi_hosts": 1, "vms": 1, "vms_with_ip": 1, "portgroups": 2}

    # the VM became a Host with role vm, os_family, hostname, mac and hypervisor placement
    vm_host = inv.hosts["10.0.0.50"]
    assert vm_host.role == "vm"
    assert vm_host.os_family == "linux"
    assert vm_host.os == "Ubuntu Linux (64-bit)"
    assert vm_host.hostname == "web01.corp.local"
    assert vm_host.mac == "00:50:56:aa:bb:cc"
    assert "vmware" in vm_host.sources
    assert vm_host.system["hypervisor"] == "esx-01"
    assert vm_host.system["vm_host_ip"] == "10.0.0.10"
    assert vm_host.system["power_state"] == "poweredOn"
    assert vm_host.system["vcpu"] == 4
    assert vm_host.system["tools"] is True

    # the ESXi host became a Host too
    esx = inv.hosts["10.0.0.10"]
    assert esx.role == "hypervisor"
    assert esx.os_family == "esxi"
    assert esx.os == "8.0.2 build-21813344"
    assert esx.vendor == "Dell Inc."
    assert esx.model == "PowerEdge R740"
    assert esx.system["cores"] == 40
    assert esx.system["cluster"] == "Cluster-A"
    assert "vmware" in esx.sources

    # relationships stashed on inv.vmware
    assert inv.vmware["clusters"] == {"Cluster-A": ["esx-01"]}
    assert [h["name"] for h in inv.vmware["hosts"]] == ["esx-01"]
    assert [v["name"] for v in inv.vmware["vms"]] == ["web01"]


def test_discover_accepts_content_injected_as_si():
    inv = Inventory()
    content = FakeContent([fake_host()], [fake_vm()])  # a bare content, not wrapped in an SI
    summary = vmware.discover(inv, "vcenter.local", "u", "p", si=content)
    assert summary["esxi_hosts"] == 1
    assert "10.0.0.50" in inv.hosts


def test_discover_does_not_overwrite_existing_mac():
    inv = Inventory()
    inv.touch_host("10.0.0.50", "arp", "aa:bb:cc:dd:ee:ff")  # pre-existing MAC from another source
    vmware.discover(inv, "vcenter.local", "u", "p", si=FakeSI([fake_host()], [fake_vm()]))
    assert inv.hosts["10.0.0.50"].mac == "aa:bb:cc:dd:ee:ff"  # untouched


def test_discover_windows_vm_family_mapping():
    inv = Inventory()
    vm = fake_vm(name="dc01", hostname="dc01", guest_os="Microsoft Windows Server 2022 (64-bit)", ips=("10.0.0.60",))
    vmware.discover(inv, "v", "u", "p", si=FakeSI([fake_host()], [vm]))
    assert inv.hosts["10.0.0.60"].os_family == "windows"


def test_discover_vm_without_ip_is_not_folded_as_host():
    inv = Inventory()
    vm = fake_vm(name="db01", ips=(), power="poweredOff")
    summary = vmware.discover(inv, "v", "u", "p", si=FakeSI([fake_host()], [vm]))
    assert summary["vms"] == 1
    assert summary["vms_with_ip"] == 0
    # only the ESXi host address is present, no VM host address
    assert set(inv.hosts) == {"10.0.0.10"}


def test_discover_never_raises_returns_error():
    inv = Inventory()

    class Boom:
        @property
        def content(self):
            raise RuntimeError("kaboom")

    out = vmware.discover(inv, "v", "u", "p", si=Boom())
    assert "error" in out
    assert "kaboom" in out["error"]
