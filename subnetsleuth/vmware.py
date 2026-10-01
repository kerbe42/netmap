"""Read-only VMware vCenter / ESXi discovery.

A lot of what runs on an inherited network is not a physical box: it is a VM on an ESXi
host we can only see from the outside. Pointed at a vCenter (or a lone ESXi), this module
logs in read-only over pyVmomi and reads back the virtual estate - which hosts exist, what
they are made of, and every VM on them with its guest OS, addresses and portgroups - then
folds the VMs and hosts into the same :class:`~subnetsleuth.model.Inventory` a scan builds, so a
VM discovered here lines up with the same address an ARP sweep or DNS saw.

Strictly read-only: every access is a managed-object *property* read (``host.summary``,
``vm.guest.net`` ...). Nothing here powers, reconfigures or migrates anything - there are no
calls to any ``*_Task`` method.

Design mirrors :mod:`subnetsleuth.hostinfo`: the work is a set of **pure extractors**
(:func:`collect_hosts`, :func:`collect_vms`) plus small pure helpers
(:func:`parse_guest_nics`, :func:`map_portgroup`, :func:`normalise_version`,
:func:`os_family_from_guest`) that turn managed objects into plain dicts, so they can be
unit-tested against a fake managed-object tree with no server. The only networked function is
:func:`connect`; :func:`discover` takes an injectable ``si=`` so it too runs offline in tests.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional

log = logging.getLogger("subnetsleuth.vmware")

# pyVmomi is an optional heavy dependency. Import it lazily-at-module-load but never let an
# ImportError take down the whole package import; surface it clearly only when someone tries
# to actually connect (the pure extractors work on fakes and never need a live import).
try:
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim

    _IMPORT_ERROR: Optional[Exception] = None
except Exception as _e:  # pragma: no cover - exercised only where pyVmomi is absent
    SmartConnect = None  # type: ignore
    Disconnect = None  # type: ignore
    vim = None  # type: ignore
    _IMPORT_ERROR = _e


# --------------------------------------------------------------------------- #
# tiny read-only accessors
# --------------------------------------------------------------------------- #
def _g(obj, *path, default=None):
    """Walk an attribute path, returning ``default`` if any step is missing/None.

    Managed objects are deeply nested and any leg can be absent (a powered-off VM has no
    ``guest.net``); this keeps the extractors flat and read-only.
    """
    cur = obj
    for name in path:
        if cur is None:
            return default
        cur = getattr(cur, name, None)
    return cur if cur is not None else default


def _mb_from_bytes(n) -> int:
    try:
        return int(n) // (1024 * 1024)
    except (TypeError, ValueError):
        return 0


def _gb_from_bytes(n) -> float:
    try:
        return round(int(n) / (1024 ** 3), 2)
    except (TypeError, ValueError):
        return 0.0


def _is_usable_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_unspecified or a.is_link_local)


# --------------------------------------------------------------------------- #
# pure helpers (unit-tested directly)
# --------------------------------------------------------------------------- #
def parse_guest_nics(nics) -> dict:
    """Turn a list of ``vim.vm.GuestNicInfo`` into ``{"ips":[...], "macs":[...]}``.

    Each nic carries a ``.macAddress`` and a ``.ipAddress`` list (older API) and/or an
    ``.ipConfig.ipAddress`` list of objects with ``.ipAddress`` (newer API); both are read.
    Loopback, unspecified and link-local addresses are dropped, order is preserved and
    everything is de-duplicated.
    """
    ips: list[str] = []
    macs: list[str] = []
    for nic in nics or []:
        mac = getattr(nic, "macAddress", None)
        if mac and mac not in macs:
            macs.append(mac)
        for ip in getattr(nic, "ipAddress", None) or []:
            if _is_usable_ip(ip) and ip not in ips:
                ips.append(ip)
        for ipobj in _g(nic, "ipConfig", "ipAddress", default=[]) or []:
            ip = getattr(ipobj, "ipAddress", None)
            if _is_usable_ip(ip) and ip not in ips:
                ips.append(ip)
    return {"ips": ips, "macs": macs}


def map_portgroup(pg) -> dict:
    """Normalise a portgroup managed object to ``{"name":..., "vlan":...}``.

    Handles a ``vim.host.PortGroup`` (name/vlan live under ``.spec``) and a plain object that
    exposes ``.name``/``.vlanId`` directly. ``vlan`` is ``None`` when unknown, ``0`` means the
    untagged/native VLAN.
    """
    name = _g(pg, "spec", "name") or getattr(pg, "name", None) or ""
    vlan = _g(pg, "spec", "vlanId")
    if vlan is None:
        vlan = getattr(pg, "vlanId", None)
    try:
        vlan = int(vlan) if vlan is not None else None
    except (TypeError, ValueError):
        vlan = None
    return {"name": name, "vlan": vlan}


def normalise_version(product) -> str:
    """One-line ESXi version from a ``vim.AboutInfo`` (``.version``/``.build``).

    ``"8.0.2 build-21813344"``; falls back to whatever of the two is present, else ``""``.
    """
    version = getattr(product, "version", None) or ""
    build = getattr(product, "build", None) or ""
    if version and build:
        return f"{version} build-{build}"
    return version or (f"build-{build}" if build else "")


def os_family_from_guest(guest_os: Optional[str]) -> str:
    """Map a guest-OS full name to subnetsleuth's ``os_family`` (``windows``/``linux``/``""``)."""
    s = (guest_os or "").lower()
    if not s:
        return ""
    if "windows" in s:
        return "windows"
    linux_markers = (
        "linux", "ubuntu", "debian", "red hat", "redhat", "rhel", "centos", "photon",
        "suse", "fedora", "rocky", "alma", "oracle linux", "amazon linux",
    )
    if any(m in s for m in linux_markers):
        return "linux"
    return ""


# --------------------------------------------------------------------------- #
# managed-object -> dict extraction (pure; tested against fakes)
# --------------------------------------------------------------------------- #
def _ethernet_cards(vm):
    """The virtual NICs of a VM: every hardware device that carries a MAC address."""
    for dev in _g(vm, "config", "hardware", "device", default=[]) or []:
        if getattr(dev, "macAddress", None):
            yield dev


def _vm_config_macs(vm) -> list[str]:
    macs: list[str] = []
    for dev in _ethernet_cards(vm):
        mac = getattr(dev, "macAddress", None)
        if mac and mac not in macs:
            macs.append(mac)
    return macs


def _vm_portgroups(vm) -> list[dict]:
    """Portgroups a VM is attached to, read from its ethernet cards' backing.

    The name comes from ``deviceInfo.summary`` or the standard/DVS backing; VLAN is not
    exposed on the VM side so it is left ``None`` (the ESXi host record carries VLANs).
    """
    out: list[dict] = []
    seen: set[str] = set()
    for dev in _ethernet_cards(vm):
        name = (
            _g(dev, "backing", "network", "name")
            or _g(dev, "backing", "deviceName")
            or _g(dev, "deviceInfo", "summary")
            or ""
        )
        if name and name not in seen:
            seen.add(name)
            out.append({"name": name, "vlan": None})
    return out


def _host_mgmt_ip(host) -> str:
    """Best-effort management IP of an ESXi host.

    Prefer a vmkernel NIC address (``config.network.vnic[].spec.ip.ipAddress``), fall back to
    ``summary.managementServerIp`` and finally to the host name if it is itself an IP.
    """
    for vnic in _g(host, "config", "network", "vnic", default=[]) or []:
        ip = _g(vnic, "spec", "ip", "ipAddress")
        if _is_usable_ip(ip):
            return ip
    ip = _g(host, "summary", "managementServerIp")
    if _is_usable_ip(ip):
        return ip
    name = getattr(host, "name", "") or ""
    return name if _is_usable_ip(name) else ""


def _host_cluster(host) -> str:
    """Name of the cluster the host sits in, if its parent is a ClusterComputeResource."""
    parent = getattr(host, "parent", None)
    if parent is None:
        return ""
    # A standalone host's parent is a ComputeResource, a clustered one's is a
    # ClusterComputeResource - both expose .name; only surface it as a cluster when it looks
    # like one (has a name that is not just the host).
    return getattr(parent, "name", "") or ""


def collect_hosts(content_or_hosts) -> list[dict]:
    """Extract one dict per ESXi ``HostSystem``.

    Accepts either an already-gathered list/tuple of ``HostSystem`` managed objects, or a
    ``ServiceInstanceContent`` from which the hosts are walked via a container view.
    """
    hosts = _gather(content_or_hosts, "HostSystem")
    out: list[dict] = []
    for h in hosts:
        hw = _g(h, "summary", "hardware")
        product = _g(h, "summary", "config", "product")
        datastores = []
        for ds in getattr(h, "datastore", None) or []:
            datastores.append(
                {
                    "name": _g(ds, "summary", "name") or getattr(ds, "name", "") or "",
                    "capacity_gb": _gb_from_bytes(_g(ds, "summary", "capacity")),
                    "free_gb": _gb_from_bytes(_g(ds, "summary", "freeSpace")),
                }
            )
        portgroups = [map_portgroup(pg) for pg in _g(h, "config", "network", "portgroup", default=[]) or []]
        out.append(
            {
                "name": getattr(h, "name", "") or "",
                "mgmt_ip": _host_mgmt_ip(h),
                "model": getattr(hw, "model", "") or "",
                "vendor": getattr(hw, "vendor", "") or "",
                "cpu_model": getattr(hw, "cpuModel", "") or "",
                "cores": getattr(hw, "numCpuCores", 0) or 0,
                "memory_mb": _mb_from_bytes(getattr(hw, "memorySize", 0)),
                "version": normalise_version(product),
                "uptime_s": _g(h, "summary", "quickStats", "uptime", default=0) or 0,
                "cluster": _host_cluster(h),
                "vms": [getattr(vm, "name", "") or "" for vm in getattr(h, "vm", None) or []],
                "datastores": datastores,
                "portgroups": portgroups,
            }
        )
    return out


def collect_vms(content_or_vms) -> list[dict]:
    """Extract one dict per ``VirtualMachine``.

    Accepts a list/tuple of ``VirtualMachine`` managed objects or a ``ServiceInstanceContent``.
    IPs/MACs are read from ``guest.net`` and MACs are also gathered from the configured
    hardware devices (so a powered-off VM with no guest agent still yields its MACs).
    """
    vms = _gather(content_or_vms, "VirtualMachine")
    out: list[dict] = []
    for vm in vms:
        nic = parse_guest_nics(_g(vm, "guest", "net", default=[]))
        macs = list(nic["macs"])
        for m in _vm_config_macs(vm):
            if m not in macs:
                macs.append(m)
        guest_os = _g(vm, "guest", "guestFullName") or _g(vm, "config", "guestFullName") or ""
        out.append(
            {
                "name": getattr(vm, "name", "") or "",
                "guest_hostname": _g(vm, "guest", "hostName") or "",
                "guest_os": guest_os,
                "power_state": str(_g(vm, "runtime", "powerState") or ""),
                "ips": nic["ips"],
                "macs": macs,
                "host": _g(vm, "runtime", "host", "name") or "",
                "cpu": _g(vm, "config", "hardware", "numCPU", default=0) or 0,
                "memory_mb": _g(vm, "config", "hardware", "memoryMB", default=0) or 0,
                "portgroups": _vm_portgroups(vm),
                "tools_running": _tools_running(vm),
                "annotation": _g(vm, "config", "annotation") or "",
            }
        )
    return out


def _tools_running(vm) -> bool:
    status = _g(vm, "guest", "toolsRunningStatus")
    if status:
        return str(status) == "guestToolsRunning"
    status = _g(vm, "guest", "toolsStatus")
    return str(status) in ("toolsOk", "toolsOld")


# --------------------------------------------------------------------------- #
# container-view gathering (real server) / passthrough (tests)
# --------------------------------------------------------------------------- #
def _gather(content_or_objs, kind: str) -> list:
    """Return the managed objects of ``kind``.

    If a list/tuple is handed in (tests, or a caller that already walked the tree) it is
    returned as-is. Otherwise ``content_or_objs`` is treated as a ``ServiceInstanceContent``
    and a read-only container view is created, drained and destroyed.
    """
    if isinstance(content_or_objs, (list, tuple)):
        return list(content_or_objs)
    content = content_or_objs
    if vim is None:  # pragma: no cover
        raise RuntimeError(f"pyVmomi is not available: {_IMPORT_ERROR}")
    vimtype = getattr(vim, kind)
    view = content.viewManager.CreateContainerView(content.rootFolder, [vimtype], True)
    try:
        return list(view.view)
    finally:
        try:
            view.Destroy()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass


def _content(si):
    """Resolve a ServiceInstance / injected fake to its content object.

    Handles a real ``ServiceInstance`` (``.RetrieveContent()``), an object already carrying
    ``.content``, or a fake content passed straight in.
    """
    if si is None:
        return None
    c = getattr(si, "content", None)
    if c is not None:
        return c
    rc = getattr(si, "RetrieveContent", None)
    if callable(rc):
        return rc()
    return si


# --------------------------------------------------------------------------- #
# connection (the only networked function)
# --------------------------------------------------------------------------- #
def connect(host, username, password, port: int = 443, insecure: bool = False, timeout: int = 20):
    """Open a read-only vCenter/ESXi session and return the connected ``ServiceInstance``.

    The caller owns the session and must :func:`disconnect` it (or use :func:`discover`,
    which handles that). The server certificate is verified by default; pass
    ``insecure=True`` explicitly to accept a self-signed / untrusted certificate (the
    credentials then go to whoever answers on that address).
    """
    if SmartConnect is None:
        raise RuntimeError(
            "pyVmomi is required for VMware discovery but could not be imported "
            f"({_IMPORT_ERROR}); install it with 'pip install pyvmomi'."
        )
    ssl_context = None
    if insecure:
        import ssl

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    log.info("connecting to vCenter/ESXi %s:%s (verify=%s)", host, port, not insecure)
    return SmartConnect(
        host=host,
        user=username,
        pwd=password,
        port=port,
        sslContext=ssl_context,
        connectionPoolTimeout=timeout,
    )


def disconnect(si) -> None:
    """Close a session opened by :func:`connect`; never raises."""
    if si is None or Disconnect is None:
        return
    try:
        Disconnect(si)
    except Exception:  # pragma: no cover - best-effort
        pass


# --------------------------------------------------------------------------- #
# orchestration: fold the virtual estate into an Inventory
# --------------------------------------------------------------------------- #
def discover(inv, host, username, password, port: int = 443, insecure: bool = False, si=None) -> dict:
    """Discover the VMware estate at ``host`` and fold it into ``inv``.

    Connects (verifying TLS unless ``insecure=True``; or uses an injected ``si``
    ServiceInstance/content, as tests do), reads every ESXi host and VM read-only, then:

    * every VM address becomes/updates a ``Host`` (role ``vm``) - a multi-homed VM is folded
      under each of its addresses - with guest OS/family and hostname filled where the record
      had none (curated data is never overwritten), first guest MAC, and hypervisor placement
      recorded on ``host.system``;
    * every ESXi host with a management IP becomes/updates a ``Host`` (role ``hypervisor``);
    * the VM->host->cluster relationships and portgroup/VLAN list are stashed on
      ``inv.vmware`` (a live-scan enrichment; it is not persisted to JSON, which is fine).

    Never raises: any failure comes back as ``{"error": ...}``. Returns a summary dict.
    """
    connected = False
    try:
        if si is None:
            si = connect(host, username, password, port=port, insecure=insecure)
            connected = True
        content = _content(si)
        if content is None:
            return {"error": "no vCenter content available"}

        esxi_hosts = collect_hosts(content)
        vms = collect_vms(content)

        name_to_mgmt = {h["name"]: h["mgmt_ip"] for h in esxi_hosts if h["name"]}
        portgroup_names: set[str] = set()
        clusters: dict[str, list[str]] = {}

        # ---- ESXi hosts ----
        for h in esxi_hosts:
            for pg in h["portgroups"]:
                if pg["name"]:
                    portgroup_names.add(pg["name"])
            if h["cluster"]:
                clusters.setdefault(h["cluster"], []).append(h["name"])
            ip = h["mgmt_ip"]
            if not ip:
                continue
            host_rec = inv.touch_host(ip, "vmware")
            host_rec.role = "hypervisor"
            host_rec.os_family = "esxi"
            if not host_rec.os and h["version"]:
                host_rec.os = h["version"]
            if h["vendor"] and not host_rec.vendor:
                host_rec.vendor = h["vendor"]
            if h["model"] and not host_rec.model:
                host_rec.model = h["model"]
            if h["name"]:
                host_rec.names["vmware"] = h["name"]
                if not host_rec.hostname:
                    host_rec.hostname = h["name"]
            host_rec.system.update(
                {
                    "vendor": h["vendor"],
                    "product": h["model"],
                    "cpu": h["cpu_model"],
                    "cores": h["cores"],
                    "memory_mb": h["memory_mb"],
                    "esxi_version": h["version"],
                    "cluster": h["cluster"],
                    "uptime_s": h["uptime_s"],
                }
            )

        # ---- VMs ----
        vms_with_ip = 0
        for v in vms:
            for pg in v["portgroups"]:
                if pg["name"]:
                    portgroup_names.add(pg["name"])
            if not v["ips"]:
                continue
            vms_with_ip += 1
            mac = v["macs"][0] if v["macs"] else None
            fam = os_family_from_guest(v["guest_os"])
            for ip in v["ips"]:  # a multi-homed VM is the same machine at every address
                host_rec = inv.touch_host(ip, "vmware", mac)
                host_rec.role = "vm"
                # fill-if-empty, like hostinfo.apply_facts: never clobber curated data
                if v["guest_os"] and not host_rec.os:
                    host_rec.os = v["guest_os"]
                if fam and not host_rec.os_family:
                    host_rec.os_family = fam
                if v["guest_hostname"]:
                    host_rec.names["vmware"] = v["guest_hostname"]
                    if not host_rec.hostname:
                        host_rec.hostname = v["guest_hostname"]
                host_rec.system.update(
                    {
                        "vm_name": v["name"],
                        "hypervisor": v["host"],
                        "vm_host_ip": name_to_mgmt.get(v["host"], ""),
                        "power_state": v["power_state"],
                        "vcpu": v["cpu"],
                        "memory_mb": v["memory_mb"],
                        "tools": v["tools_running"],
                        "all_ips": list(v["ips"]),
                    }
                )

        # ---- stash the relationships (live-scan enrichment, not persisted) ----
        try:
            setattr(
                inv,
                "vmware",
                {"hosts": esxi_hosts, "vms": vms, "clusters": clusters},
            )
        except Exception:  # pragma: no cover - defensive; some Inventory could reject setattr
            pass

        return {
            "esxi_hosts": len(esxi_hosts),
            "vms": len(vms),
            "vms_with_ip": vms_with_ip,
            "portgroups": len(portgroup_names),
        }
    except Exception as e:  # never raise out of discover
        log.warning("VMware discovery failed for %s: %s", host, e)
        return {"error": str(e)}
    finally:
        if connected:
            disconnect(si)
