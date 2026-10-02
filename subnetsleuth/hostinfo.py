"""Agentless deep-inspection of hosts: log in read-only and pull the facts an asset
register wants - OS and hardware, installed software, running services and the active
network connections - without installing an agent on the target.

Linux/Unix are inspected over SSH (paramiko, as in subnetsleuth/capture.py); Windows over WinRM
(pywinrm). Nothing here ever changes the target: every command is a read (uname, cat,
Get-CimInstance, ...). The functions never raise - a connect/auth/parse failure comes back
as ``{"ok": False, "error": ...}`` so a scan of hundreds of hosts is never derailed by one.

Design: each collector is a set of **pure parsers** (``parse_*``) that turn captured command
output into the model's dicts, plus a thin network layer. The network layer takes an
injectable runner - ``run(cmd)->stdout`` for SSH, ``run_ps(script)->stdout`` for WinRM - so
the parsers and the collectors are unit-tested against canned output with no sockets.

Orchestrator injection seam: :func:`inspect_hosts` resolves its per-host inspectors from the
module-level :func:`inspect_ssh` / :func:`inspect_winrm` (so a test can monkeypatch
``subnetsleuth.hostinfo.inspect_ssh``), and also accepts explicit ``ssh_inspector=`` /
``winrm_inspector=`` overrides. Real callers (scan.py, a GUI worker) just call
``inspect_hosts(inv, creds)``; tests pass the overrides.
"""
from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from .profile import _APPLIANCE_ROLES as _PROFILE_APPLIANCES

# ---------------------------------------------------------------------------
# Commands (all read-only). Kept as constants so callers/tests can see exactly
# what runs on a target.
# ---------------------------------------------------------------------------
SSH_CMDS = {
    "uname": "uname -sr",
    "os_release": "cat /etc/os-release",
    "hostname": "hostname",
    "nproc": "nproc",
    "meminfo": "cat /proc/meminfo",
    "cpuinfo": "cat /proc/cpuinfo",
    "product": "cat /sys/class/dmi/id/product_name",
    "vendor": "cat /sys/class/dmi/id/sys_vendor",
    "serial": "cat /sys/class/dmi/id/product_serial",
    "serial_dmidecode": "dmidecode -s system-serial-number",
    "uptime": "cat /proc/uptime",
    "who": "who",
    "dpkg": r"dpkg-query -W -f='${Package}\t${Version}\n'",
    "rpm": r"rpm -qa --qf '%{NAME}\t%{VERSION}\n'",
    "services": "systemctl list-units --type=service --state=running --no-pager --no-legend",
    "ss": "ss -tunp",
    "netstat": "netstat -tunp",
}

WILDCARD_ADDRS = {"", "*", "0.0.0.0", "::", "[::]"}


def _empty(source: str, error: str = "") -> dict:
    return {"ok": False, "source": source, "system": {}, "software": [],
            "services": [], "connections": [], "error": error}


# ===========================================================================
# Linux/Unix parsers (pure)
# ===========================================================================
def parse_os_release(text: str) -> dict:
    """Parse /etc/os-release into {os, distro, version}."""
    kv: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        kv[k.strip()] = v.strip().strip('"').strip("'")
    os_name = kv.get("PRETTY_NAME") or " ".join(x for x in (kv.get("NAME"), kv.get("VERSION")) if x)
    return {"os": os_name, "distro": kv.get("ID", ""), "version": kv.get("VERSION_ID", "")}


def parse_meminfo(text: str) -> int:
    """MemTotal from /proc/meminfo, in MB (0 if absent)."""
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            m = re.search(r"(\d+)", line)
            if m:
                return int(m.group(1)) // 1024  # kB -> MB
    return 0


def parse_cpu_model(text: str) -> str:
    """First 'model name' from /proc/cpuinfo."""
    for line in text.splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip() if ":" in line else ""
    return ""


def parse_uptime(text: str) -> int:
    """Seconds of uptime from the first field of /proc/uptime."""
    text = text.strip()
    if not text:
        return 0
    try:
        return int(float(text.split()[0]))
    except (ValueError, IndexError):
        return 0


def parse_who(text: str) -> list[str]:
    """Distinct logged-on usernames from `who`/`w` output (first token per line)."""
    users: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        u = line.split()[0]
        if u and u not in users:
            users.append(u)
    return users


def parse_packages(text: str) -> list[dict]:
    """Tab-separated 'name\\tversion' from dpkg-query or rpm into [{name, version}]."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip("'").rstrip()
        if not line:
            continue
        parts = line.split("\t")
        name = parts[0].strip()
        if not name:
            continue
        out.append({"name": name, "version": parts[1].strip() if len(parts) > 1 else ""})
    return out


def parse_systemd_services(text: str) -> list[dict]:
    """`systemctl list-units --no-legend` lines into [{name, state}]."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        # UNIT LOAD ACTIVE SUB DESCRIPTION...
        name = parts[0]
        if not name.endswith(".service") and "." not in name:
            continue
        state = parts[3] if len(parts) >= 4 else "running"
        out.append({"name": name, "state": state})
    return out


def _split_hostport(s: str) -> tuple[str, str]:
    """Split 'addr:port' handling IPv6 ([::1]:22, fe80::1%eth0:22) and wildcards."""
    s = s.strip()
    if not s:
        return "", ""
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, sep, port = s.rpartition(":")
        if not sep:  # no colon at all
            host, port = s, ""
    if "%" in host:
        host = host.split("%", 1)[0]
    return host, port


def _proc_name(blob: str) -> str:
    """Pull a process name out of an ss users:(("name",pid=..)) or netstat pid/name blob."""
    m = re.search(r'\("([^"]+)"', blob)
    if m:
        return m.group(1)
    m = re.search(r"/([^/\s]+)$", blob.strip())
    if m and blob.strip() not in ("-",):
        return m.group(1)
    return ""


def _keep_connection(state: str, raddr: str, rport: str) -> bool:
    """A real connection: not a passive listener and with a concrete remote peer."""
    if state.upper() in ("LISTEN", "UNCONN") and raddr in WILDCARD_ADDRS:
        return False
    if raddr in WILDCARD_ADDRS or rport in ("", "*", "0"):
        return False
    return True


def parse_ss(text: str) -> list[dict]:
    """`ss -tunp` output into connection dicts (established/connected only)."""
    out: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):  # skips the header ("Netid ...")
            continue
        state = parts[1]
        laddr, lport = _split_hostport(parts[4])
        raddr, rport = _split_hostport(parts[5])
        process = _proc_name(" ".join(parts[6:])) if len(parts) > 6 else ""
        if not _keep_connection(state, raddr, rport):
            continue
        out.append({"proto": proto, "laddr": laddr, "lport": lport, "raddr": raddr,
                    "rport": rport, "state": state, "process": process})
    return out


_TCP_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
               "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "UNKNOWN"}


def parse_netstat(text: str) -> list[dict]:
    """`netstat -tunp` output into connection dicts (established/connected only).

    Column layout varies (UDP rows may or may not carry a State column), so the state is
    found by keyword and the process is taken from the trailing PID/Program field.
    """
    out: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].lower().startswith(("tcp", "udp")):
            continue
        proto = "udp" if parts[0].lower().startswith("udp") else "tcp"
        laddr, lport = _split_hostport(parts[3])
        raddr, rport = _split_hostport(parts[4])
        state = next((p for p in parts[5:] if p.upper() in _TCP_STATES), "")
        # the PID/Program column, when present (-p), is the last token: "1234/sshd" or "-"
        process = _proc_name(parts[-1]) if len(parts) > 5 else ""
        if not _keep_connection(state, raddr, rport):
            continue
        out.append({"proto": proto, "laddr": laddr, "lport": lport, "raddr": raddr,
                    "rport": rport, "state": state, "process": process})
    return out


# ===========================================================================
# Linux/Unix collector over SSH
# ===========================================================================
def _paramiko_run(ip, username, password, key_filename, port, timeout):
    """Connect with paramiko and return (client, run) where run(cmd)->stdout string.

    Host keys are checked trust-on-first-use (see :mod:`subnetsleuth.sshtrust`): a key that differs
    from the one recorded earlier raises and the host is reported as ``host key changed``."""
    import paramiko

    from .sshtrust import prepare_client

    client = prepare_client(paramiko.SSHClient())
    client.connect(ip, port=port, username=username, password=password or None,
                   key_filename=key_filename, timeout=timeout, banner_timeout=timeout,
                   auth_timeout=timeout, look_for_keys=bool(key_filename), allow_agent=False)

    def run(cmd: str) -> str:
        _in, out, _err = client.exec_command(cmd, timeout=timeout)
        return out.read().decode("utf-8", "replace")

    return client, run


def _safe(run: Callable[[str], str], cmd: str) -> str:
    """Run one command, swallowing any error (a denied/absent command is just empty)."""
    try:
        return run(cmd) or ""
    except Exception:  # noqa: BLE001 - one failed read must not sink the whole host
        return ""


def _collect_ssh(run: Callable[[str], str]) -> dict:
    """Run and parse every SSH command with an already-connected runner. Never raises."""
    osr = parse_os_release(_safe(run, SSH_CMDS["os_release"]))
    kernel = _safe(run, SSH_CMDS["uname"]).strip()
    hostname = _safe(run, SSH_CMDS["hostname"]).strip()
    try:
        cores = int(_safe(run, SSH_CMDS["nproc"]).strip() or 0)
    except ValueError:
        cores = 0
    memory_mb = parse_meminfo(_safe(run, SSH_CMDS["meminfo"]))
    cpu = parse_cpu_model(_safe(run, SSH_CMDS["cpuinfo"]))
    serial = _safe(run, SSH_CMDS["serial"]).strip() or _safe(run, SSH_CMDS["serial_dmidecode"]).strip()
    manufacturer = _safe(run, SSH_CMDS["vendor"]).strip()
    product = _safe(run, SSH_CMDS["product"]).strip()
    uptime_s = parse_uptime(_safe(run, SSH_CMDS["uptime"]))
    logged_on = parse_who(_safe(run, SSH_CMDS["who"]))

    software = parse_packages(_safe(run, SSH_CMDS["dpkg"]))
    if not software:
        software = parse_packages(_safe(run, SSH_CMDS["rpm"]))

    services = parse_systemd_services(_safe(run, SSH_CMDS["services"]))

    ss_out = _safe(run, SSH_CMDS["ss"])
    connections = parse_ss(ss_out)
    if not ss_out.strip():
        connections = parse_netstat(_safe(run, SSH_CMDS["netstat"]))

    system = {
        "os": osr["os"] or kernel,
        "hostname": hostname,
        "kernel": kernel,
        "cpu": cpu,
        "cores": cores,
        "memory_mb": memory_mb,
        "serial": _clean_dmi(serial),
        "manufacturer": _clean_dmi(manufacturer),
        "product": _clean_dmi(product),
        "uptime_s": uptime_s,
        "logged_on": logged_on,
    }
    return {"ok": True, "source": "ssh", "system": system, "software": software,
            "services": services, "connections": connections, "error": ""}


def _clean_dmi(v: str) -> str:
    """DMI fields are often placeholders on VMs; treat those as unknown."""
    if v.strip().lower() in ("", "none", "not specified", "to be filled by o.e.m.",
                             "system serial number", "default string", "not available"):
        return ""
    return v.strip()


def inspect_ssh(ip: str, username: str, password: str = "", key_filename: Optional[str] = None,
                port: int = 22, timeout: int = 15,
                run: Optional[Callable[[str], str]] = None) -> dict:
    """Deep-inspect a Linux/Unix host over SSH (read-only). Never raises.

    ``run`` is an injectable ``(command)->stdout`` callable; when omitted a paramiko
    connection is opened and used. Returns the standard facts dict; on connect/auth
    failure returns ``{"ok": False, "error": ...}``.
    """
    client = None
    if run is None:
        try:
            client, run = _paramiko_run(ip, username, password, key_filename, port, timeout)
        except Exception as e:  # noqa: BLE001 - connect/auth failure -> ok=False, never raise
            from .sshtrust import describe_error

            hk = describe_error(e)
            if hk:
                out = _empty("ssh", hk)
                out["host_key_changed"] = True
                return out
            return _empty("ssh", f"{type(e).__name__}: {e}")
    try:
        return _collect_ssh(run)
    except Exception as e:  # noqa: BLE001 - defensive; collectors are already safe
        return _empty("ssh", f"{type(e).__name__}: {e}")
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:  # noqa: BLE001
            pass


# ===========================================================================
# Windows parsers (pure) - fed canned ConvertTo-Json output
# ===========================================================================
def _load_json(text: str):
    """Parse JSON, tolerating empty output and PowerShell's single-item-not-a-list quirk."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _as_list(obj) -> list:
    if obj is None:
        return []
    return obj if isinstance(obj, list) else [obj]


def _get(d: dict, *keys, default=""):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return default


def parse_win_system(text: str) -> dict:
    """Parse the combined OS/ComputerSystem/BIOS/CPU ConvertTo-Json object."""
    d = _load_json(text) or {}
    if isinstance(d, list):
        d = d[0] if d else {}
    try:
        cores = int(_get(d, "cores", "Cores", "NumberOfLogicalProcessors", default=0) or 0)
    except (ValueError, TypeError):
        cores = 0
    try:
        memory_mb = int(round(float(_get(d, "memory_mb", "MemoryMB", default=0) or 0)))
    except (ValueError, TypeError):
        memory_mb = 0
    try:
        uptime_s = int(float(_get(d, "uptime_s", "UptimeSeconds", default=0) or 0))
    except (ValueError, TypeError):
        uptime_s = 0
    logged = _get(d, "logged_on", "UserName", "LoggedOn", default="")
    logged_on = logged if isinstance(logged, list) else ([logged] if logged else [])

    def _int(*keys, default):
        try:
            return int(_get(d, *keys, default=default))
        except (ValueError, TypeError):
            return default

    return {
        "os": _get(d, "os", "OS", "Caption"),
        "kernel": _get(d, "version", "Version", "BuildNumber"),
        "cpu": _get(d, "cpu", "CPU", "Name"),
        "cores": cores,
        "memory_mb": memory_mb,
        "serial": _get(d, "serial", "Serial", "SerialNumber"),
        "manufacturer": _get(d, "manufacturer", "Manufacturer"),
        "product": _get(d, "product", "Product", "Model"),
        "uptime_s": uptime_s,
        "logged_on": logged_on,
        "domain": _get(d, "domain", "Domain"),
        "hostname": _get(d, "hostname", "Hostname", "CSName", "Name"),
        # Win32_OperatingSystem.ProductType: 1 workstation, 2 domain controller, 3 server.
        # Win32_ComputerSystem.DomainRole: 4/5 are the backup/primary domain controller.
        "product_type": _int("product_type", "ProductType", default=0),
        "domain_role": _int("domain_role", "DomainRole", default=-1),
    }


def parse_win_software(text: str) -> list[dict]:
    """Parse Uninstall-registry / Win32_Product ConvertTo-Json into [{name, version}]."""
    out: list[dict] = []
    for item in _as_list(_load_json(text)):
        if not isinstance(item, dict):
            continue
        name = _get(item, "name", "DisplayName", "Name")
        if not name:
            continue
        out.append({"name": name, "version": _get(item, "version", "DisplayVersion", "Version")})
    return out


def parse_win_services(text: str) -> list[dict]:
    """Parse Get-Service ConvertTo-Json into [{name, state}]."""
    out: list[dict] = []
    for item in _as_list(_load_json(text)):
        if not isinstance(item, dict):
            continue
        name = _get(item, "name", "Name", "DisplayName")
        if not name:
            continue
        out.append({"name": name, "state": str(_get(item, "state", "Status", default="Running"))})
    return out


def parse_win_connections(text: str) -> list[dict]:
    """Parse Get-NetTCPConnection ConvertTo-Json into connection dicts."""
    out: list[dict] = []
    for item in _as_list(_load_json(text)):
        if not isinstance(item, dict):
            continue
        raddr = str(_get(item, "RemoteAddress", "raddr"))
        rport = str(_get(item, "RemotePort", "rport"))
        state = str(_get(item, "State", "state", default="Established"))
        if not _keep_connection(state, raddr, rport):
            continue
        out.append({
            "proto": "tcp",
            "laddr": str(_get(item, "LocalAddress", "laddr")),
            "lport": str(_get(item, "LocalPort", "lport")),
            "raddr": raddr,
            "rport": rport,
            "state": state,
            "process": _get(item, "ProcessName", "process", "OwningProcess"),
        })
    return out


# ===========================================================================
# Windows collector over WinRM
# ===========================================================================
PS_SYSTEM = r"""
$os=Get-CimInstance Win32_OperatingSystem
$cs=Get-CimInstance Win32_ComputerSystem
$bios=Get-CimInstance Win32_BIOS
$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1
[pscustomobject]@{
  os=$os.Caption; version=$os.Version; hostname=$cs.Name; domain=$cs.Domain;
  manufacturer=$cs.Manufacturer; product=$cs.Model; serial=$bios.SerialNumber;
  cpu=$cpu.Name; cores=$cs.NumberOfLogicalProcessors;
  memory_mb=[math]::Round($cs.TotalPhysicalMemory/1MB);
  uptime_s=[math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalSeconds);
  logged_on=$cs.UserName;
  product_type=$os.ProductType; domain_role=$cs.DomainRole
} | ConvertTo-Json -Compress
"""

PS_SOFTWARE = r"""
$paths='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
       'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}} |
  Sort-Object name -Unique | ConvertTo-Json -Compress
"""

PS_SERVICES = r"""
Get-Service | Where-Object { $_.Status -eq 'Running' } |
  Select-Object @{n='name';e={$_.Name}},@{n='state';e={$_.Status.ToString()}} |
  ConvertTo-Json -Compress
"""

PS_CONNECTIONS = r"""
$procs=@{}; Get-Process | ForEach-Object { $procs[$_.Id]=$_.ProcessName }
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,
    @{n='State';e={$_.State.ToString()}},OwningProcess,
    @{n='ProcessName';e={$procs[[int]$_.OwningProcess]}} |
  ConvertTo-Json -Compress
"""


WINRM_HTTP_PORT, WINRM_HTTPS_PORT = 5985, 5986


def _winrm_run_ps(ip, username, password, transport, timeout, port: int = WINRM_HTTP_PORT,
                  use_ssl: bool = False, verify_ssl: bool = True):
    """Return a run_ps(script)->stdout callable backed by a pywinrm session.

    Plain HTTP is only used with an authentication scheme that never sends the password in
    the clear (NTLM/Kerberos/CredSSP); ``basic``/``plaintext`` need ``use_ssl=True``."""
    if transport in ("basic", "plaintext") and not use_ssl:
        raise ValueError("WinRM basic authentication over plain HTTP would send the password in clear; "
                         "use transport='ntlm' (default) or use_ssl=True (port 5986)")
    import winrm

    scheme = "https" if use_ssl else "http"
    kwargs = {"transport": transport}
    if use_ssl:
        kwargs["server_cert_validation"] = "validate" if verify_ssl else "ignore"
    session = winrm.Session(f"{scheme}://{ip}:{port}/wsman", auth=(username, password), **kwargs)
    # pywinrm reads timeouts from the underlying protocol; set if available
    try:
        session.protocol.transport.timeout = timeout
        session.protocol.read_timeout_sec = timeout + 5
        session.protocol.operation_timeout_sec = timeout
    except Exception:  # noqa: BLE001
        pass

    def run_ps(script: str) -> str:
        r = session.run_ps(script)
        return (r.std_out or b"").decode("utf-8", "replace")

    return run_ps


def inspect_winrm(ip: str, username: str, password: str, transport: str = "ntlm",
                  timeout: int = 20,
                  run_ps: Optional[Callable[[str], str]] = None,
                  port: Optional[int] = None, use_ssl: bool = False, verify_ssl: bool = True) -> dict:
    """Deep-inspect a Windows host over WinRM (read-only PowerShell). Never raises.

    ``run_ps`` is an injectable ``(script)->stdout`` callable; when omitted a pywinrm
    session is opened on ``port`` (5985, or 5986 with ``use_ssl``). The default transport is
    NTLM; basic authentication is refused unless the session is TLS. Returns the standard
    facts dict; on failure ``ok=False``.
    """
    if port is None:
        port = WINRM_HTTPS_PORT if use_ssl else WINRM_HTTP_PORT
    try:
        if run_ps is None:
            run_ps = _winrm_run_ps(ip, username, password, transport, timeout, port=port,
                                   use_ssl=use_ssl, verify_ssl=verify_ssl)
        # The first call establishes the session; a failure here means auth/connect.
        sysj = run_ps(PS_SYSTEM)
    except Exception as e:  # noqa: BLE001 - connect/auth failure -> ok=False, never raise
        return _empty("winrm", f"{type(e).__name__}: {e}")
    try:
        system = parse_win_system(sysj)
        software = parse_win_software(_safe(run_ps, PS_SOFTWARE))
        services = parse_win_services(_safe(run_ps, PS_SERVICES))
        connections = parse_win_connections(_safe(run_ps, PS_CONNECTIONS))
        # keep the model's canonical system shape (drop hostname/domain into it too)
        return {"ok": True, "source": "winrm", "system": system, "software": software,
                "services": services, "connections": connections, "error": ""}
    except Exception as e:  # noqa: BLE001
        return _empty("winrm", f"{type(e).__name__}: {e}")


# ===========================================================================
# Apply + orchestrate
# ===========================================================================
def windows_role(system: dict) -> str:
    """Classify a Windows box from its authoritative WMI facts.

    ``Win32_OperatingSystem.ProductType`` is the reliable server-vs-workstation signal
    (1 = workstation, 2 = domain controller, 3 = server); ``Win32_ComputerSystem.DomainRole``
    (4 = backup DC, 5 = primary DC) corroborates a domain controller. Returns a role key
    (``dc`` / ``server`` / ``workstation``) or ``""`` when the facts don't say.
    """
    system = system or {}
    pt = system.get("product_type") or 0
    dr = system.get("domain_role")
    dr = dr if isinstance(dr, int) else -1
    if pt == 2 or dr in (4, 5):
        return "dc"
    if pt == 3:
        return "server"
    if pt == 1:
        return "workstation"
    return ""


def apply_facts(host, facts: dict) -> None:
    """Write a facts dict onto a :class:`~subnetsleuth.model.Host` (in place)."""
    facts = facts or {}
    system = facts.get("system") or {}
    host.system = system
    host.software = facts.get("software") or []
    host.services = facts.get("services") or []
    host.connections = facts.get("connections") or []
    host.inspected_at = time.time()
    source = facts.get("source", "")
    host.inspect_source = source
    if source and source not in host.sources:
        host.sources.append(source)
    # fill identity fields only where empty - never clobber curated data
    if not host.os and system.get("os"):
        host.os = system["os"]
    if not host.hostname and system.get("hostname"):
        host.hostname = system["hostname"]
    if not host.vendor and system.get("manufacturer"):
        host.vendor = system["manufacturer"]
    # an authenticated Windows login tells us, authoritatively, whether this is a server,
    # a domain controller or a workstation - better than any port/MAC heuristic, so it
    # sets the role (the user's own role override lives in the project note, not here).
    if source == "winrm":
        host.os_family = host.os_family or "windows"
        role = windows_role(system)
        if role:
            host.role = role
            host.confidence = "high"
            observed = f"ProductType={system.get('product_type')}"
            if system.get("domain_role", -1) in (4, 5):
                observed += f", DomainRole={system.get('domain_role')}"
            ev = {"source": "winrm", "observed": observed, "implies": role}
            if ev not in host.evidence:
                host.evidence.append(ev)


def _family(host) -> str:
    fam = (getattr(host, "os_family", "") or "").lower()
    if fam in ("linux", "macos", "unix", "bsd", "darwin", "esxi"):
        return "linux"
    if fam == "windows":
        return "windows"
    return "unknown"


# Appliances and network gear: their SSH/HTTP is a management plane with its own local
# accounts, and a read-only service account tried against them is a lockout waiting to
# happen. They are never inspected, whatever ports they expose.

SKIP_ROLES = frozenset(_PROFILE_APPLIANCES) | {"media", "unpolled", "subnet"}
SSH_PORT = 22
WINRM_PORTS = (WINRM_HTTP_PORT, WINRM_HTTPS_PORT)


def _open_ports(host) -> set[int]:
    out: set[int] = set()
    for p in getattr(host, "ports", None) or []:
        try:
            out.add(int(p.get("port")) if isinstance(p, dict) else int(p))
        except (TypeError, ValueError, AttributeError):
            continue
    return out


def _tcp_reachable(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Read-only reachability check: TCP connect then close, nothing sent."""
    import socket

    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _port_ok(host, ip: str, ports: tuple, check, timeout: float) -> bool:
    """True if one of `ports` is known open on the host, or (when its port list is unknown)
    answers a quick TCP connect via `check(ip, port)`."""
    known = _open_ports(host)
    if known:
        return any(p in known for p in ports)
    if check is None:
        return True
    return any(check(ip, p, timeout) for p in ports)


def _inspectable(host, creds: dict) -> bool:
    if (getattr(host, "role", "") or "") in SKIP_ROLES:
        return False
    fam = _family(host)
    if fam == "linux":
        return bool(creds.get("linux"))
    if fam == "windows":
        return bool(creds.get("windows"))
    return bool(creds.get("linux") or creds.get("windows"))


async def inspect_hosts(inv, creds: dict, hosts=None, workers: int = 16, timeout: int = 15,
                        ssh_inspector: Optional[Callable] = None,
                        winrm_inspector: Optional[Callable] = None,
                        scope=None, exclude=None,
                        port_check: Optional[Callable] = None) -> dict:
    """Deep-inspect a set of hosts concurrently and write the facts back onto ``inv``.

    ``creds`` is ``{"linux": {"username","password","key_filename","port"}, "windows":
    {"username","password","transport","port","use_ssl"}}``. By default the targets are the
    hosts in ``inv.hosts`` that are not already SNMP devices (``ip not in inv.ip_to_device``),
    are not appliances (:data:`SKIP_ROLES` - printers, cameras, PLCs, BMCs, phones, network
    gear...) and look inspectable: os_family linux/macos/bsd -> SSH, windows -> WinRM,
    unknown -> SSH then WinRM (whichever creds exist). Pass ``hosts`` (a list of IP strings)
    to override the selection.

    ``scope``/``exclude`` are lists of ``ipaddress.ip_network``; when ``scope`` is given every
    target must fall inside it and outside ``exclude`` (the GUI passes the project's scan scope
    so credentials are never presented to an address outside it).

    Credentials are only presented where the service is: SSH needs port 22 (WinRM 5985/5986)
    in the host's known open ports, or - when no port scan was done - a quick TCP connect
    (``port_check(ip, port, timeout) -> bool``; the default connects for real when the real
    inspectors are used and assumes reachable when injected, offline inspectors are used).

    Injection seam: the inspectors default to the module-level :func:`inspect_ssh` /
    :func:`inspect_winrm` (monkeypatchable), or pass ``ssh_inspector=`` / ``winrm_inspector=``
    with the same signatures to run without any network.

    Returns ``{"inspected", "ok", "linux", "windows", "failed"}`` (plus ``"skipped"`` when
    any host was skipped for missing ports or an appliance role).
    """
    import asyncio

    from .util import in_scope

    do_ssh = ssh_inspector or inspect_ssh
    do_winrm = winrm_inspector or inspect_winrm
    lc = creds.get("linux") or {}
    wc = creds.get("windows") or {}
    if port_check is None and ssh_inspector is None and winrm_inspector is None:
        port_check = _tcp_reachable

    if hosts is None:
        targets = [ip for ip, h in inv.hosts.items()
                   if ip not in inv.ip_to_device and _inspectable(h, creds)]
    else:
        targets = list(hosts)
    if scope is not None:
        targets = [ip for ip in targets if in_scope(ip, list(scope), list(exclude or []))]

    counts = {"inspected": 0, "ok": 0, "linux": 0, "windows": 0, "failed": 0}
    if not targets:
        return counts
    skipped = 0

    def _ssh(ip):
        return do_ssh(ip, username=lc.get("username", ""), password=lc.get("password", ""),
                      key_filename=lc.get("key_filename"), port=lc.get("port", SSH_PORT), timeout=timeout)

    def _winrm(ip):
        kw = {}
        if wc.get("port") or wc.get("use_ssl"):
            kw = {"port": wc.get("port") or (WINRM_HTTPS_PORT if wc.get("use_ssl") else WINRM_HTTP_PORT),
                  "use_ssl": bool(wc.get("use_ssl"))}
        return do_winrm(ip, username=wc.get("username", ""), password=wc.get("password", ""),
                        transport=wc.get("transport", "ntlm"), timeout=timeout, **kw)

    def work(ip: str) -> dict:
        """Blocking: pick the transport, run the inspector(s). Returns the facts dict."""
        host = inv.hosts.get(ip)
        role = (getattr(host, "role", "") or "") if host is not None else ""
        if role in SKIP_ROLES:
            return _empty("", f"skipped: {role} is an appliance/network device; credentials are not presented to it")
        fam = _family(host) if host is not None else "unknown"
        probe_t = min(float(timeout), 3.0)
        ssh_ports = (int(lc.get("port", SSH_PORT)),) if lc else ()
        win_ports = ((int(wc["port"]),) if wc.get("port") else WINRM_PORTS) if wc else ()
        ssh_ok = bool(lc) and _port_ok(host, ip, ssh_ports, port_check, probe_t)
        win_ok = bool(wc) and _port_ok(host, ip, win_ports, port_check, probe_t)
        if fam == "linux" and lc:
            return _ssh(ip) if ssh_ok else _empty("ssh", "skipped: SSH port not open/reachable")
        if fam == "windows" and wc:
            return _winrm(ip) if win_ok else _empty("winrm", "skipped: WinRM port (5985/5986) not open/reachable")
        # unknown: try SSH, then WinRM - only where the service is actually listening
        facts = None
        if ssh_ok:
            facts = _ssh(ip)
            if facts.get("ok"):
                return facts
        if win_ok:
            wfacts = _winrm(ip)
            if wfacts.get("ok") or facts is None:
                return wfacts
        if facts is None:
            if lc or wc:
                return _empty("", "skipped: neither SSH (22) nor WinRM (5985/5986) is open/reachable")
            return _empty("ssh", "no credentials for host")
        return facts

    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="subnetsleuth-inspect")
    sem = asyncio.Semaphore(workers)

    async def one(ip: str) -> None:
        nonlocal skipped
        async with sem:
            facts = await loop.run_in_executor(pool, work, ip)
        if (facts.get("error") or "").startswith("skipped:"):
            skipped += 1
            return
        counts["inspected"] += 1
        if facts.get("host_key_changed"):
            # surfaced to the caller (CLI log / GUI) as ip -> message; the message names
            # the known_hosts file so the operator can clear a legitimately re-keyed host
            counts.setdefault("host_key_changed", {})[ip] = facts.get("error") or "host key changed"
        host = inv.hosts.get(ip)
        if host is not None:
            apply_facts(host, facts)
        if facts.get("ok"):
            counts["ok"] += 1
            if facts.get("source") == "ssh":
                counts["linux"] += 1
            elif facts.get("source") == "winrm":
                counts["windows"] += 1
        else:
            counts["failed"] += 1

    try:
        await asyncio.gather(*(one(ip) for ip in targets))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if skipped:
        counts["skipped"] = skipped
    return counts
