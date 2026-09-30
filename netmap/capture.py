"""Capture device running-configuration over SSH, and diff it over time.

Read-only: it logs in with the credentials you give, disables paging and runs the vendor's
'show running-config' (and a version command), then stores the text in the project so you can
read it and see what changed between captures. No configuration is ever sent.

The SSH transport is injectable (`transport=`), so the vendor command logic and the
shell-reading loop are unit-tested without a real device.
"""
from __future__ import annotations

import difflib
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# os_family / vendor -> (paging-disable command, running-config command, version command)
VENDOR_CMDS = {
    "ios": ("terminal length 0", "show running-config", "show version"),
    "ios-xe": ("terminal length 0", "show running-config", "show version"),
    "nx-os": ("terminal length 0", "show running-config", "show version"),
    "junos": ("set cli screen-length 0", "show configuration | display set", "show version"),
    "eos": ("terminal length 0", "show running-config", "show version"),
    "arista": ("terminal length 0", "show running-config", "show version"),
    "fortios": ("config system console\nset output standard\nend", "show full-configuration", "get system status"),
    "arubaos": ("no paging", "show running-config", "show version"),
    "arubaos-cx": ("no page", "show running-config", "show version"),
    "hp-provision": ("no page", "show running-config", "show version"),
    "routeros": ("", "/export", "/system resource print"),
}
DEFAULT_CMDS = ("terminal length 0", "show running-config", "show version")

# lines to drop from a captured config so diffs don't churn on timestamps/counters
NOISE = [
    re.compile(r"^\s*!?\s*(Current configuration|Last configuration change|! No configuration change|Building configuration|NVRAM config last updated)", re.I),
    re.compile(r"^\s*ntp clock-period"),
    re.compile(r"uptime is", re.I),
]


@dataclass
class Capture:
    ok: bool
    text: str = ""
    version: str = ""
    error: str = ""
    device: str = ""


def commands_for(os_family: str = "", vendor: str = "") -> tuple[str, str, str]:
    key = (os_family or "").lower()
    if key in VENDOR_CMDS:
        return VENDOR_CMDS[key]
    v = (vendor or "").lower()
    for hint, k in (("cisco", "ios"), ("arista", "eos"), ("juniper", "junos"), ("fortinet", "fortios"),
                    ("aruba", "arubaos-cx"), ("hp", "hp-provision"), ("mikrotik", "routeros")):
        if hint in v:
            return VENDOR_CMDS[k]
    return DEFAULT_CMDS


def clean_config(text: str) -> str:
    """Strip command echoes, pager artefacts and volatile lines so diffs show real changes."""
    lines = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if "\x08" in line:  # backspaces from a pager
            line = re.sub(r".\x08", "", line)
        if any(rx.search(line) for rx in NOISE):
            continue
        if re.search(r"--\s*More\s*--", line):
            continue
        lines.append(line)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines) + "\n"


def _read_shell(chan, commands: list[str], prompt_idle: float = 1.2, total: float = 90.0, recv=4096) -> str:
    """Send each command to an interactive shell channel and collect everything printed.

    Generic and prompt-free: it waits for output to go idle after each command rather than
    matching a device prompt, so it works across vendors. `chan` needs send(str),
    recv(n)->bytes, recv_ready()->bool and (optionally) recv_exit_status."""
    out = []
    deadline = time.time() + total
    # drain the login banner first
    _drain(chan, out, 1.5, recv)
    for cmd in commands:
        chan.send(cmd + "\n")
        _drain(chan, out, prompt_idle, recv, deadline)
        if time.time() > deadline:
            break
    return "".join(out)


def _drain(chan, out: list, idle: float, recv: int, deadline: float = 0.0):
    last = time.time()
    while True:
        if chan.recv_ready():
            data = chan.recv(recv)
            if not data:
                break
            out.append(data.decode("utf-8", "replace"))
            last = time.time()
        else:
            if time.time() - last >= idle:
                break
            if deadline and time.time() > deadline:
                break
            time.sleep(0.05)


def _paramiko_transport(ip, username, password, port, timeout, key_filename=None):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=username, password=password or None, key_filename=key_filename,
                   timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, look_for_keys=bool(key_filename), allow_agent=False)
    chan = client.invoke_shell(width=200, height=1000)
    chan.settimeout(timeout)
    return client, chan


def capture_config(ip: str, username: str, password: str = "", os_family: str = "", vendor: str = "",
                   port: int = 22, timeout: float = 15.0, key_filename: Optional[str] = None,
                   transport: Optional[Callable] = None) -> Capture:
    """Log in to `ip` and return its running-config. `transport(ip, user, pw, port, timeout)`
    may be injected (for tests); it must return (closer, channel) where channel behaves like a
    paramiko shell channel."""
    paging, run_cmd, ver_cmd = commands_for(os_family, vendor)
    cmds = [c for c in ([paging] if paging else []) + [ver_cmd, run_cmd] if c]
    closer = chan = None
    try:
        make = transport or (lambda *_a, **_k: _paramiko_transport(ip, username, password, port, timeout, key_filename))
        closer, chan = make(ip, username, password, port, timeout)
        raw = _read_shell(chan, cmds)
    except Exception as e:  # noqa: BLE001 - report any SSH/auth/timeout failure, never raise out
        return Capture(ok=False, error=f"{type(e).__name__}: {e}", device=ip)
    finally:
        for obj in (chan, closer):
            try:
                obj and obj.close()
            except Exception:  # noqa: BLE001
                pass
    text, version = _split(raw, run_cmd, ver_cmd)
    if not text.strip():
        return Capture(ok=False, error="logged in but no configuration was returned (wrong command for this platform, or paging blocked it)", device=ip)
    return Capture(ok=True, text=clean_config(text), version=version.strip()[:200], device=ip)


def _split(raw: str, run_cmd: str, ver_cmd: str) -> tuple[str, str]:
    """Pull the running-config and version sections out of the combined shell transcript."""
    version = ""
    # the config is everything from the run command echo onward
    idx = raw.find(run_cmd)
    text = raw[idx + len(run_cmd):] if idx >= 0 else raw
    vidx = raw.find(ver_cmd)
    if vidx >= 0:
        vend = raw.find(run_cmd, vidx + len(ver_cmd))
        version = raw[vidx + len(ver_cmd): vend if vend > 0 else vidx + 800]
        for line in version.splitlines():
            if line.strip() and not line.strip().startswith(ver_cmd):
                version = line.strip()
                break
    return text, version


def store_config(inv, device_id: str, cap: Capture, keep: int = 10) -> bool:
    """Save a capture into the project history for a device. Returns True if it differs from
    the last one stored (a change), False if identical (still refreshes the timestamp)."""
    if not cap.ok:
        return False
    sha = hashlib.sha256(cap.text.encode("utf-8", "replace")).hexdigest()
    hist = inv.configs.setdefault(device_id, [])
    changed = not hist or hist[-1].get("sha") != sha
    if changed:
        hist.append({"captured_at": time.time(), "text": cap.text, "sha": sha, "version": cap.version})
        del hist[:-keep]
    else:
        hist[-1]["captured_at"] = time.time()
    return changed


def diff_configs(old: str, new: str, old_label: str = "previous", new_label: str = "current") -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=old_label, tofile=new_label, lineterm="\n"))
