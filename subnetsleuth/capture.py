"""Capture device running-configuration over SSH, and diff it over time.

Read-only: it logs in with the credentials you give, disables paging with the vendor's
*exec-mode* command and runs the vendor's 'show running-config' (and a version command),
then stores the text in the project so you can read it and see what changed between
captures. No configuration-mode command is ever sent: :data:`VENDOR_CMDS` contains only
show/get/export-style commands, and a pager prompt (``--More--``) is answered with a space
rather than reconfigured away.

Secrets in a captured config (SNMP communities, type-7/5/8/9 password hashes, RADIUS and
TACACS keys, pre-shared keys, WPA passphrases, private keys) are replaced with ``<redacted>``
before the text is stored in the project, line structure intact so diffs still line up.

The SSH transport is injectable (`transport=`), so the vendor command logic and the
shell-reading loop are unit-tested without a real device.
"""
from __future__ import annotations

import difflib
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

# os_family / vendor -> (paging-disable command, running-config command, version command)
# Every entry is an exec/operational-mode command; none enters configuration mode.
VENDOR_CMDS = {
    "ios": ("terminal length 0", "show running-config", "show version"),
    "ios-xe": ("terminal length 0", "show running-config", "show version"),
    "nx-os": ("terminal length 0", "show running-config", "show version"),
    "junos": ("set cli screen-length 0", "show configuration | display set", "show version"),
    "eos": ("terminal length 0", "show running-config", "show version"),
    "arista": ("terminal length 0", "show running-config", "show version"),
    # FortiOS pages exec output with --More-- when 'output more' is set; the reader answers
    # the pager instead of changing the console setting (that would be a config write).
    "fortios": ("", "show full-configuration", "get system status"),
    "arubaos": ("no paging", "show running-config", "show version"),
    "arubaos-cx": ("no page", "show running-config", "show version"),
    "hp-provision": ("no page", "show running-config", "show version"),
    "routeros": ("", "/export", "/system resource print"),
}
DEFAULT_CMDS = ("terminal length 0", "show running-config", "show version")

# Anything sent to a device must be one of these shapes: never a configuration command.
_CONFIG_MODE = re.compile(r"^\s*(config|configure|conf\s+t|edit\s|commit|write|copy|reload|delete|erase|clear\s)", re.I)

# lines to drop from a captured config so diffs don't churn on timestamps/counters
NOISE = [
    re.compile(r"^\s*!?\s*(Current configuration|Last configuration change|! No configuration change|Building configuration|NVRAM config last updated)", re.I),
    re.compile(r"^\s*ntp clock-period"),
    re.compile(r"uptime is", re.I),
]

_MORE = re.compile(r"--\s*more\s*--|-- more --|<--- more --->|press any key to continue|lines \d+-\d+", re.I)
_PROMPT_TAIL = re.compile(r"^(.*?)\s*[>#$%]\s*$")


@dataclass
class Capture:
    ok: bool
    text: str = ""
    version: str = ""
    error: str = ""
    device: str = ""
    host_key_changed: bool = False  # the SSH host key did not match the one recorded on first use


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


def is_config_command(cmd: str) -> bool:
    """True if `cmd` would enter configuration mode or change state on any supported vendor."""
    return any(_CONFIG_MODE.match(line) for line in (cmd or "").splitlines())


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


# --------------------------------------------------------------------------- #
# interactive shell reading
# --------------------------------------------------------------------------- #
def learn_prompt(banner: str) -> Optional[re.Pattern]:
    """Build a regex matching the device prompt from the last line of the login banner.

    ``core-sw-01>`` becomes a pattern that also matches ``core-sw-01#`` (enable) and a
    trailing space; Junos ``user@host>`` and RouterOS ``[admin@MikroTik] >`` work the same
    way. None when the banner gives nothing usable (the reader then falls back to idle).
    """
    lines = [ln.strip() for ln in banner.replace("\r", "\n").split("\n") if ln.strip()]
    if not lines:
        return None
    m = _PROMPT_TAIL.match(lines[-1])
    if not m or not m.group(1).strip():
        return None
    base = m.group(1).strip()
    if len(base) > 80:
        return None
    return re.compile(re.escape(base) + r"\s*[>#$%]\s*$")


def _read_shell(chan, commands: list[str], prompt_idle: float = 1.2, total: float = 90.0, recv=4096,
                pause_tolerance: float = 8.0) -> str:
    """Send each command to an interactive shell channel and collect everything printed.

    The prompt is learned from the login banner and each command is considered finished when
    the prompt comes back, so a device that pauses mid-output ("Building configuration..." on
    IOS) does not get truncated. Without a recognisable prompt it falls back to waiting for
    output to go idle. Pager prompts (``--More--``) are answered with a space. `chan` needs
    send(str), recv(n)->bytes and recv_ready()->bool."""
    out: list[str] = []
    deadline = time.time() + total
    banner: list[str] = []
    _drain(chan, banner, prompt_idle if prompt_idle < 1.5 else 1.5, recv)
    out.extend(banner)
    prompt = learn_prompt("".join(banner))
    for cmd in commands:
        if is_config_command(cmd):
            raise ValueError(f"refusing to send a configuration-mode command: {cmd!r}")
        chan.send(cmd + "\n")
        _drain(chan, out, prompt_idle, recv, deadline, prompt=prompt, pause_tolerance=pause_tolerance)
        if time.time() > deadline:
            break
    return "".join(out)


def _drain(chan, out: list, idle: float, recv: int, deadline: float = 0.0,
           prompt: Optional[re.Pattern] = None, pause_tolerance: float = 8.0):
    """Read from the channel until the prompt is seen (when known), the output goes idle, or
    the deadline passes. Pager prompts are answered with a space."""
    last = time.time()
    tail = ""
    max_idle = pause_tolerance if prompt is not None else idle
    while True:
        if chan.recv_ready():
            data = chan.recv(recv)
            if not data:
                break
            text = data.decode("utf-8", "replace")
            out.append(text)
            last = time.time()
            tail = (tail + text)[-400:]
            last_line = tail.replace("\r", "\n").rstrip("\n").rsplit("\n", 1)[-1]
            if _MORE.search(last_line):
                try:
                    chan.send(" ")
                except Exception:  # noqa: BLE001
                    break
                tail = ""
                continue
            if prompt is not None and prompt.search(last_line.strip("\x08 ")):
                # the prompt is back: give a moment for anything still in flight, then stop
                if not _settle(chan, 0.15):
                    break
        else:
            if time.time() - last >= max_idle:
                break
            if deadline and time.time() > deadline:
                break
            time.sleep(0.05)


def _settle(chan, wait: float) -> bool:
    """True if more data arrives within `wait` seconds (so the caller keeps reading)."""
    end = time.time() + wait
    while time.time() < end:
        if chan.recv_ready():
            return True
        time.sleep(0.02)
    return False


def _paramiko_transport(ip, username, password, port, timeout, key_filename=None):
    import paramiko

    from .sshtrust import prepare_client

    client = prepare_client(paramiko.SSHClient())
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
    paramiko shell channel. A host whose SSH key changed since it was first seen is refused
    and reported with ``host_key_changed=True``."""
    from .sshtrust import describe_error

    paging, run_cmd, ver_cmd = commands_for(os_family, vendor)
    cmds = [c for c in ([paging] if paging else []) + [ver_cmd, run_cmd] if c]
    closer = chan = None
    try:
        make = transport or (lambda *_a, **_k: _paramiko_transport(ip, username, password, port, timeout, key_filename))
        closer, chan = make(ip, username, password, port, timeout)
        raw = _read_shell(chan, cmds)
    except Exception as e:  # noqa: BLE001 - report any SSH/auth/timeout failure, never raise out
        hk = describe_error(e)
        if hk:
            return Capture(ok=False, error=hk, device=ip, host_key_changed=True)
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


# --------------------------------------------------------------------------- #
# secret redaction
# --------------------------------------------------------------------------- #
REDACTED = "<redacted>"
_TOKEN = r'("[^"]*"|\'[^\']*\'|\S+)'
# words that follow "password"/"secret" without being a secret themselves
_NOT_SECRET = {"min-length", "encryption", "policy", "expiry", "type", "none", "required", "enable", "disable",
               "complexity", "history", "aging", "strength", "max-age", "lockout", "attempts", "change", "reuse",
               "length", "recovery", "no", "authentication", "level", "mode", "rules", "cleartext", "hash",
               "md5", "sha", "sha1", "sha256", "sha512", "des", "3des", "aes", "key", "key-string", "key-chain",
               "chain", "ascii", "hex", "text", "local", "remote"}
_HASH_ALGOS = r"(?:sha512|sha256|sha1|sha|md5)"
# (pattern with group 1 = prefix to keep, group 2 = the secret) - applied to every line, case-insensitive.
# Order matters where one keyword is nested in another's syntax (HSRP "authentication md5 key-string 7 X").
_SECRET_RES = [re.compile(p, re.I) for p in (
    # SNMP communities: IOS/NX-OS/EOS "snmp-server community X ...", Junos "set snmp community X", Junos
    # hierarchical "community X {", IOS trap target "snmp-server host A [version 2c] X"
    r"(\bsnmp-server\s+community\s+)" + _TOKEN,
    r"(\bsnmp\s+community\s+)" + _TOKEN,
    r"(^\s*community\s+)" + _TOKEN + r"(?=\s*[{;])",
    r"(\bsnmp-server\s+host\s+\S+(?:\s+(?:informs|traps|version\s+\S+|vrf\s+\S+|udp-port\s+\d+))*\s+)" + _TOKEN,
    # SNMPv3 user auth/priv secrets (IOS "auth md5 X priv aes 128 Y", NX-OS "auth md5 0x.. priv 0x..")
    r"(\bauth\s+" + _HASH_ALGOS + r"\s+)" + _TOKEN,
    r"(\bpriv\s+(?:des|3des|aes\s+\d+|aes)\s+)" + _TOKEN,
    r"(\bpriv\s+)(0x\S+)",
    # HSRP/VRRP before the generic md5 rule, so "authentication md5 key-string 7 X" redacts X
    r"(\b(?:standby|vrrp)\s+\d+\s+authentication\s+(?:text\s+|md5\s+key-string\s+(?:[0-9]\s+)?)?)" + _TOKEN,
    # passwords and secrets: "enable secret 5 $1$..", "password 7 0822..", "username a secret 9 $9$..",
    # EOS "secret sha512 $6$..", Junos 'encrypted-password "$6$.."', 'secret "$9$.."', FortiOS "set password ENC .."
    r"(\bpassword\s+level\s+\d+\s+(?:[0-9]\s+)?)" + _TOKEN,
    r"(\b(?:password|passwd|secret|encrypted-password|plain-text-password-value|psksecret|passphrase|wpa-passphrase|"
    r"shared-secret|auth-pwd|priv-pwd|privacy-pwd|auth-password(?:-l\d)?|priv-password(?:-l\d)?)\s+"
    r"(?:ENC\s+|[0-9]\s+|" + _HASH_ALGOS + r"\s+)?)" + _TOKEN,
    r"(\bset\s+(?:\S*(?:password|passwd|pwd|secret|psk|passphrase)\S*)\s+(?:ENC\s+)?)" + _TOKEN,
    # keys: RADIUS/TACACS/keychain/NTP/OSPF/IKE
    r"(\b(?:tacacs-server|radius-server|tacacs|radius)\s+key\s+(?:[0-9]\s+)?)" + _TOKEN,
    r"(\bserver-private\s+\S+(?:\s+(?:auth-port|acct-port|timeout|port|retransmit)\s+\d+)*\s+key\s+(?:[0-9]\s+)?)" + _TOKEN,
    r"(\bkey-string\s+(?:[0-9]\s+)?)" + _TOKEN,
    r"((?<![-\w])key\s+[0-9]\s+)" + _TOKEN,  # "key 7 0822455D0A16" - an encryption-type digit marks a secret
    r"((?<![-\w])key\s+)(\"[^\"]*\"|\$\d\$\S+)",  # Junos 'key "$9$.."'
    r"(\bset\s+key\s+(?:ENC\s+)?)" + _TOKEN,
    r"(\bcrypto\s+isakmp\s+key\s+(?:[0-9]\s+)?)" + _TOKEN,
    r"(\bpre-shared-key\s+(?:(?:local|remote)\s+)?(?:[0-9]\s+)?(?:ascii-text\s+|hexadecimal\s+)?)" + _TOKEN,
    r"(\bmd5\s+(?:[0-9]\s+)?)" + _TOKEN + r"(?=\s|$)",  # "ip ospf message-digest-key 1 md5 7 X", "ntp authentication-key 1 md5 X 7"
    r"(\bauthentication-key\s+(?:[0-9]\s+)?)" + _TOKEN,
    # wireless
    r"(\bwpa-psk\s+(?:ascii|hex)\s+(?:[0-9]\s+)?)" + _TOKEN,
    r"(\b(?:wpa2?-preshared-key|wpa2?-pre-shared-key|preshared-key|psk)\s+(?:ENC\s+|[0-9]\s+)?)" + _TOKEN,
    # key=value styles (RouterOS export, some appliances)
    r"(\b(?:password|passwd|secret|psk|wpa-pre-shared-key|wpa2-pre-shared-key|authentication-password|encryption-password|key)=)" + _TOKEN,
)]
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_FORTI_CONFIG = re.compile(r"^\s*config\s+(.+?)\s*$", re.I)
_FORTI_END = re.compile(r"^\s*end\s*$", re.I)
_FORTI_SET_NAME = re.compile(r"(^\s*set\s+name\s+)" + _TOKEN, re.I)
_FORTI_MULTILINE = re.compile(r"^(\s*set\s+(?:private-key|passphrase|password)\s+)\"(?:[^\"\\]|\\.)*$", re.I)


def _redact_token(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        return tok[0] + REDACTED + tok[0]
    return REDACTED


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace secret tokens in a device configuration with ``<redacted>``.

    Line count and structure are preserved (only the secret token changes), so a diff between
    two redacted captures still lines up. Returns ``(text, number_of_redactions)``. Covers
    IOS/IOS-XE/NX-OS/EOS, Junos (set and hierarchical), FortiOS, ArubaOS, RouterOS and PEM
    private-key blocks.
    """
    count = 0
    out: list[str] = []
    forti_stack: list[str] = []
    in_pem = False
    in_forti_multiline = False
    for line in (text or "").split("\n"):
        stripped = line.strip()
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
                out.append(line)
            else:
                count += 1
                out.append(REDACTED)
            continue
        if _PEM_BEGIN.search(line):
            in_pem = True
            out.append(line)
            continue
        if in_forti_multiline:
            count += 1
            if stripped.endswith('"') and not stripped.endswith('\\"'):
                in_forti_multiline = False
                out.append(REDACTED + '"')
            else:
                out.append(REDACTED)
            continue
        m = _FORTI_MULTILINE.match(line)
        if m:
            in_forti_multiline = True
            count += 1
            out.append(m.group(1) + '"' + REDACTED)
            continue
        # FortiOS nesting: an SNMP community's name is the secret ("config system snmp community" / "set name")
        cm = _FORTI_CONFIG.match(line)
        if cm:
            forti_stack.append(cm.group(1).lower())
        elif _FORTI_END.match(line) and forti_stack:
            forti_stack.pop()
        if forti_stack and "snmp community" in forti_stack[-1]:
            nm = _FORTI_SET_NAME.match(line)
            if nm:
                count += 1
                out.append(nm.group(1) + _redact_token(nm.group(2)))
                continue
        new = line
        for rx in _SECRET_RES:
            def repl(mo, _rx=rx):
                nonlocal count
                tok = mo.group(2)
                if tok.strip("\"'").lower() in _NOT_SECRET or tok.lower() == REDACTED or tok.lower() in ('"<redacted>"', "'<redacted>'"):
                    return mo.group(0)
                count += 1
                return mo.group(1) + _redact_token(tok) + mo.group(0)[len(mo.group(1)) + len(tok):]
            new = rx.sub(repl, new)
        out.append(new)
    return "\n".join(out), count


def store_config(inv, device_id: str, cap: Capture, keep: int = 10, redact: bool = True) -> bool:
    """Save a capture into the project history for a device. Returns True if it differs from
    the last one stored (a change), False if identical (still refreshes the timestamp).

    Secrets are redacted before storing (``redact=True``); the entry carries
    ``redacted: True`` when anything was replaced. Because the hash is taken over the
    redacted text, a rotated password alone does not register as a configuration change."""
    if not cap.ok:
        return False
    text = cap.text
    n = 0
    if redact:
        text, n = redact_secrets(text)
    sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    hist = inv.configs.setdefault(device_id, [])
    changed = not hist or hist[-1].get("sha") != sha
    if changed:
        hist.append({"captured_at": time.time(), "text": text, "sha": sha, "version": cap.version, "redacted": n > 0})
        del hist[:-keep]
    else:
        hist[-1]["captured_at"] = time.time()
    return changed


def diff_configs(old: str, new: str, old_label: str = "previous", new_label: str = "current") -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=old_label, tofile=new_label, lineterm="\n"))
