"""Trust-on-first-use SSH host-key handling shared by the SSH collectors.

Both the config capture (:mod:`subnetsleuth.capture`) and the agentless inspection
(:mod:`subnetsleuth.hostinfo`) log in to devices with real credentials, so they must not accept
any host key blindly. The policy here mirrors what an operator's own ssh client does:

* keys from the system ``known_hosts`` (``~/.ssh/known_hosts``) are honoured;
* a host seen for the first time is recorded in SubnetSleuth's own per-user store and accepted;
* a host whose key **differs** from what was recorded is rejected with a clear error, so the
  UI/CLI can show "host key changed" and the operator can decide.

Nothing here needs Qt; the per-user store lives beside the app's other data:
``%LOCALAPPDATA%\\SubnetSleuth\\known_hosts`` on Windows, ``~/.local/share/subnetsleuth/known_hosts``
elsewhere (``SUBNETSLEUTH_KNOWN_HOSTS`` overrides the path, which tests use).
"""
from __future__ import annotations

import os
import shutil
import sys
from typing import Optional


def _data_dir(name: str) -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), name)
    return os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), name.lower())


def data_dir() -> str:
    """Per-user data folder for the core library (no Qt): created on demand."""
    path = _data_dir("SubnetSleuth")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path


def known_hosts_path() -> str:
    override = os.environ.get("SUBNETSLEUTH_KNOWN_HOSTS") or os.environ.get("NETMAP_KNOWN_HOSTS")
    if override:
        return override
    path = os.path.join(data_dir(), "known_hosts")
    old = os.path.join(_data_dir("NetMap"), "known_hosts")
    if not os.path.exists(path) and os.path.exists(old):
        # carry over the keys recorded before the rename, so a changed key is still noticed
        try:
            shutil.copy2(old, path)
        except OSError:
            pass
    return path


class HostKeyChanged(Exception):
    """The server presented a key that does not match the one recorded for it."""

    def __init__(self, hostname: str, key_type: str = "", fingerprint: str = "", path: str = ""):
        self.hostname = hostname
        self.key_type = key_type
        self.fingerprint = fingerprint
        self.path = path or known_hosts_path()
        super().__init__(
            f"host key changed for {hostname}: the server now presents a {key_type or 'different'} key "
            f"({fingerprint or 'unknown fingerprint'}) that does not match the one recorded on first use. "
            f"If the device was legitimately reinstalled, remove its entry from {self.path} and retry."
        )


def _fingerprint(key) -> str:
    try:
        import base64
        import hashlib

        digest = hashlib.sha256(key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    except Exception:  # noqa: BLE001
        return ""


def make_policy(path: Optional[str] = None):
    """A paramiko ``MissingHostKeyPolicy`` implementing trust-on-first-use over ``path``."""
    import paramiko

    store = path or known_hosts_path()

    class TrustOnFirstUse(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            # paramiko only calls this when no key of *this type* is known for the host;
            # a key of the same type that differs already raised BadHostKeyException.
            # If we know the host under another key type its keys have changed - reject.
            for keys in (getattr(client, "_host_keys", None), getattr(client, "_system_host_keys", None)):
                try:
                    if keys is not None and keys.lookup(hostname):
                        raise HostKeyChanged(hostname, key.get_name(), _fingerprint(key), store)
                except HostKeyChanged:
                    raise
                except Exception:  # noqa: BLE001 - a malformed store never blocks the check below
                    pass
            client._host_keys.add(hostname, key.get_name(), key)
            _save(client, store)

    return TrustOnFirstUse()


def _save(client, store: str) -> None:
    try:
        os.makedirs(os.path.dirname(store) or ".", exist_ok=True)
        client.save_host_keys(store)
    except OSError:
        pass


def prepare_client(client, path: Optional[str] = None):
    """Load the system and SubnetSleuth known_hosts into a paramiko ``SSHClient`` and install the
    trust-on-first-use policy. Returns the client."""
    store = path or known_hosts_path()
    try:
        client.load_system_host_keys()
    except Exception:  # noqa: BLE001 - no ~/.ssh is fine
        pass
    if os.path.exists(store):
        try:
            client.load_host_keys(store)
        except Exception:  # noqa: BLE001 - unreadable store: start fresh rather than fail every login
            client._host_keys_filename = store
    else:
        client._host_keys_filename = store
    client.set_missing_host_key_policy(make_policy(store))
    return client


def describe_error(exc: BaseException) -> Optional[str]:
    """A clear message when ``exc`` is a host-key problem, else None."""
    if isinstance(exc, HostKeyChanged):
        return str(exc)
    name = type(exc).__name__
    if name == "BadHostKeyException":
        host = getattr(exc, "hostname", "") or "?"
        got = getattr(exc, "key", None)
        return str(HostKeyChanged(host, got.get_name() if got is not None else "", _fingerprint(got) if got is not None else ""))
    return None


def is_host_key_error(exc: BaseException) -> bool:
    return describe_error(exc) is not None
