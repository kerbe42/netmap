"""Protect saved SNMP secrets at rest.

On Windows the desktop app encrypts communities and v3 keys with DPAPI
(CryptProtectData), which ties them to the Windows user account: another account, or
the same file copied to another PC, cannot decrypt them. Elsewhere `keyring` is used if
it is installed; with neither, secrets are kept for the session only and never written.
"""
from __future__ import annotations

import base64
import sys

# Kept from when the app was called NetMap: secrets saved then were protected with these
# identifiers, and changing them would make every saved credential unreadable.
ENTROPY = b"netmap-credential-v1"
KEYRING_SERVICE = "netmap"


class SecretUnavailable(Exception):
    pass


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(data: bytes) -> _Blob:
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def _call(fn, data: bytes) -> bytes:
        out = _Blob()
        src = _blob(data)
        ent = _blob(ENTROPY)
        CRYPTPROTECT_UI_FORBIDDEN = 0x01
        if not fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise SecretUnavailable(f"DPAPI failed: {ctypes.WinError()}")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    def protect(plain: str) -> str:
        return "dpapi:" + base64.b64encode(_call(ctypes.windll.crypt32.CryptProtectData, plain.encode("utf-8"))).decode("ascii")

    def unprotect(token: str) -> str:
        if not token.startswith("dpapi:"):
            raise SecretUnavailable("not a DPAPI token")
        return _call(ctypes.windll.crypt32.CryptUnprotectData, base64.b64decode(token[6:])).decode("utf-8")

    def available() -> str:
        return "Windows DPAPI (your Windows account)"

else:
    try:
        import keyring  # type: ignore
    except Exception:  # noqa: BLE001
        keyring = None

    def protect(plain: str, key: str = "") -> str:
        if not available():
            raise SecretUnavailable("no secret store on this platform")
        import secrets

        # The identifier is written to the settings file, so it must not be derived from
        # the secret (a hash of a short community would be guessable from a word list).
        ident = key or secrets.token_hex(8)
        try:
            keyring.set_password(KEYRING_SERVICE, ident, plain)
        except Exception as e:  # noqa: BLE001 - a locked or missing backend
            raise SecretUnavailable(str(e)) from e
        return "keyring:" + ident

    def unprotect(token: str) -> str:
        if not available() or not token.startswith("keyring:"):
            raise SecretUnavailable("no secret store on this platform")
        try:
            v = keyring.get_password(KEYRING_SERVICE, token[8:])
        except Exception as e:  # noqa: BLE001
            raise SecretUnavailable(str(e)) from e
        if v is None:
            raise SecretUnavailable("secret not found in keyring")
        return v

    def available() -> str:
        if keyring is None:
            return ""
        try:
            backend = keyring.get_keyring()
        except Exception:  # noqa: BLE001
            return ""
        mod = type(backend).__module__.lower()
        if "fail" in mod or "null" in mod:
            return ""  # keyring is installed but has nowhere to keep anything
        return "the system keyring"
