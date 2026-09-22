"""Thin async SNMP client over pysnmp 7 using raw OIDs (no MIB loading)."""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    EndOfMibView,
    IpAddress,
    NoSuchInstance,
    NoSuchObject,
    Null,
    ObjectIdentifier,
    ObjectIdentity,
    ObjectType,
    OctetString,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
)
from pysnmp.hlapi.v3arch.asyncio import auth as _auth
from pysnmp.proto import errind

log = logging.getLogger("netmap.snmp")

AUTH_PROTOS = {
    "MD5": _auth.usmHMACMD5AuthProtocol,
    "SHA": _auth.usmHMACSHAAuthProtocol,
    "SHA1": _auth.usmHMACSHAAuthProtocol,
    "SHA224": _auth.usmHMAC128SHA224AuthProtocol,
    "SHA256": _auth.usmHMAC192SHA256AuthProtocol,
    "SHA384": _auth.usmHMAC256SHA384AuthProtocol,
    "SHA512": _auth.usmHMAC384SHA512AuthProtocol,
    "NONE": _auth.usmNoAuthProtocol,
}
PRIV_PROTOS = {
    "DES": _auth.usmDESPrivProtocol,
    "3DES": _auth.usm3DESEDEPrivProtocol,
    "AES": _auth.usmAesCfb128Protocol,
    "AES128": _auth.usmAesCfb128Protocol,
    "AES192": _auth.usmAesCfb192Protocol,
    "AES256": _auth.usmAesCfb256Protocol,
    "AES192B": _auth.usmAesBlumenthalCfb192Protocol,
    "AES256B": _auth.usmAesBlumenthalCfb256Protocol,
    "NONE": _auth.usmNoPrivProtocol,
}


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


class SnmpAuthError(SnmpError):
    pass


def _resolve_secret(v: Optional[str]) -> Optional[str]:
    """Allow 'env:VAR' in config so secrets need not sit in the file."""
    if v and v.startswith("env:"):
        return os.environ.get(v[4:])
    return v


@dataclass
class Credential:
    kind: str = "v2c"  # v2c | v3
    label: str = ""
    community: Optional[str] = None
    user: Optional[str] = None
    auth: str = "NONE"
    auth_key: Optional[str] = None
    priv: str = "NONE"
    priv_key: Optional[str] = None
    context: str = ""
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        kind = d.get("kind", "v3" if d.get("user") else "v2c")
        return cls(
            kind=kind,
            label=d.get("label") or (f"v2c:{d.get('community', '')[:3]}***" if kind == "v2c" else f"v3:{d.get('user')}"),
            community=_resolve_secret(d.get("community")),
            user=d.get("user"),
            auth=(d.get("auth") or "NONE").upper(),
            auth_key=_resolve_secret(d.get("auth_key")),
            priv=(d.get("priv") or "NONE").upper(),
            priv_key=_resolve_secret(d.get("priv_key")),
            context=d.get("context", ""),
        )

    def auth_data(self, vlan: Optional[int] = None):
        if self.kind == "v2c":
            comm = self.community or ""
            if vlan is not None:
                comm = f"{comm}@{vlan}"  # Cisco community-string indexing
            return CommunityData(comm, mpModel=1)
        if self.kind == "v3":
            if self.auth not in AUTH_PROTOS:
                raise SnmpError(f"unknown auth protocol {self.auth}")
            if self.priv not in PRIV_PROTOS:
                raise SnmpError(f"unknown priv protocol {self.priv}")
            return UsmUserData(
                self.user,
                authKey=self.auth_key if self.auth != "NONE" else None,
                privKey=self.priv_key if self.priv != "NONE" else None,
                authProtocol=AUTH_PROTOS[self.auth],
                privProtocol=PRIV_PROTOS[self.priv],
            )
        raise SnmpError(f"unknown credential kind {self.kind}")

    def context_data(self, vlan: Optional[int] = None) -> ContextData:
        if self.kind == "v3" and vlan is not None:
            return ContextData(contextName=f"vlan-{vlan}")  # Cisco v3 per-VLAN context
        return ContextData(contextName=self.context or "")


def convert(v: Any) -> Any:
    """pysnmp value -> plain python (bytes/int/str/None)."""
    if v is None or isinstance(v, (NoSuchObject, NoSuchInstance, EndOfMibView, Null)):
        return None
    if isinstance(v, IpAddress):
        return v.prettyPrint()
    if isinstance(v, OctetString):
        return v.asOctets()
    if isinstance(v, ObjectIdentifier):
        return str(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


class SnmpSession:
    """One target + one credential. `get` and `walk` return plain python values keyed by dotted OID."""

    def __init__(
        self,
        engine: SnmpEngine,
        ip: str,
        cred: Credential,
        port: int = 161,
        timeout: float = 2.0,
        retries: int = 1,
        vlan: Optional[int] = None,
        max_repetitions: int = 25,
    ):
        self.engine = engine
        self.ip = ip
        self.cred = cred
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.vlan = vlan
        self.max_repetitions = max_repetitions
        self._target = None

    def with_vlan(self, vlan: int) -> "SnmpSession":
        return SnmpSession(self.engine, self.ip, self.cred, self.port, self.timeout, self.retries, vlan, self.max_repetitions)

    async def _tgt(self):
        if self._target is None:
            self._target = await UdpTransportTarget.create((self.ip, self.port), timeout=self.timeout, retries=self.retries)
        return self._target

    @staticmethod
    def _check(err_ind, err_stat, err_idx, var_binds):
        if err_ind:
            if isinstance(err_ind, errind.RequestTimedOut):
                raise SnmpTimeout(str(err_ind))
            if isinstance(err_ind, (errind.WrongDigest, errind.UnknownUserName, errind.UnsupportedSecurityLevel, errind.DecryptionError)):
                raise SnmpAuthError(str(err_ind))
            raise SnmpError(str(err_ind))
        if err_stat:
            raise SnmpError(f"{err_stat.prettyPrint()} at {err_idx}")

    async def get(self, *oids: str) -> dict[str, Any]:
        tgt = await self._tgt()
        res = await get_cmd(
            self.engine,
            self.cred.auth_data(self.vlan),
            tgt,
            self.cred.context_data(self.vlan),
            *[ObjectType(ObjectIdentity(o)) for o in oids],
            lookupMib=False,
        )
        self._check(*res)
        return {str(name): convert(val) for name, val in res[3]}

    async def walk(self, base: str) -> list[tuple[str, Any]]:
        """Bulk-walk a subtree. Returns [(oid, value)] in lexicographic order, limited to the subtree."""
        tgt = await self._tgt()
        out: list[tuple[str, Any]] = []
        gen = bulk_walk_cmd(
            self.engine,
            self.cred.auth_data(self.vlan),
            tgt,
            self.cred.context_data(self.vlan),
            0,
            self.max_repetitions,
            ObjectType(ObjectIdentity(base)),
            lexicographicMode=False,
            lookupMib=False,
            ignoreNonIncreasingOid=True,
        )
        async for err_ind, err_stat, err_idx, var_binds in gen:
            self._check(err_ind, err_stat, err_idx, var_binds)
            for name, val in var_binds:
                s = str(name)
                if not s.startswith(base + "."):
                    continue
                cv = convert(val)
                if cv is None and isinstance(val, EndOfMibView):
                    continue
                out.append((s, cv))
        return out

    async def walk_map(self, base: str) -> dict[str, Any]:
        """Walk and key by the index suffix (string after base)."""
        return {oid[len(base) + 1 :]: v for oid, v in await self.walk(base)}


async def probe(engine: SnmpEngine, ip: str, creds: list[Credential], timeout: float, retries: int, port: int = 161) -> tuple[Optional[SnmpSession], Optional[dict]]:
    """Try credentials in order; return (session, system-group dict) for the first that answers."""
    from . import oids as O

    for cred in creds:
        sess = SnmpSession(engine, ip, cred, port=port, timeout=timeout, retries=retries)
        try:
            sysinfo = await sess.get(O.SYS_DESCR, O.SYS_OBJECTID, O.SYS_NAME, O.SYS_SERVICES)
            if sysinfo.get(O.SYS_DESCR) is None and sysinfo.get(O.SYS_OBJECTID) is None:
                continue
            return sess, sysinfo
        except SnmpTimeout:
            # For v2c a wrong community is indistinguishable from a timeout; keep trying.
            continue
        except SnmpAuthError as e:
            log.debug("%s: auth failed with %s: %s", ip, cred.label, e)
            continue
        except SnmpError as e:
            log.debug("%s: %s with %s", ip, e, cred.label)
            continue
        except Exception as e:  # noqa: BLE001 - pysnmp raises raw errors for e.g. missing crypto backends
            log.warning("%s: %s failed: %s: %s", ip, cred.label, type(e).__name__, str(e)[:200])
            continue
    return None, None
