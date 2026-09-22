"""In-memory stand-in for netmap.snmp.SnmpSession / probe."""
from __future__ import annotations

from netmap import oids as O
from netmap.snmp import Credential


class FakeSession:
    def __init__(self, ip: str, table: dict, cred=None, vlan=None):
        self.ip = ip
        self.table = table
        self.cred = cred or Credential(kind="v2c", community="lab", label="lab")
        self.vlan = vlan
        self.calls = 0

    def with_vlan(self, vlan):
        return FakeSession(self.ip, self.table, self.cred, vlan)

    async def get(self, *oids):
        self.calls += 1
        return {o: self.table.get(o) for o in oids}

    async def walk(self, base):
        self.calls += 1
        pfx = base + "."
        keys = sorted((k for k in self.table if k.startswith(pfx)), key=lambda k: tuple(int(x) for x in k.split(".")))
        return [(k, self.table[k]) for k in keys]

    async def walk_map(self, base):
        return {oid[len(base) + 1 :]: v for oid, v in await self.walk(base)}


def make_prober(devices: dict[str, dict]):
    """devices: ip -> OID table. Anything else times out (returns None)."""
    probed = []

    async def prober(engine, ip, creds, timeout, retries, port=161):
        probed.append(ip)
        t = devices.get(ip)
        if t is None:
            return None, None
        s = FakeSession(ip, t, creds[0])
        return s, await s.get(O.SYS_DESCR, O.SYS_OBJECTID, O.SYS_NAME, O.SYS_SERVICES)

    prober.probed = probed
    return prober
