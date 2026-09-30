"""Shared fixtures: snmpsim agents serving the lab on loopback, for tests that need real SNMP."""
import asyncio
import os
import shutil
import subprocess
import sys
import time

import pytest

from . import labnet

PORT = 11161


def _responder():
    here = os.path.dirname(sys.executable)
    for name in ("snmpsim-command-responder", "snmpsim-command-responder.exe"):
        for d in (here, os.path.join(here, "Scripts")):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    return shutil.which("snmpsim-command-responder")


RESPONDER = _responder()


def _wait_agent(ip, cred_args, timeout=20):
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

    from netmap import oids as O
    from netmap.snmp import Credential, SnmpSession

    async def one():
        eng = SnmpEngine()
        try:
            r = await SnmpSession(eng, ip, Credential.from_dict(cred_args), port=PORT, timeout=1, retries=0).get(O.SYS_NAME)
            return r.get(O.SYS_NAME)
        finally:
            eng.close_dispatcher()

    end = time.time() + timeout
    while time.time() < end:
        try:
            if asyncio.run(one()):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


@pytest.fixture(scope="session")
def agents(tmp_path_factory):
    """One snmpsim responder per lab device, bound to its 127.x address, for the whole session."""
    if not RESPONDER:
        pytest.skip("snmpsim not installed")
    lab = labnet.build("127")
    procs = []
    root = tmp_path_factory.mktemp("snmpsim")
    for ip, dev in lab.items():
        d = root / ip.replace(".", "_")
        d.mkdir()
        (d / "lab.snmprec").write_text(dev.snmprec())
        cmd = [
            RESPONDER, f"--data-dir={d}", f"--agent-udpv4-endpoint={ip}:{PORT}", "--logging-method=null",
            "--v3-user=netmap", "--v3-auth-key=authpass123", "--v3-auth-proto=SHA", "--v3-priv-key=privpass123", "--v3-priv-proto=AES",
        ]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    ok = all(_wait_agent(ip, {"kind": "v2c", "community": "lab"}) for ip in lab)
    if not ok:
        for p in procs:
            p.kill()
        pytest.skip("snmpsim agents did not come up on loopback")
    yield lab
    for p in procs:
        p.kill()
        p.wait()
