"""Shared fixtures: snmpsim agents serving the lab on loopback, for tests that need real SNMP.

The agents are `snmpsim-command-responder` processes (the full responder: the lite one has
no SNMPv3), one per lab device, each bound to its own 127.x address on one UDP port chosen
free at start-up (tests import PORT from here). Locally, a missing snmpsim or agents that
never answer skip the dependent tests; on CI (the `CI` environment variable is set) that is
a failure, with each responder's stderr in the report, so a broken simulator can no longer
hide as "5 skipped".
"""
import asyncio
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from . import labnet

ON_CI = bool(os.environ.get("CI"))


def _free_udp_port() -> int:
    """A UDP port nobody is listening on right now (the agents bind it on 127.0.0.1, 127.0.0.2, 127.1.0.2)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


PORT = int(os.environ.get("SUBNETSLEUTH_TEST_SNMP_PORT") or _free_udp_port())


def _responder():
    here = os.path.dirname(sys.executable)
    for name in ("snmpsim-command-responder", "snmpsim-command-responder.exe"):
        for d in (here, os.path.join(here, "Scripts")):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    return shutil.which("snmpsim-command-responder")


RESPONDER = _responder()


def _probe(ip, cred_args) -> bool:
    """One SNMP GET of sysName against an agent; True when it answered."""
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

    from subnetsleuth import oids as O
    from subnetsleuth.snmp import Credential, SnmpSession

    async def one():
        eng = SnmpEngine()
        try:
            r = await SnmpSession(eng, ip, Credential.from_dict(cred_args), port=PORT, timeout=1, retries=0).get(O.SYS_NAME)
            return bool(r.get(O.SYS_NAME))
        finally:
            eng.close_dispatcher()

    try:
        return asyncio.run(one())
    except Exception:
        return False


def _tail(path, n=40) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return "(no stderr captured)"
    return "\n".join(lines[-n:]) if lines else "(stderr empty)"


@pytest.fixture(scope="session")
def agents(tmp_path_factory):
    """One snmpsim responder per lab device, bound to its 127.x address, for the whole session."""
    if not RESPONDER:
        (pytest.fail if ON_CI else pytest.skip)("snmpsim-command-responder not found beside %s or on PATH" % sys.executable)
    lab = labnet.build("127")
    root = tmp_path_factory.mktemp("snmpsim")
    procs: dict[str, subprocess.Popen] = {}
    logs: dict[str, str] = {}
    # Never let a root CI container trip snmpsim's "must drop privileges" refusal.
    env = {**os.environ, "SNMPSIM_ALLOW_ROOT": "true"}
    for ip, dev in lab.items():
        d = root / ip.replace(".", "_")
        d.mkdir()
        (d / "lab.snmprec").write_text(dev.snmprec())
        (d / "cache").mkdir()  # per-agent cache dir: three responders racing to create one shared %TEMP%/snmpsim is a start-up failure
        (d / "variation").mkdir()  # empty: the stock sql/redis variation modules only log load errors
        logs[ip] = str(root / f"{ip}.stderr.log")
        cmd = [
            RESPONDER, f"--data-dir={d}", f"--cache-dir={d / 'cache'}", f"--variation-modules-dir={d / 'variation'}",
            f"--agent-udpv4-endpoint={ip}:{PORT}",
            "--logging-method=stderr", "--log-level=error",
            "--v3-user=subnetsleuth", "--v3-auth-key=authpass123", "--v3-auth-proto=SHA", "--v3-priv-key=privpass123", "--v3-priv-proto=AES",
        ]
        with open(logs[ip], "wb") as err:
            procs[ip] = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err, env=env)

    # Readiness: poll every agent until all answer, and stop early if any responder has exited.
    pending = set(lab)
    started = time.time()
    deadline = started + (120 if ON_CI else 60)
    exited: dict[str, int] = {}
    while pending and time.time() < deadline:
        for ip, p in procs.items():
            rc = p.poll()
            if rc is not None:
                exited[ip] = rc
        if exited:
            break
        for ip in sorted(pending):
            if _probe(ip, {"kind": "v2c", "community": "lab"}):
                pending.discard(ip)
        if pending:
            time.sleep(0.5)

    if pending:
        for p in procs.values():
            p.kill()
            p.wait()
        try:
            from importlib.metadata import version

            ver = version("snmpsim")
        except Exception:  # noqa: BLE001
            ver = "?"
        report = [
            f"snmpsim agents did not come up on loopback after {time.time() - started:.0f}s "
            f"(responder {RESPONDER}, snmpsim {ver}, UDP port {PORT}, python {sys.version.split()[0]})",
            f"never answered: {sorted(pending)}; exited early: {exited or 'none'}",
        ]
        for ip in lab:
            report.append(f"--- {ip} stderr ({logs[ip]}):\n{_tail(logs[ip])}")
        msg = "\n".join(report)
        print(msg, file=sys.stderr)
        (pytest.fail if ON_CI else pytest.skip)(msg)
    yield lab
    for p in procs.values():
        p.kill()
        p.wait()
