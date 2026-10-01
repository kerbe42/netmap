"""Hardware end-of-sale / end-of-support lookup - fully offline, best-effort.

When someone inherits a network they did not build, the first question after "what is
on it?" is usually "how much of it is past support?". This flags devices whose hardware
platform has a published end-of-sale (EoS) or end-of-support (EoL) milestone.

It is deliberately self-contained: the lookup table lives in `data/eol.json` (bundled the
same way as the IEEE OUI table) and there are no network calls, so it works on an air-
gapped assessment laptop and in the frozen PyInstaller build alike.

The bundled dates are hand-curated from vendors' public end-of-life notices for well-known
enterprise platforms (Cisco Catalyst / Nexus / ISR / ASR / Small Business, HPE/Aruba
ProCurve, Fortinet FortiGate, Juniper EX, Dell PowerConnect, Netgear and a few common
access points). Many are approximate and some SKUs are only matched by family, so every
result is best-effort: always verify a milestone against the vendor's own EoL notice for
the exact part number before acting on it. Records with an approximate or uncertain date
carry a caveat in their "note" field.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime

from . import util

_RECORDS: list[dict] | None = None


def _load() -> list[dict]:
    """Load and cache the EoL table, compiling each record's regex once.

    A malformed record (bad JSON shape or an uncompilable regex) is skipped rather than
    fatal: a typo in the data file must never take the whole tool down.
    """
    global _RECORDS
    if _RECORDS is None:
        recs: list[dict] = []
        try:
            with open(util.resource_path("data", "eol.json"), encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            raw = []
        for r in raw if isinstance(raw, list) else []:
            if not isinstance(r, dict) or not r.get("match"):
                continue
            try:
                rx = re.compile(r["match"], re.I)
            except re.error:
                continue
            rec = dict(r)
            rec["_rx"] = rx
            recs.append(rec)
        _RECORDS = recs
    return _RECORDS


def _parse_date(s) -> date | None:
    """A YYYY-MM-DD string as a date, or None for anything empty/malformed."""
    if not s or not isinstance(s, str):
        return None
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _vendor_agrees(rec_vendor: str, vendor: str) -> bool:
    """Loose vendor check: only rules out a match when both sides name a vendor and they
    plainly disagree. HP/HPE/Aruba are treated as one, as are Cisco's sub-brands."""
    rv = (rec_vendor or "").strip().lower()
    dv = (vendor or "").strip().lower()
    if not rv or not dv:
        return True
    if rv in dv or dv in rv:
        return True
    aliases = [
        {"hp", "hpe", "hewlett", "hewlett-packard", "aruba", "procurve"},
        {"cisco", "cisco systems", "meraki", "aironet"},
        {"dell", "dell emc", "force10"},
    ]
    for group in aliases:
        if any(a in rv for a in group) and any(a in dv for a in group):
            return True
    return False


def eol_status(vendor: str, model: str, sysdescr: str = "", today=None) -> dict | None:
    """Best-effort end-of-life status for a hardware platform, or None if unrecognised.

    The record whose `match` regex hits the model or sysDescr is chosen; when several hit,
    the one with the longest (most specific) `match` pattern wins. A record that names a
    vendor is skipped when the device's vendor plainly disagrees.

    Returns a dict with the matched record's family/eos/eol/note/match plus a computed
    `status` (active | end-of-sale | end-of-support | unknown) and, when the EoL date is
    known, `days_to_eol` (negative once past). Bad or missing dates never raise.
    """
    model = (model or "").strip()
    sysdescr = (sysdescr or "").strip()
    hay = [h for h in (model, sysdescr) if h]
    if not hay:
        return None

    best = None
    best_len = -1
    for rec in _load():
        if not _vendor_agrees(rec.get("vendor", ""), vendor):
            continue
        if not any(rec["_rx"].search(h) for h in hay):
            continue
        mlen = len(rec.get("match", ""))
        if mlen > best_len:
            best, best_len = rec, mlen
    if best is None:
        return None

    if today is None:
        today = date.today()
    eos = _parse_date(best.get("eos"))
    eol = _parse_date(best.get("eol"))

    if eol and today >= eol:
        status = "end-of-support"
    elif eos and today >= eos:
        status = "end-of-sale"
    elif eos or eol:
        status = "active"
    else:
        status = "unknown"

    out = {
        "family": best.get("family", ""),
        "eos": best.get("eos", ""),
        "eol": best.get("eol", ""),
        "note": best.get("note", ""),
        "match": best.get("match", ""),
        "status": status,
    }
    if eol:
        out["days_to_eol"] = (eol - today).days
    return out


def annotate_device(dev) -> dict | None:
    """Convenience wrapper: EoL status for a `model.Device`, or None if unrecognised."""
    return eol_status(
        getattr(dev, "vendor", "") or "",
        getattr(dev, "model", "") or "",
        getattr(dev, "sysdescr", "") or "",
    )
