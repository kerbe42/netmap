"""Regenerate the sample project shipped with the desktop app (Help > Explore the sample network).

    python tools/make_sample.py                 # -> subnetsleuth/data/sample-campus.sleuth
    python tools/make_sample.py path/to/out.sleuth

The sample is the simulated campus in tests/demonet.py (11 network devices, ~500 endpoints,
with the untidiness real networks have). It is generated, not hand-edited, so this script is
the single source of truth for it: run it after changing demonet.py or the project format,
and commit the result. CI runs it before building the desktop app so the bundled sample
always matches the code that reads it.

Exit status 1 when the freshly generated file differs from the one on disk and --check is
given (for CI: "the tracked sample is stale").
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from subnetsleuth.model import FORMAT_VERSION, Inventory  # noqa: E402
from tests import demonet  # noqa: E402

DEFAULT = os.path.join(ROOT, "subnetsleuth", "data", "sample-campus.sleuth")


def main(argv: list[str]) -> int:
    check = "--check" in argv
    args = [a for a in argv if a != "--check"]
    out = args[0] if args else DEFAULT
    if check:
        import tempfile

        fd, tmp = tempfile.mkstemp(suffix=".sleuth")
        os.close(fd)
        try:
            demonet.build_project(tmp)
            fresh = Inventory.load(tmp)
        finally:
            os.unlink(tmp)
        if not os.path.exists(out):
            print(f"{out}: missing (run tools/make_sample.py)")
            return 1
        current = Inventory.load(out)
        same = fresh.summary() == current.summary() and current.meta.get("version") == FORMAT_VERSION
        print(f"{out}: {'up to date' if same else 'STALE - run tools/make_sample.py'} ({current.summary()})")
        return 0 if same else 1
    inv = demonet.build_project(out)
    print(f"{out}: {inv.summary()} (format version {FORMAT_VERSION}, {os.path.getsize(out):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
