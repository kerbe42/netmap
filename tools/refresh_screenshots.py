"""Refresh docs/screenshots/*.png (the eight images the README shows) from the app's self-test.

    python tools/refresh_screenshots.py                       # run the app from source, offscreen
    python tools/refresh_screenshots.py --exe dist\\NetMap\\NetMap.exe   # use a frozen build (Windows: real desktop)
    python tools/refresh_screenshots.py --from shots-native   # copy from an existing self-test folder
                                                              # (e.g. the netmap-desktop-screenshots CI artifact)

The self-test (`NetMap --selftest --screenshots DIR project.netmap`) writes one PNG per screen
with a numbered name; the README references stable names. The mapping below is the single
place that ties the two together - keep it in step with netmap/gui/selftest.py.

The pictures in the repository are taken on the Windows CI runner (native desktop, dark
theme, 1920x1080) so they look like the shipped app; a Linux offscreen run is fine for
checking layout but will not match the Windows widget style. Typical release flow: download
the `netmap-desktop-screenshots` artifact of the tag build, unzip, then
`python tools/refresh_screenshots.py --from <unzipped>/shots-native` and commit.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs", "screenshots")
SAMPLE = os.path.join(ROOT, "netmap", "data", "sample-campus.netmap")

# README image  <-  self-test screenshot (see shot(...) calls in netmap/gui/selftest.py)
MAPPING = {
    "overview.png": "01-overview.png",  # the Overview page, right after opening the project
    "map-physical.png": "30-map-physical.png",  # Topology map, Physical preset
    "map-logical.png": "30-map-logical.png",  # Topology map, Logical preset
    "map-hosts.png": "33-map-physical-hosts.png",  # Physical map with the Hosts toggle on
    "device.png": "20-device-details.png",  # Devices list with a device's details panel (Overview tab)
    "subnet.png": "22-subnet-ipmap.png",  # Subnets list with a subnet's IP address map
    "findings.png": "11-findings.png",  # Needs attention page
    "dark.png": "51-overview-dark.png",  # Overview after View > Theme > Dark
}


def run_selftest(out_dir: str, exe: str | None, theme: str | None) -> None:
    if exe:
        cmd = [exe]
    else:
        cmd = [sys.executable, "-m", "netmap.gui.app"]
    cmd += ["--selftest", "--screenshots", out_dir]
    if theme:
        cmd += ["--theme", theme]
    cmd.append(SAMPLE)
    env = dict(os.environ)
    if not exe and not env.get("QT_QPA_PLATFORM") and sys.platform != "win32":
        env["QT_QPA_PLATFORM"] = "offscreen"
    print("running:", " ".join(cmd))
    r = subprocess.run(cmd, cwd=ROOT, env=env)
    if r.returncode != 0:
        sys.exit(f"self-test failed with exit code {r.returncode}")


def copy_mapped(src_dir: str, check_only: bool) -> int:
    missing = [s for s in MAPPING.values() if not os.path.exists(os.path.join(src_dir, s))]
    if missing:
        sys.exit(f"{src_dir} lacks {missing}; is it a --screenshots folder of a full self-test run?")
    changed = 0
    for readme_name, shot in MAPPING.items():
        src = os.path.join(src_dir, shot)
        dst = os.path.join(DOCS, readme_name)
        same = os.path.exists(dst) and open(src, "rb").read() == open(dst, "rb").read()
        print(f"{'same     ' if same else 'update   '} {readme_name:18} <- {shot}  ({os.path.getsize(src):,} bytes)")
        if not same:
            changed += 1
            if not check_only:
                os.makedirs(DOCS, exist_ok=True)
                shutil.copyfile(src, dst)
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--exe", help="frozen NetMap.exe / NetMap binary to run instead of the source tree")
    ap.add_argument("--from", dest="src", help="existing --screenshots folder to copy from (skips running the app)")
    ap.add_argument("--theme", choices=["system", "light", "dark"], default="dark", help="theme for the run (default dark, as in the README)")
    ap.add_argument("--check", action="store_true", help="report which images would change; write nothing")
    args = ap.parse_args()
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    unreferenced = [n for n in MAPPING if f"docs/screenshots/{n}" not in readme]
    if unreferenced:
        print("warning: README does not reference", unreferenced)
    if args.src:
        changed = copy_mapped(args.src, args.check)
    else:
        with tempfile.TemporaryDirectory(prefix="netmap-shots-") as tmp:
            run_selftest(tmp, args.exe, args.theme)
            changed = copy_mapped(tmp, args.check)
    print(f"{changed} image(s) {'would change' if args.check else 'updated'} in {DOCS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
