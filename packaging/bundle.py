"""What goes into a frozen NetMap build - shared by netmap.spec and packaging/netmap-gui.spec.

Both PyInstaller specs used to carry their own copies of these lists and drifted apart
(the EoL table shipped in neither). Keep every bundled data file, wholesale-collected
package and exclusion here, and let tests/test_packaging.py check the lists against the
files actually on disk and the wheel's package-data globs.

A spec loads this module by path (PyInstaller runs specs with their own directory, not
the repository root, on sys.path):

    import importlib.util, os
    _spec = importlib.util.spec_from_file_location("bundle", os.path.join(<packaging dir>, "bundle.py"))
    bundle = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(bundle)
"""
from __future__ import annotations

import os

# Data files inside the netmap package, as paths relative to netmap/. Every file under
# netmap/data and netmap/vendor must be listed here (test_packaging enforces it).
SAMPLE_PROJECT = "data/sample-campus.netmap"
DATA_FILES = [
    "vendor/vis-network.min.js",  # the interactive HTML map
    "data/oui.tsv",  # offline MAC -> vendor, so typing works with no internet
    "data/eol.json",  # offline hardware end-of-sale / end-of-support table
    SAMPLE_PROJECT,  # Help > Explore the sample network (desktop app only)
]

# Whole packages that PyInstaller's static analysis misses pieces of (dynamic imports).
COLLECT_PACKAGES = [
    "pysnmp", "pyasn1", "pyasn1_modules", "networkx", "openpyxl", "et_xmlfile", "paramiko", "nacl", "bcrypt",
    "winrm", "requests", "requests_ntlm", "ntlm_auth", "xmltodict", "pyVmomi", "pyVim",
]

# cryptography backs SNMPv3 auth/priv and paramiko; its provider modules load dynamically.
SUBMODULE_PACKAGES = ["cryptography"]

HIDDEN_IMPORTS = ["netmap"]

# Never wanted in a frozen build: test tooling, notebooks, and heavy libraries nothing imports.
EXCLUDES = ["tkinter", "matplotlib", "pytest", "snmpsim", "pysmi", "IPython", "numpy", "scipy", "pandas"]

# Qt modules the desktop app never touches (the GUI spec adds these to EXCLUDES).
QT_EXCLUDES = ["PySide6.QtNetwork", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtOpenGL", "PySide6.QtPdf", "PySide6.QtDBus"]


def data_files(root: str, *, with_sample: bool) -> list[tuple[str, str]]:
    """PyInstaller `datas` entries for the package data files.

    The single-file command line leaves the 1.5 MB sample project out (nothing on the
    command line opens it); the desktop app needs it for Help > Explore the sample network.
    """
    out = []
    for rel in DATA_FILES:
        if rel == SAMPLE_PROJECT and not with_sample:
            continue
        src = os.path.join(root, "netmap", *rel.split("/"))
        if not os.path.exists(src):
            raise FileNotFoundError(f"bundled data file missing: {src}")
        out.append((src, "netmap/" + os.path.dirname(rel)))
    return out


def collect(root: str, *, with_sample: bool) -> tuple[list, list, list]:
    """(datas, binaries, hiddenimports) for an Analysis(): data files plus the packages above."""
    from PyInstaller.utils.hooks import collect_all, collect_submodules

    datas = data_files(root, with_sample=with_sample)
    binaries: list = []
    hiddenimports = list(HIDDEN_IMPORTS)
    for pkg in COLLECT_PACKAGES:
        try:
            d, b, h = collect_all(pkg)
        except Exception:  # an optional sub-dependency may be absent; skip it rather than fail the build
            continue
        datas += d
        binaries += b
        hiddenimports += h
    for pkg in SUBMODULE_PACKAGES:
        hiddenimports += collect_submodules(pkg)
    return datas, binaries, hiddenimports
