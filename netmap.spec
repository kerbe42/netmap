# PyInstaller spec: build a single-file `netmap` / `netmap.exe`.
#   pyinstaller netmap.spec
# The same spec is used on Linux (produces `dist/netmap`) and on the Windows CI
# runner (produces `dist/netmap.exe`). pysnmp, pyasn1 and cryptography all lean on
# dynamic imports, so we pull them in wholesale rather than trust auto-detection.
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [
    ("netmap/vendor/vis-network.min.js", "netmap/vendor"),
    ("netmap/data/oui.tsv", "netmap/data"),  # offline MAC -> vendor, so typing works with no internet
]
binaries = []
hiddenimports = ["netmap"]

# Whole packages that PyInstaller's static analysis misses pieces of.
for pkg in ("pysnmp", "pyasn1", "pyasn1_modules", "networkx", "openpyxl", "et_xmlfile", "paramiko", "nacl", "bcrypt", "winrm", "requests", "requests_ntlm", "ntlm_auth", "xmltodict", "pyVmomi", "pyVim"):
    try:
        d, b, h = collect_all(pkg)
    except Exception:  # an optional sub-dependency may be absent; skip it rather than fail the build
        continue
    datas += d
    binaries += b
    hiddenimports += h

# cryptography backs SNMPv3 auth/priv; its provider modules load dynamically.
hiddenimports += collect_submodules("cryptography")

a = Analysis(
    ["packaging/entry.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "pytest", "snmpsim", "pysmi", "IPython"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="netmap",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
