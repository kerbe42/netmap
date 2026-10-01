# PyInstaller spec: build a single-file `subnetsleuth` / `subnetsleuth.exe`.
#   pyinstaller subnetsleuth.spec --noconfirm
# The same spec is used on Linux (produces `dist/subnetsleuth`) and on the Windows CI
# runner (produces `dist/subnetsleuth.exe`). What is bundled - data files, wholesale-collected
# packages, exclusions - is defined once in packaging/bundle.py and shared with the
# desktop-app spec, so the two cannot drift apart again.
import importlib.util
import os

ROOT = os.path.abspath(SPECPATH)
_spec = importlib.util.spec_from_file_location("bundle", os.path.join(ROOT, "packaging", "bundle.py"))
bundle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bundle)

datas, binaries, hiddenimports = bundle.collect(ROOT, with_sample=False)

a = Analysis(
    [os.path.join(ROOT, "packaging", "entry.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=bundle.EXCLUDES,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="subnetsleuth",
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
