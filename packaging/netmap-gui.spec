# PyInstaller spec for the desktop app: a folder holding NetMap.exe (windowed) and
# netmap-cli.exe (the command line), sharing one copy of Python and the libraries.
# (Not "netmap.exe": Windows file names ignore case, so it would collide with NetMap.exe.)
#   pyinstaller packaging/netmap-gui.spec --noconfirm      ->  dist/NetMap/
# A folder rather than one file: it starts instantly (nothing to unpack to %TEMP% on
# every launch), endpoint protection is calmer about it, and the installer and the
# portable zip are both made from it.
#
# What is bundled (data files, collected packages, exclusions) lives in packaging/bundle.py,
# shared with netmap.spec.
import importlib.util
import os
import re

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
_spec = importlib.util.spec_from_file_location("bundle", os.path.join(SPECPATH, "bundle.py"))
bundle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bundle)

VERSION = re.search(r'__version__ = "([^"]+)"', open(os.path.join(ROOT, "netmap", "__init__.py"), encoding="utf-8").read()).group(1)
nums = [int(x) for x in re.findall(r"\d+", VERSION)[:3]] + [0]

# Windows version resource: what Explorer shows under Properties > Details.
version_file = os.path.join(SPECPATH, "version_info.txt")
with open(version_file, "w", encoding="utf-8") as f:
    f.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({nums[0]}, {nums[1]}, {nums[2]}, 0), prodvers=({nums[0]}, {nums[1]}, {nums[2]}, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'kerbe42'),
      StringStruct('FileDescription', 'NetMap - network inventory and topology'),
      StringStruct('FileVersion', '{VERSION}'),
      StringStruct('InternalName', 'NetMap'),
      StringStruct('LegalCopyright', 'Copyright (c) 2026 kerbe42. MIT License.'),
      StringStruct('OriginalFilename', 'NetMap.exe'),
      StringStruct('ProductName', 'NetMap'),
      StringStruct('ProductVersion', '{VERSION}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""")

datas, binaries, hiddenimports = bundle.collect(ROOT, with_sample=True)
hiddenimports += ["netmap.gui", "netmap.gui.app"]
EXCLUDES = bundle.EXCLUDES + bundle.QT_EXCLUDES

gui = Analysis(
    [os.path.join(SPECPATH, "gui_entry.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports + ["PySide6.QtSvg", "PySide6.QtPrintSupport"],
    excludes=EXCLUDES,
    noarchive=False,
)
cli = Analysis(
    [os.path.join(SPECPATH, "entry.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=EXCLUDES + ["PySide6", "shiboken6"],
    noarchive=False,
)

# Qt pieces the app never uses. opengl32sw.dll alone is 20 MB (a software OpenGL fallback;
# the map is drawn by the raster engine), and Qt's own translations only localise its stock
# dialogs. The frozen build's --selftest in CI proves nothing needed went with them.
DROP = ("opengl32sw", "d3dcompiler_47", "qt6quick", "qt6qml", "qt6pdf", "qt6virtualkeyboard", "qt6webengine")
gui.binaries = [b for b in gui.binaries if not any(x in os.path.basename(b[0]).lower() for x in DROP)]
gui.datas = [d for d in gui.datas if "/translations/" not in d[0].replace("\\", "/") + "/"]

gui_exe = EXE(
    PYZ(gui.pure),
    gui.scripts,
    [],
    exclude_binaries=True,
    name="NetMap",
    icon=os.path.join(SPECPATH, "netmap.ico"),
    version=version_file,
    console=False,
    upx=False,
)
cli_exe = EXE(
    PYZ(cli.pure),
    cli.scripts,
    [],
    exclude_binaries=True,
    name="netmap-cli",
    icon=os.path.join(SPECPATH, "netmap.ico"),
    version=version_file,
    console=True,
    upx=False,
)
COLLECT(
    gui_exe,
    gui.binaries,
    gui.datas,
    cli_exe,
    cli.binaries,
    cli.datas,
    name="NetMap",
    upx=False,
)
