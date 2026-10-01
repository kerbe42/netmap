"""Desktop app entry point (`subnetsleuth-gui`, `SubnetSleuth.exe`)."""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import sys


def data_dir() -> str:
    """Per-user folder for logs (and settings in portable mode: beside the exe)."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        path = os.path.join(base, "SubnetSleuth")
    else:
        path = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "subnetsleuth")
    os.makedirs(path, exist_ok=True)
    return path


def migrate_netmap_settings() -> int:
    """First run after the rename: copy NetMap's settings (window layout, preferences, saved
    SNMP credentials, recent files) to SubnetSleuth's, unless it already has its own. The old
    settings are left in place. Returns how many values were copied."""
    from PySide6.QtCore import QSettings

    new = QSettings()
    if new.allKeys():
        return 0
    old = QSettings("netmap", "NetMap")  # the organisation/application names before the rename
    keys = old.allKeys()
    for k in keys:
        new.setValue(k, old.value(k))
    if keys:
        new.setValue("migrated_from", "NetMap")
        new.sync()
    return len(keys)


def _fix_streams() -> None:
    # A windowed (no console) Windows build has no stdout/stderr at all: anything that
    # prints - a library warning, a stray traceback - would raise. Give them a sink.
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def _setup_logging(verbose: bool) -> str:
    path = os.path.join(data_dir(), "subnetsleuth.log")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(name)s: %(message)s"))
    root.addHandler(fh)
    logging.getLogger("pysnmp").setLevel(logging.WARNING)
    return path


def headless_run(args) -> bool:
    return bool(args.selftest or args.screenshots)


def main(argv=None) -> int:
    _fix_streams()
    ap = argparse.ArgumentParser(prog="subnetsleuth-gui", description="SubnetSleuth desktop app")
    ap.add_argument("project", nargs="?", help="project (.sleuth / .json) to open")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--screenshots", metavar="DIR", help="render every page of the project to PNG files in DIR and exit (for docs and CI)")
    ap.add_argument("--selftest", action="store_true", help="open the project, exercise every page and export, exit 0 on success")
    ap.add_argument("--theme", choices=["system", "light", "dark"], help="override the saved theme")
    args = ap.parse_args(argv)
    log_path = _setup_logging(args.verbose)

    from PySide6.QtCore import QCoreApplication, QSettings, Qt, QTimer
    from PySide6.QtWidgets import QApplication

    from .. import __version__

    QCoreApplication.setOrganizationName("subnetsleuth")
    QCoreApplication.setApplicationName("SubnetSleuth")
    QCoreApplication.setApplicationVersion(__version__)
    if args.selftest or args.screenshots:
        # never touch the user's real settings (window layout, credentials, recent files)
        import tempfile

        QSettings.setDefaultFormat(QSettings.IniFormat)
        QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, tempfile.mkdtemp(prefix="subnetsleuth-selftest-settings-"))
    here = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else __file__)
    portable_ini = os.path.join(here, "subnetsleuth-portable.ini")
    if not os.path.exists(portable_ini) and os.path.exists(os.path.join(here, "netmap-portable.ini")):
        portable_ini = os.path.join(here, "netmap-portable.ini")  # a portable folder from before the rename
    if os.path.exists(portable_ini) and not (args.selftest or args.screenshots):
        # portable mode: settings live beside the executable, nothing in the registry
        QSettings.setDefaultFormat(QSettings.IniFormat)
        QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, os.path.dirname(portable_ini))
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationDisplayName("SubnetSleuth")
    if not headless_run(args):
        n = migrate_netmap_settings()
        if n:
            logging.getLogger("subnetsleuth.gui").info("copied %d setting(s) from NetMap", n)

    from .icons import app_icon
    from .mainwindow import MainWindow
    from .theme import apply_theme

    app.setWindowIcon(app_icon())
    apply_theme(app, args.theme or QSettings().value("ui/theme", "system"))
    headless = bool(args.screenshots or args.selftest)
    # the recovery copy lives beside the log; a self-test must never touch (or clear) a real one
    win = MainWindow(log_path=log_path, recovery_dir="" if headless else None)
    if args.project:
        win.open_project(args.project)
    if headless:
        from .selftest import run_selftest

        return run_selftest(win, args.screenshots, args.selftest)
    win.show()
    if not args.project or not win.inv.devices:
        win.offer_recovery()
    else:
        QTimer.singleShot(300, win.offer_recovery)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
