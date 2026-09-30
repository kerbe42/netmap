"""Desktop app entry point (`netmap-gui`, `NetMap.exe`)."""
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
        path = os.path.join(base, "NetMap")
    else:
        path = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "netmap")
    os.makedirs(path, exist_ok=True)
    return path


def _fix_streams() -> None:
    # A windowed (no console) Windows build has no stdout/stderr at all: anything that
    # prints - a library warning, a stray traceback - would raise. Give them a sink.
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def _setup_logging(verbose: bool) -> str:
    path = os.path.join(data_dir(), "netmap.log")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(name)s: %(message)s"))
    root.addHandler(fh)
    logging.getLogger("pysnmp").setLevel(logging.WARNING)
    return path


def main(argv=None) -> int:
    _fix_streams()
    ap = argparse.ArgumentParser(prog="netmap-gui", description="NetMap desktop app")
    ap.add_argument("project", nargs="?", help="project (.netmap / .json) to open")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--screenshots", metavar="DIR", help="render every page of the project to PNG files in DIR and exit (for docs and CI)")
    ap.add_argument("--selftest", action="store_true", help="open the project, exercise every page and export, exit 0 on success")
    ap.add_argument("--theme", choices=["system", "light", "dark"], help="override the saved theme")
    args = ap.parse_args(argv)
    log_path = _setup_logging(args.verbose)

    from PySide6.QtCore import QCoreApplication, QSettings, Qt
    from PySide6.QtWidgets import QApplication

    from .. import __version__

    QCoreApplication.setOrganizationName("netmap")
    QCoreApplication.setApplicationName("NetMap")
    QCoreApplication.setApplicationVersion(__version__)
    portable_ini = os.path.join(os.path.dirname(sys.executable if getattr(sys, "frozen", False) else __file__), "netmap-portable.ini")
    if os.path.exists(portable_ini):
        # portable mode: settings live beside the executable, nothing in the registry
        QSettings.setDefaultFormat(QSettings.IniFormat)
        QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, os.path.dirname(portable_ini))
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationDisplayName("NetMap")

    from .icons import app_icon
    from .mainwindow import MainWindow
    from .theme import apply_theme

    app.setWindowIcon(app_icon())
    apply_theme(app, args.theme or QSettings().value("ui/theme", "system"))
    win = MainWindow(log_path=log_path)
    if args.project:
        win.open_project(args.project)
    if args.screenshots or args.selftest:
        from .selftest import run_selftest

        return run_selftest(win, args.screenshots, args.selftest)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
