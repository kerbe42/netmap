"""Entry point for the PyInstaller one-file build (`netmap` / `netmap.exe`).

Adds one bit of field-friendliness over the plain console script: if the frozen
binary is launched with no arguments (e.g. double-clicked in Explorer), show the
help instead of an argparse error, and on Windows keep the console window open so
the user can actually read it before it disappears.
"""
import sys

from netmap.cli import main


def run() -> None:
    frozen = getattr(sys, "frozen", False)
    bare_launch = frozen and len(sys.argv) <= 1
    if bare_launch:
        sys.argv.append("--help")
    try:
        main()
    finally:
        # A double-clicked console app on Windows closes instantly; pause so the
        # help text stays on screen. Only on a bare double-click, never in a shell.
        if bare_launch and sys.platform == "win32":
            try:
                input("\nRun netmap from PowerShell/cmd with a command above. Press Enter to close.")
            except (EOFError, KeyboardInterrupt):
                pass


if __name__ == "__main__":
    run()
