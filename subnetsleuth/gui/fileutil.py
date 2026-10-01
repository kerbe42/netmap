"""Small file helpers shared by the window and its dialogs: where exports go by default,
rotating backups of a project before it is overwritten, and the crash-recovery copy."""
from __future__ import annotations

import json
import os
import shutil
import time
from typing import Optional

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QFileDialog

BACKUPS = 3


def export_dir(project_path: Optional[str] = None) -> str:
    """The folder exports default to: the last one used, else the project's, else home."""
    d = QSettings().value("ui/export_dir")
    if isinstance(d, str) and d and os.path.isdir(d):
        return d
    if project_path:
        return os.path.dirname(os.path.abspath(project_path))
    return os.path.expanduser("~")


def ask_save_path(parent, title: str, default_name: str, filt: str, project_path: Optional[str] = None) -> str:
    """A save dialog that starts in the shared export folder and remembers where the file went."""
    start = os.path.join(export_dir(project_path), default_name)
    path, _ = QFileDialog.getSaveFileName(parent, title, start, filt)
    if path:
        QSettings().setValue("ui/export_dir", os.path.dirname(os.path.abspath(path)))
    return path


def backup_paths(path: str) -> list[str]:
    return [f"{path}.bak{i}" for i in range(1, BACKUPS + 1)]


def rotate_backups(path: str) -> Optional[str]:
    """Keep the last few versions of a project file: name.sleuth.bak1 (newest) … bak3.
    Called before `path` is overwritten; returns the new bak1 or None if there was nothing."""
    if not os.path.exists(path):
        return None
    baks = backup_paths(path)
    for i in range(len(baks) - 1, 0, -1):
        if os.path.exists(baks[i - 1]):
            os.replace(baks[i - 1], baks[i])
    shutil.copy2(path, baks[0])
    return baks[0]


def recovery_paths(data_dir: str) -> tuple[str, str]:
    return os.path.join(data_dir, "recovery.sleuth"), os.path.join(data_dir, "recovery.json")


def write_recovery_meta(data_dir: str, origin: Optional[str], name: str) -> None:
    _, meta = recovery_paths(data_dir)
    with open(meta, "w", encoding="utf-8") as f:
        json.dump({"origin": origin or "", "name": name, "saved": time.time()}, f)


def read_recovery(data_dir: str) -> Optional[dict]:
    """The recovery copy's description if one exists and is newer than the file it came
    from (or came from an unsaved project); None otherwise."""
    path, meta_path = recovery_paths(data_dir)
    if not os.path.exists(path):
        return None
    meta = {}
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        meta = {}
    origin = meta.get("origin") or ""
    saved = os.path.getmtime(path)
    if origin and os.path.exists(origin) and os.path.getmtime(origin) >= saved - 1:
        return None
    return {"path": path, "origin": origin, "name": meta.get("name") or (os.path.basename(origin) if origin else "Untitled project"), "saved": saved}


def clear_recovery(data_dir: str) -> None:
    for p in recovery_paths(data_dir):
        try:
            os.remove(p)
        except OSError:
            pass
