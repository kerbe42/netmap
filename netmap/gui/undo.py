"""Undo for the edits people make by hand: documentation fields, removing an item from the
project, and Re-arrange on the map. Scans are not undoable (the project file's backups are
for that); these three are the ones a slip of the hand makes and a Ctrl+Z should fix."""
from __future__ import annotations

import time

from PySide6.QtGui import QUndoCommand

MERGE_WINDOW_S = 4.0  # keystrokes on the same item within this window undo as one step


class _AppliedCommand(QUndoCommand):
    """The change has already happened when the command is pushed; the first redo() that
    QUndoStack.push() triggers must therefore do nothing."""

    def __init__(self, text: str):
        super().__init__(text)
        self._skip_first_redo = True

    def redo(self):
        if self._skip_first_redo:
            self._skip_first_redo = False
            return
        self.apply()

    def apply(self):  # pragma: no cover - overridden
        raise NotImplementedError


class AnnotateCommand(_AppliedCommand):
    """A documentation edit on one node: `before` and `after` are the node's annotation records."""

    ID = 1

    def __init__(self, win, node_id: str, before: dict, after: dict):
        super().__init__(f"Edit notes of {win.inv.display_name(node_id) if hasattr(win.inv, 'display_name') else node_id}")
        self.win = win
        self.node_id = node_id
        self.before = dict(before)
        self.after = dict(after)
        self.stamp = time.time()

    def id(self):
        return self.ID

    def mergeWith(self, other):
        if not isinstance(other, AnnotateCommand) or other.node_id != self.node_id or other.stamp - self.stamp > MERGE_WINDOW_S:
            return False
        self.after = dict(other.after)
        self.stamp = other.stamp
        return True

    def _set(self, record: dict):
        fields = {k: "" for k in set(self.before) | set(self.after)}  # "" clears a field
        fields.update(record)
        self.win.inv.annotate(self.node_id, **fields)
        self.win.set_dirty(True)
        self.win.refresh(keep_details=False)

    def apply(self):
        self._set(self.after)

    def undo(self):
        self._set(self.before)


class ForgetCommand(_AppliedCommand):
    """Removing a device or host from the project; undo puts the same objects back."""

    def __init__(self, win, node_id: str, device=None, host=None, unreachable_via=None):
        super().__init__(f"Remove {node_id} from project")
        self.win = win
        self.node_id = node_id
        self.device = device
        self.host = host
        self.via = unreachable_via

    def apply(self):
        self.win._remove_node(self.node_id)
        self.win.set_dirty(True)
        self.win.refresh()

    def undo(self):
        inv = self.win.inv
        if self.device is not None:
            inv.add_device(self.device)
            inv.reindex()
        if self.host is not None:
            inv.hosts[self.node_id] = self.host
            inv.rev += 1
        if self.via is not None:
            inv.unreachable[self.node_id] = self.via
        self.win.set_dirty(True)
        self.win.refresh()


class RelayoutCommand(_AppliedCommand):
    """Re-arrange dropped the hand-placed positions of one map view; undo restores them."""

    def __init__(self, win, key: str, old_positions: dict):
        super().__init__(f"Re-arrange {key} map")
        self.win = win
        self.key = key
        self.old = dict(old_positions)

    def apply(self):
        self.win.inv.layout.pop(self.key, None)
        self.win.set_dirty(True)
        if self.win.topology._layout_key() == self.key:
            self.win.topology.rebuild(keep_view=False)

    def undo(self):
        self.win.topology.restore_layout(self.key, self.old)
        self.win.set_dirty(True)
