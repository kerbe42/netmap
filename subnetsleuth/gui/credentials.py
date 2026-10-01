"""Saved SNMP credentials and the dialog to manage them.

Secrets never go into a project file: projects get handed around, credentials should
not. They live in the user's settings, encrypted with Windows DPAPI (or the system
keyring elsewhere); where neither exists they are kept for this session only.
A secret can also be `env:NAME`, read from the environment when a scan starts.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Optional

from PySide6.QtCore import QSettings, Qt, QThread, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from .. import secret
from ..snmp import AUTH_PROTOS, PRIV_PROTOS, Credential

SECRET_FIELDS = ("community", "auth_key", "priv_key")


@dataclass
class SavedCredential:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    label: str = ""
    kind: str = "v2c"
    user: str = ""
    auth: str = "SHA"
    priv: str = "AES"
    context: str = ""
    community: str = ""  # stored protected: "dpapi:…", "keyring:…", "env:NAME", or "" (session only)
    auth_key: str = ""
    priv_key: str = ""
    enabled: bool = True

    def describe(self) -> str:
        if self.kind == "v2c":
            return f"SNMPv2c · community {'•' * 6}"
        sec = "authPriv" if self.priv != "NONE" and self.auth != "NONE" else ("authNoPriv" if self.auth != "NONE" else "noAuthNoPriv")
        return f"SNMPv3 · user {self.user} · {sec} ({self.auth}/{self.priv})"


class CredentialStore:
    """Credentials in QSettings; secrets protected at rest (or kept for the session)."""

    KEY = "credentials/list"

    def __init__(self):
        self._session: dict[tuple[str, str], str] = {}  # (id, field) -> plaintext, when not persistable

    def load(self) -> list[SavedCredential]:
        raw = QSettings().value(self.KEY, "[]")
        try:
            items = json.loads(raw if isinstance(raw, str) else "[]")
        except ValueError:
            items = []
        out = []
        for d in items:
            try:
                out.append(SavedCredential(**{k: v for k, v in d.items() if k in SavedCredential.__dataclass_fields__}))
            except TypeError:
                continue
        return out

    def save(self, creds: list[SavedCredential]) -> None:
        QSettings().setValue(self.KEY, json.dumps([asdict(c) for c in creds]))

    def can_persist(self) -> bool:
        return bool(secret.available())

    def set_secret(self, cred: SavedCredential, field_name: str, plain: str) -> None:
        """Protect and attach a secret to `cred` (not saved until save())."""
        if not plain:
            setattr(cred, field_name, "")
            self._session.pop((cred.id, field_name), None)
            return
        if plain.startswith("env:"):
            setattr(cred, field_name, plain)
            return
        try:
            if secret.available():
                token = secret.protect(plain)
                setattr(cred, field_name, token)
                return
        except secret.SecretUnavailable:
            pass
        setattr(cred, field_name, "")
        self._session[(cred.id, field_name)] = plain

    def get_secret(self, cred: SavedCredential, field_name: str) -> str:
        token = getattr(cred, field_name, "") or ""
        if (cred.id, field_name) in self._session:
            return self._session[(cred.id, field_name)]
        if not token:
            return ""
        if token.startswith("env:"):
            return token  # Credential.from_dict resolves it at use time
        try:
            return secret.unprotect(token)
        except secret.SecretUnavailable:
            return ""

    def has_secret(self, cred: SavedCredential, field_name: str) -> bool:
        return bool(getattr(cred, field_name, "")) or (cred.id, field_name) in self._session

    def to_credential(self, cred: SavedCredential) -> Credential:
        d = {"kind": cred.kind, "label": cred.label or cred.id, "user": cred.user or None, "auth": cred.auth, "priv": cred.priv, "context": cred.context}
        for f in SECRET_FIELDS:
            d[f] = self.get_secret(cred, f) or None
        if cred.kind == "v2c":
            d.pop("user")
        return Credential.from_dict(d)


class SnmpTestThread(QThread):
    """Probe one address with a list of credentials off the UI thread."""

    done = Signal(object, object, str)  # label or None, sysinfo dict or None, error

    def __init__(self, ip: str, creds: list[Credential], port: int = 161, timeout: float = 2.0, parent=None):
        super().__init__(parent)
        self.ip, self.creds, self.port, self.timeout = ip, creds, port, timeout

    def run(self):
        import asyncio

        from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

        from .. import oids as O
        from ..snmp import probe
        from ..util import to_text

        async def go():
            eng = SnmpEngine()
            try:
                sess, info = await probe(eng, self.ip, self.creds, self.timeout, 1, self.port)
                if sess is None:
                    return None, None
                r = await sess.get(O.SYS_NAME, O.SYS_DESCR, O.SYS_UPTIME, O.SYS_LOCATION, O.SYS_CONTACT, O.SYS_OBJECTID)
                return sess.cred.label, {k: to_text(v) if not isinstance(v, int) else v for k, v in r.items()}
            finally:
                eng.close_dispatcher()

        try:
            label, info = asyncio.run(go())
            self.done.emit(label, info, "")
        except Exception as e:  # noqa: BLE001
            self.done.emit(None, None, f"{type(e).__name__}: {e}")


def describe_sysinfo(info: dict) -> str:
    from .. import oids as O
    from ..views import fmt_duration

    up = info.get(O.SYS_UPTIME)
    lines = [
        f"Name:        {info.get(O.SYS_NAME, '')}",
        f"Description: {info.get(O.SYS_DESCR, '')}",
        f"Location:    {info.get(O.SYS_LOCATION, '')}",
        f"Contact:     {info.get(O.SYS_CONTACT, '')}",
        f"Uptime:      {fmt_duration(int(up) // 100) if isinstance(up, int) else up}",
        f"Object ID:   {info.get(O.SYS_OBJECTID, '')}",
    ]
    return "\n".join(lines)


class _CredentialList(QListWidget):
    """The saved-credential list, with a hint while it is empty."""

    PLACEHOLDER = "No credentials yet.\n\nAdd your first read-only community or SNMPv3 user with Add…\nSubnetSleuth only reads (SNMP GET/GETBULK); a read-only credential is all it needs."

    def paintEvent(self, e):
        super().paintEvent(e)
        if self.count():
            return
        from PySide6.QtGui import QPainter

        p = QPainter(self.viewport())
        p.setPen(self.palette().color(QPalette.PlaceholderText))
        p.drawText(self.viewport().rect().adjusted(20, 20, -20, -20), Qt.AlignCenter | Qt.TextWordWrap, self.PLACEHOLDER)
        p.end()


class CredentialEditor(QDialog):
    def __init__(self, store: CredentialStore, cred: Optional[SavedCredential] = None, parent=None, ordinal: int = 1):
        super().__init__(parent)
        self.setWindowTitle("SNMP credential")
        self.store = store
        self.cred = cred or SavedCredential()
        self.ordinal = ordinal  # for the default label of a new credential
        self.label = QLineEdit(self.cred.label)
        self.label.setPlaceholderText("e.g. Head office read-only")
        self.v2 = QRadioButton("SNMP v2c (community)")
        self.v3 = QRadioButton("SNMP v3 (user)")
        grp = QButtonGroup(self)
        grp.addButton(self.v2)
        grp.addButton(self.v3)
        (self.v3 if self.cred.kind == "v3" else self.v2).setChecked(True)
        self.community = QLineEdit()
        self.community.setEchoMode(QLineEdit.Password)
        self.user = QLineEdit(self.cred.user)
        self.auth = QComboBox()
        self.auth.addItems([k for k in AUTH_PROTOS if k not in ("SHA1",)])
        self.auth.setCurrentText(self.cred.auth or "SHA")
        self.auth_key = QLineEdit()
        self.auth_key.setEchoMode(QLineEdit.Password)
        self.priv = QComboBox()
        self.priv.addItems([k for k in PRIV_PROTOS if k not in ("AES128",)])
        self.priv.setCurrentText(self.cred.priv or "AES")
        self.priv_key = QLineEdit()
        self.priv_key.setEchoMode(QLineEdit.Password)
        self.context = QLineEdit(self.cred.context)
        for w, f in ((self.community, "community"), (self.auth_key, "auth_key"), (self.priv_key, "priv_key")):
            if store.has_secret(self.cred, f):
                w.setPlaceholderText("(saved — leave empty to keep)")
            else:
                w.setPlaceholderText("secret, or env:VARIABLE to read it from the environment")
        self.show_btn = QPushButton("Show")
        self.show_btn.setCheckable(True)
        self.show_btn.toggled.connect(self._show)

        form = QFormLayout()
        form.addRow("Label", self.label)
        kinds = QHBoxLayout()
        kinds.addWidget(self.v2)
        kinds.addWidget(self.v3)
        kinds.addStretch(1)
        form.addRow("Version", kinds)
        self.v2box = QWidget()
        f2 = QFormLayout(self.v2box)
        f2.setContentsMargins(0, 0, 0, 0)
        c = QHBoxLayout()
        c.addWidget(self.community)
        c.addWidget(self.show_btn)
        f2.addRow("Community", c)
        self.v3box = QWidget()
        f3 = QFormLayout(self.v3box)
        f3.setContentsMargins(0, 0, 0, 0)
        f3.addRow("User name", self.user)
        f3.addRow("Authentication", self.auth)
        f3.addRow("Auth password", self.auth_key)
        f3.addRow("Privacy", self.priv)
        f3.addRow("Privacy password", self.priv_key)
        f3.addRow("Context (optional)", self.context)
        form.addRow(self.v2box)
        form.addRow(self.v3box)
        where = secret.available()
        note = QLabel(f"Secrets are stored encrypted with {where}." if where else "This system has no secure store: secrets are kept only until SubnetSleuth closes.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        self.test_btn = QPushButton("Test against a device…")
        self.test_btn.clicked.connect(self._test)
        self.result = QLabel()
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(note)
        tl = QHBoxLayout()
        tl.addWidget(self.test_btn)
        tl.addStretch(1)
        lay.addLayout(tl)
        lay.addWidget(self.result)
        lay.addWidget(bb)
        self.v2.toggled.connect(self._kind)
        self._kind()
        self.resize(460, 0)

    def _show(self, on):
        for w in (self.community, self.auth_key, self.priv_key):
            w.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)

    def _kind(self, *_):
        self.v2box.setVisible(self.v2.isChecked())
        self.v3box.setVisible(self.v3.isChecked())
        self.adjustSize()

    def _apply(self) -> Optional[SavedCredential]:
        c = self.cred
        c.kind = "v2c" if self.v2.isChecked() else "v3"
        # never derive the label from the community: labels go into project files as Device.credential
        c.label = self.label.text().strip() or self._default_label(c.kind)
        c.user = self.user.text().strip()
        c.auth = self.auth.currentText()
        c.priv = self.priv.currentText()
        c.context = self.context.text().strip()
        for w, f in ((self.community, "community"), (self.auth_key, "auth_key"), (self.priv_key, "priv_key")):
            if w.text():
                self.store.set_secret(c, f, w.text())
        if c.kind == "v2c" and not self.store.has_secret(c, "community"):
            QMessageBox.warning(self, "Community needed", "Enter the SNMP community string.")
            return None
        if c.kind == "v3" and not c.user:
            QMessageBox.warning(self, "User needed", "Enter the SNMPv3 user name.")
            return None
        return c

    def _default_label(self, kind: str) -> str:
        from .. import snmp

        fn = getattr(snmp, "default_label", None)  # the core's naming when it has one
        if callable(fn):
            try:
                label = fn(kind)
                if label:
                    return str(label)
            except TypeError:
                pass
        if kind == "v3" and self.user.text().strip():
            return f"v3 {self.user.text().strip()}"
        return f"{kind} credential {self.ordinal}"

    def _accept(self):
        if self._apply() is not None:
            self.accept()

    def _test(self):
        c = self._apply()
        if c is None:
            return
        ip, ok = QInputDialog.getText(self, "Test credential", "Device address to query (one SNMP GET of the system group):")
        if not ok or not ip.strip():
            return
        self.result.setText(f"Asking {ip.strip()}…")
        self.test_btn.setEnabled(False)
        self._thread = SnmpTestThread(ip.strip(), [self.store.to_credential(c)], parent=self)
        self._thread.done.connect(self._tested)
        self._thread.start()

    def _tested(self, label, info, err):
        self.test_btn.setEnabled(True)
        if err:
            self.result.setText(f"<span style='color:#dc2626'>Error: {err}</span>")
        elif label is None:
            self.result.setText("<span style='color:#dc2626'>No answer.</span> Wrong community/user or keys, SNMP not enabled for this address, or filtered on the way.")
        else:
            from .. import oids as O

            self.result.setText(f"<span style='color:#16a34a'>Answered.</span> <b>{info.get(O.SYS_NAME, '')}</b><br>{info.get(O.SYS_DESCR, '')[:200]}")


class CredentialsDialog(QDialog):
    """List, order, add, edit and remove saved credentials. Order is the order they are tried."""

    def __init__(self, store: CredentialStore, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SNMP credentials")
        self.store = store
        self.creds = store.load()
        self.list = _CredentialList()
        self.list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list.setDragDropMode(QAbstractItemView.InternalMove)
        self.list.itemDoubleClicked.connect(lambda _: self._edit())
        self.list.model().rowsMoved.connect(self._reordered)
        add = QPushButton("Add…")
        add.clicked.connect(self._add)
        edit = QPushButton("Edit…")
        edit.clicked.connect(self._edit)
        rm = QPushButton("Remove")
        rm.clicked.connect(self._remove)
        up = QPushButton("Move up")
        up.clicked.connect(lambda: self._move(-1))
        down = QPushButton("Move down")
        down.clicked.connect(lambda: self._move(1))
        side = QVBoxLayout()
        for b in (add, edit, rm, up, down):
            side.addWidget(b)
        side.addStretch(1)
        body = QHBoxLayout()
        body.addWidget(self.list, 1)
        body.addLayout(side)
        hint = QLabel("Credentials are tried in this order on every device; the first that answers is recorded against it. "
                      "Use read-only credentials: SubnetSleuth only ever reads (SNMP GET/GETBULK).")
        hint.setWordWrap(True)
        hint.setObjectName("muted")
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.accept)
        bb.accepted.connect(self.accept)
        lay = QVBoxLayout(self)
        lay.addLayout(body)
        lay.addWidget(hint)
        lay.addWidget(bb)
        self._fill()
        self.resize(560, 360)

    def _fill(self, select: int = -1):
        self.list.clear()
        for c in self.creds:
            it = QListWidgetItem(f"{c.label}\n{c.describe()}")
            it.setData(Qt.UserRole, c.id)
            self.list.addItem(it)
        if 0 <= select < self.list.count():
            self.list.setCurrentRow(select)

    def _save(self):
        self.store.save(self.creds)

    def _reordered(self, *_):
        order = [self.list.item(i).data(Qt.UserRole) for i in range(self.list.count())]
        by = {c.id: c for c in self.creds}
        self.creds = [by[i] for i in order if i in by]
        self._save()

    def _add(self):
        dlg = CredentialEditor(self.store, None, self, ordinal=len(self.creds) + 1)
        if dlg.exec():
            self.creds.append(dlg.cred)
            self._save()
            self._fill(len(self.creds) - 1)

    def _edit(self):
        row = self.list.currentRow()
        if row < 0:
            return
        dlg = CredentialEditor(self.store, self.creds[row], self)
        if dlg.exec():
            self._save()
            self._fill(row)

    def _remove(self):
        row = self.list.currentRow()
        if row < 0:
            return
        if QMessageBox.question(self, "Remove credential", f"Remove “{self.creds[row].label}”?") == QMessageBox.Yes:
            del self.creds[row]
            self._save()
            self._fill(min(row, len(self.creds) - 1))

    def _move(self, d):
        row = self.list.currentRow()
        new = row + d
        if row < 0 or not (0 <= new < len(self.creds)):
            return
        self.creds[row], self.creds[new] = self.creds[new], self.creds[row]
        self._save()
        self._fill(new)
