"""Upgrading from NetMap (the name up to 0.12): settings, secrets, host keys and env vars carry over."""
import os

import pytest

from subnetsleuth import secret, sshtrust
from subnetsleuth.cli import build_credentials, build_parser


def test_secret_identifiers_are_the_netmap_ones():
    # changing these would make every credential saved before the rename unreadable
    assert secret.ENTROPY == b"netmap-credential-v1"
    assert secret.KEYRING_SERVICE == "netmap"


def test_old_community_variable_still_works(monkeypatch):
    monkeypatch.delenv("SUBNETSLEUTH_COMMUNITY", raising=False)
    monkeypatch.setenv("NETMAP_COMMUNITY", "old-ro")
    creds = build_credentials(build_parser().parse_args(["crawl", "--seed", "10.0.0.1"]), {})
    assert [c.community for c in creds] == ["old-ro"]
    monkeypatch.setenv("SUBNETSLEUTH_COMMUNITY", "new-ro")
    creds = build_credentials(build_parser().parse_args(["crawl", "--seed", "10.0.0.1"]), {})
    assert [c.community for c in creds] == ["new-ro"]


def test_known_hosts_recorded_by_netmap_are_carried_over(monkeypatch, tmp_path):
    monkeypatch.delenv("SUBNETSLEUTH_KNOWN_HOSTS", raising=False)
    monkeypatch.delenv("NETMAP_KNOWN_HOSTS", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    old_dir = tmp_path / ("NetMap" if os.name == "nt" else "netmap")
    old_dir.mkdir()
    (old_dir / "known_hosts").write_text("10.0.0.1 ssh-ed25519 AAAA\n")
    path = sshtrust.known_hosts_path()
    assert open(path).read() == "10.0.0.1 ssh-ed25519 AAAA\n"
    assert os.path.dirname(path) != str(old_dir)


def test_netmap_settings_are_copied_once(tmp_path):
    pytest.importorskip("PySide6")
    from PySide6.QtCore import QCoreApplication, QSettings

    from subnetsleuth.gui.app import migrate_netmap_settings

    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, str(tmp_path))
    old = QSettings("netmap", "NetMap")
    old.setValue("credentials", '[{"label": "site-ro"}]')
    old.setValue("scan_defaults/workers", 20)
    old.sync()
    QCoreApplication.setOrganizationName("subnetsleuth")
    QCoreApplication.setApplicationName("SubnetSleuth")
    try:
        assert migrate_netmap_settings() == 2
        new = QSettings()
        assert new.value("credentials") == '[{"label": "site-ro"}]' and int(new.value("scan_defaults/workers")) == 20
        assert QSettings("netmap", "NetMap").value("credentials")  # the old settings are left in place
        old.setValue("scan_defaults/workers", 4)
        old.sync()
        assert migrate_netmap_settings() == 0 and int(QSettings().value("scan_defaults/workers")) == 20
    finally:
        QCoreApplication.setOrganizationName("")
        QCoreApplication.setApplicationName("")
