"""Light and dark themes. "System" follows Windows' app mode with the native style;
Light and Dark force a consistent Fusion look everywhere."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QStyleFactory

EXTRA_QSS = """
QLabel#muted { color: palette(placeholder-text); }
QLabel#h1 { font-size: 18px; font-weight: 600; }
QLabel#h2 { font-size: 13px; font-weight: 600; }
QWidget#banner { background: #fef3c7; color: #78350f; }
QWidget#banner QLabel { color: #78350f; }
QFrame#legend { background: palette(base); border: 1px solid palette(mid); border-radius: 6px; }
QFrame#card { background: palette(base); border: 1px solid palette(midlight); border-radius: 8px; }
QLabel#cardValue { font-size: 24px; font-weight: 600; }
QLabel#cardTitle { color: palette(placeholder-text); }
QTreeWidget#nav { border: none; background: palette(window); }
QTreeWidget#nav::item { padding: 5px 4px; }
QTableView { gridline-color: palette(midlight); }
QToolBar { spacing: 4px; }
"""


def _dark_palette() -> QPalette:
    p = QPalette()
    base = QColor("#1b1f27")
    window = QColor("#232833")
    text = QColor("#e5e7eb")
    p.setColor(QPalette.Window, window)
    p.setColor(QPalette.WindowText, text)
    p.setColor(QPalette.Base, base)
    p.setColor(QPalette.AlternateBase, QColor("#20252e"))
    p.setColor(QPalette.ToolTipBase, QColor("#111827"))
    p.setColor(QPalette.ToolTipText, text)
    p.setColor(QPalette.Text, text)
    p.setColor(QPalette.Button, QColor("#2b313d"))
    p.setColor(QPalette.ButtonText, text)
    p.setColor(QPalette.BrightText, QColor("#ffffff"))
    p.setColor(QPalette.Highlight, QColor("#3b82f6"))
    p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    p.setColor(QPalette.Link, QColor("#60a5fa"))
    p.setColor(QPalette.PlaceholderText, QColor("#8b95a5"))
    p.setColor(QPalette.Mid, QColor("#3a4150"))
    p.setColor(QPalette.Midlight, QColor("#323846"))
    p.setColor(QPalette.Dark, QColor("#15181e"))
    p.setColor(QPalette.Light, QColor("#3f4757"))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor("#6b7280"))
    return p


def _light_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor("#f3f4f6"))
    p.setColor(QPalette.WindowText, QColor("#111827"))
    p.setColor(QPalette.Base, QColor("#ffffff"))
    p.setColor(QPalette.AlternateBase, QColor("#f8fafc"))
    p.setColor(QPalette.ToolTipBase, QColor("#ffffff"))
    p.setColor(QPalette.ToolTipText, QColor("#111827"))
    p.setColor(QPalette.Text, QColor("#111827"))
    p.setColor(QPalette.Button, QColor("#f9fafb"))
    p.setColor(QPalette.ButtonText, QColor("#111827"))
    p.setColor(QPalette.Highlight, QColor("#2563eb"))
    p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    p.setColor(QPalette.Link, QColor("#1d4ed8"))
    p.setColor(QPalette.PlaceholderText, QColor("#6b7280"))
    p.setColor(QPalette.Mid, QColor("#cbd5e1"))
    p.setColor(QPalette.Midlight, QColor("#e5e7eb"))
    p.setColor(QPalette.Dark, QColor("#94a3b8"))
    p.setColor(QPalette.Light, QColor("#ffffff"))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor("#9ca3af"))
    return p


_native_style = None


def apply_theme(app: QApplication, mode: str = "system") -> None:
    global _native_style
    if _native_style is None:
        _native_style = app.style().name()
    hints = app.styleHints()
    # Styles are set by name so Qt creates and owns them; handing it a Python-created
    # QStyle leads to a double free when the next theme replaces it.
    if mode == "dark":
        app.setStyle("Fusion")
        app.setPalette(_dark_palette())
        _set_scheme(hints, Qt.ColorScheme.Dark)
    elif mode == "light":
        app.setStyle("Fusion")
        app.setPalette(_light_palette())
        _set_scheme(hints, Qt.ColorScheme.Light)
    else:
        _set_scheme(hints, Qt.ColorScheme.Unknown)
        if _native_style and _native_style in [k.lower() for k in QStyleFactory.keys()] + QStyleFactory.keys():
            app.setStyle(_native_style)
        app.setPalette(app.style().standardPalette())
        if hints.colorScheme() == Qt.ColorScheme.Dark and _native_style and _native_style.lower() not in ("windows11", "macos"):
            app.setStyle("Fusion")
            app.setPalette(_dark_palette())
    app.setStyleSheet(EXTRA_QSS)


def _set_scheme(hints, scheme) -> None:
    try:
        hints.setColorScheme(scheme)
    except AttributeError:  # Qt < 6.8
        pass
