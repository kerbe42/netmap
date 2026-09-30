"""Write packaging/netmap.ico (and a 256px PNG) from the app's vector icon.

A Windows .ico holds one image per size; modern Windows reads PNG-compressed entries, so
each size is rendered by Qt and packed here without any imaging library.
Run: QT_QPA_PLATFORM=offscreen python tools/make_icon.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QBuffer, QByteArray, QIODevice  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication([])
from netmap.gui.icons import app_pixmap  # noqa: E402

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def png(size: int) -> bytes:
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    app_pixmap(size).save(buf, "PNG")
    return bytes(ba)


def main():
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packaging")
    images = [png(s) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(SIZES))
    offset = 6 + 16 * len(SIZES)
    entries = b""
    for s, data in zip(SIZES, images):
        dim = 0 if s >= 256 else s
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    with open(os.path.join(out, "netmap.ico"), "wb") as f:
        f.write(header + entries + b"".join(images))
    with open(os.path.join(out, "netmap-256.png"), "wb") as f:
        f.write(images[-1])
    print("wrote", os.path.join(out, "netmap.ico"))


if __name__ == "__main__":
    main()
