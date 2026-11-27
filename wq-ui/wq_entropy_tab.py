"""Entropy tab: plots how random each part of a file looks, so encrypted or packed data stands out.

The analysis lives in wq_entropy (plain Python, tested on its own). This module is only the
window: a plot that scrolls along the file, a whole-file overview strip, the flagged runs, and a
byte view (text/code or hex) of whatever block is selected. The plot is drawn as a widget as wide
as the window and moved by a scrollbar, so a big file does not need a giant widget that Qt cannot size.
"""
from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QFontDatabase, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDoubleSpinBox, QFileDialog, QHBoxLayout, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QProgressBar, QPushButton,
                               QScrollBar, QSizePolicy, QSplitter, QVBoxLayout, QWidget)

import wq_entropy as E

GUT = 40            # gutter on the left of the plot, for the 0..8 scale
TOP, BOT = 12, 22   # empty padding above and below the trace


def _hex(v: int) -> str:
    return f"0x{v:X}"


def _tint(c: QColor, alpha: int) -> QColor:
    t = QColor(c)
    t.setAlpha(alpha)
    return t


def _fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _decode_text(data: bytes) -> str:
    """Render bytes as readable text/code, replacing control bytes except tab/LF/CR."""
    out: list[str] = []
    for v in data:
        if v in (9, 10, 13) or 32 <= v < 127:
            out.append(chr(v))
        else:
            out.append("·")
    return "".join(out)


class _Worker(QThread):
    progress = Signal(int, int, int)     # token, done, total
    done = Signal(int, object)           # token, Analysis
    failed = Signal(int, str)            # token, message

    def __init__(self, token: int, path: str, block: int, parent=None):
        super().__init__(parent)
        self.token, self.path, self.block = token, path, block

    def run(self):
        try:
            res = E.analyse_file(
                self.path, self.block,
                progress=lambda d, t: self.progress.emit(self.token, d, t),
                cancelled=self.isInterruptionRequested)
        except E.Cancelled:
            return
        except (OSError, ValueError) as e:
            self.failed.emit(self.token, str(e))
            return
        self.done.emit(self.token, res)


class _Plot(QWidget):
    """The entropy trace for the visible part of the file. Knows nothing about scrollbars: the
    tab tells it which pixel offset to draw from."""
    block_clicked = Signal(int)
    block_hovered = Signal(int)
    pan = Signal(int)           # pixels, from the wheel or keyboard
    geometry_changed = Signal()

    def __init__(self, colors_fn, parent=None):
        super().__init__(parent)
        self._colors = colors_fn
        self.an: E.Analysis | None = None
        self.thr = E.DEFAULT_THRESHOLD
        self.zoom = 2
        self.offset = 0          # pixels scrolled
        self.sel = -1
        self._press_x = None
        self._last_x = 0.0
        self._dragging = False
        self.setMinimumHeight(200)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(220)

    def _step(self) -> float:
        """Pixels per block. When a small file fits inside the plot width at low zoom,
        stretch slightly so the trace stays readable instead of bunching in a few pixels."""
        z = float(max(1, self.zoom))
        if self.an is None or self.an.blocks <= 1:
            return z
        avail = max(1.0, float(self.width() - GUT - 16))
        natural = self.an.blocks * z
        if self.zoom <= 2 and natural < avail * 0.5:
            return max(z, avail / self.an.blocks)
        return z

    def content_width(self) -> int:
        if self.an is None or self.an.blocks == 0:
            return max(self.width(), GUT)
        span = int(self.an.blocks * self._step())
        pad = min(self.width() // 4, max(24, span // 6))
        return GUT + span + pad

    def _block_at(self, x: float) -> int:
        if self.an is None or self.an.blocks == 0 or x < GUT:
            return -1
        step = self._step()
        b = int((x - GUT + self.offset) // step)
        return b if 0 <= b < self.an.blocks else -1

    def resizeEvent(self, e):  # noqa: N802 (Qt override)
        super().resizeEvent(e)
        self.geometry_changed.emit()

    def paintEvent(self, _e):  # noqa: N802 (Qt override)
        c = self._colors()
        p = QPainter(self)
        W, H = self.width(), self.height()
        p.fillRect(self.rect(), c["bg"])
        if self.an is None or self.an.blocks == 0:
            p.setPen(c["muted"])
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "Open a file to plot its entropy." if self.an is None else "That file is empty.")
            p.end()
            return

        step, off, nb = self._step(), self.offset, self.an.blocks
        ent = self.an.ent
        top, bot = TOP, H - BOT
        plot_h = bot - top

        def y(e: float) -> float:
            return bot - (max(0.0, min(8.0, e)) / 8.0) * plot_h

        def x_left(i: int) -> float:
            return GUT + i * step - off

        def x_mid(i: int) -> float:
            return x_left(i) + step / 2.0

        # gridlines and the scale in the gutter
        p.setPen(QPen(c["grid"], 1))
        for v in range(0, 9, 2):
            yy = round(y(v)) + 0.5
            p.drawLine(QPointF(GUT, yy), QPointF(W, yy))

        i0 = max(0, int(off // step) - 1)
        i1 = min(nb - 1, int((off + W) // step) + 1)

        p.save()
        p.setClipRect(QRectF(GUT, 0, max(0, W - GUT), H))
        # flagged blocks
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(_tint(c["flag"], 90)))
        for i in range(i0, i1 + 1):
            if ent[i] >= self.thr:
                p.drawRect(QRectF(x_left(i), top, max(1.5, step), plot_h))
        if i1 >= i0:
            # area under the trace
            poly = [QPointF(x_mid(i0), bot)] + [QPointF(x_mid(i), y(ent[i])) for i in range(i0, i1 + 1)]
            poly.append(QPointF(x_mid(i1), bot))
            p.setBrush(QBrush(_tint(c["trace"], 36)))
            p.drawPolygon(QPolygonF(poly))
            # the trace itself
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(c["trace"], 1.5))
            if i1 > i0:
                p.drawPolyline(QPolygonF([QPointF(x_mid(i), y(ent[i])) for i in range(i0, i1 + 1)]))
            else:
                p.drawEllipse(QPointF(x_mid(i0), y(ent[i0])), 2.5, 2.5)
        # flag threshold
        yt = round(y(self.thr)) + 0.5
        p.setPen(QPen(c["flag"], 1, Qt.PenStyle.DashLine))
        p.drawLine(QPointF(GUT, yt), QPointF(W, yt))
        # selected block
        if 0 <= self.sel < nb:
            p.setPen(QPen(c["ink"], 1.25))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRect(QRectF(x_left(self.sel) + 0.5, top, max(1.5, step - 1), plot_h))
        p.restore()

        # gutter over anything scrolled beneath it
        p.fillRect(QRectF(0, 0, GUT, H), c["bg"])
        p.setPen(QPen(c["grid"], 1))
        p.drawLine(QPointF(GUT - 0.5, top), QPointF(GUT - 0.5, bot))
        p.setPen(c["muted"])
        for v in range(0, 9, 2):
            p.drawText(QRectF(0, y(v) - 8, GUT - 6, 16), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(v))
        p.end()

    # A press that stays put is a click (select the block). Moving more than a few pixels with the left
    # button down drags the plot along the file instead, like grabbing a map.
    DRAG_PX = 4

    def mousePressEvent(self, e):  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            self._press_x = self._last_x = e.position().x()
            self._dragging = False
        else:
            super().mousePressEvent(e)

    def mouseMoveEvent(self, e):  # noqa: N802
        x = e.position().x()
        if e.buttons() & Qt.MouseButton.LeftButton and getattr(self, "_press_x", None) is not None:
            if not self._dragging and abs(x - self._press_x) >= self.DRAG_PX:
                self._dragging = True
                self.setCursor(Qt.CursorShape.ClosedHandCursor)
                self.block_hovered.emit(-1)
            if self._dragging:
                self.pan.emit(int(round(self._last_x - x)))
                self._last_x = x
                return
        self.block_hovered.emit(self._block_at(x))

    def mouseReleaseEvent(self, e):  # noqa: N802
        if e.button() != Qt.MouseButton.LeftButton or getattr(self, "_press_x", None) is None:
            super().mouseReleaseEvent(e)
            return
        if self._dragging:
            self.unsetCursor()
        else:
            b = self._block_at(e.position().x())
            if b >= 0:
                self.block_clicked.emit(b)
        self._press_x, self._dragging = None, False

    def leaveEvent(self, e):  # noqa: N802
        super().leaveEvent(e)
        self.block_hovered.emit(-1)

    def wheelEvent(self, e):  # noqa: N802
        dx, dy = e.angleDelta().x(), e.angleDelta().y()
        d = dx if abs(dx) > abs(dy) else dy
        self.pan.emit(int(-d / 120 * 80))
        e.accept()

    def keyPressEvent(self, e):  # noqa: N802
        if e.key() == Qt.Key.Key_Right:
            self.pan.emit(self.width() // 2)
        elif e.key() == Qt.Key.Key_Left:
            self.pan.emit(-(self.width() // 2))
        else:
            super().keyPressEvent(e)


class _Overview(QWidget):
    """The whole file in one strip, each column showing the most random block it covers."""
    jump = Signal(int)          # block index to centre on

    def __init__(self, colors_fn, parent=None):
        super().__init__(parent)
        self._colors = colors_fn
        self.an: E.Analysis | None = None
        self.thr = E.DEFAULT_THRESHOLD
        self.view = (0, 0)       # first and one-past-last visible block
        self._cols: list[tuple[float, bool]] = []
        self.setFixedHeight(56)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_data(self, an, thr: float):
        self.an, self.thr = an, thr
        self._rebuild()
        self.update()

    def set_view(self, first: int, end: int):
        self.view = (first, end)
        self.update()

    def _rebuild(self):
        W = max(1, self.width())
        self._cols = []
        if self.an is None or self.an.blocks == 0:
            return
        nb, ent = self.an.blocks, self.an.ent
        for x in range(W):
            a = (x * nb) // W
            b = max(a + 1, ((x + 1) * nb) // W)
            m = max(ent[a:min(b, nb)])
            self._cols.append((m, m >= self.thr))

    def resizeEvent(self, e):  # noqa: N802
        super().resizeEvent(e)
        self._rebuild()

    def paintEvent(self, _e):  # noqa: N802
        c = self._colors()
        p = QPainter(self)
        W, H = self.width(), self.height()
        p.fillRect(self.rect(), c["bg"])
        if self._cols:
            p.setPen(Qt.PenStyle.NoPen)
            for x, (m, hot) in enumerate(self._cols):
                h = (m / 8.0) * (H - 4)
                p.setBrush(c["flag"] if hot else _tint(c["trace"], 140))
                p.drawRect(QRectF(x, H - 2 - h, 1, h))
            if self.an and self.an.blocks:
                nb = self.an.blocks
                x0 = self.view[0] / nb * W
                x1 = max(x0 + 3, self.view[1] / nb * W)
                p.setPen(QPen(c["ink"], 1))
                p.setBrush(_tint(c["ink"], 30))
                p.drawRect(QRectF(x0, 0.5, x1 - x0, H - 1))
        p.end()

    def _jump_to(self, x: float):
        nb = self.an.blocks
        self.jump.emit(max(0, min(nb - 1, int(x / max(1, self.width()) * nb))))

    def mousePressEvent(self, e):  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton and self.an and self.an.blocks:
            self._jump_to(e.position().x())

    def mouseMoveEvent(self, e):  # noqa: N802
        # holding the button and dragging scrubs through the file
        if e.buttons() & Qt.MouseButton.LeftButton and self.an and self.an.blocks:
            self._jump_to(e.position().x())


# Extensions treated as "programs and libraries" by the picker's default filter.
_BINARY_EXTS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".com", ".cpl", ".drv", ".msi", ".so", ".bin",
                ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta", ".lnk", ".sh", ".py"}


class _FilePicker(QDialog):
    """Searchable list of candidate files. Replaces a combo box that could hold hundreds of long paths."""

    MAX_ROWS = 300

    def __init__(self, candidates, current_path, binaries_only: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Choose a file to analyse")
        self.resize(760, 520)
        self._cands = list(candidates)
        self.chosen: str | None = None
        self.binaries_only = binaries_only

        self.edit = QLineEdit()
        self.edit.setPlaceholderText("Filter by name or folder…")
        self.edit.setClearButtonEnabled(True)
        self.edit.textChanged.connect(self._refill)
        self.chk_bin = QCheckBox("Programs, libraries and scripts only (.exe .dll .ps1 .bat …)")
        self.chk_bin.setChecked(binaries_only)
        self.chk_bin.toggled.connect(self._refill)
        self.lst = QListWidget()
        self.lst.setUniformItemSizes(True)
        self.lst.itemActivated.connect(self._accept_item)
        self.lst.itemDoubleClicked.connect(self._accept_item)
        self.lbl = QLabel("")

        v = QVBoxLayout(self)
        v.addWidget(self.edit)
        v.addWidget(self.chk_bin)
        v.addWidget(self.lst, 1)
        v.addWidget(self.lbl)
        self._current = current_path
        self._refill()
        self.edit.setFocus()

    def _refill(self, *_):
        needle = self.edit.text().strip().lower()
        only_bin = self.chk_bin.isChecked()
        self.binaries_only = only_bin
        self.lst.clear()
        shown = 0
        matched = 0
        select_row = 0
        for c in self._cands:
            rel = c.rel
            if only_bin and Path(rel).suffix.lower() not in _BINARY_EXTS:
                continue
            if needle and needle not in rel.lower():
                continue
            matched += 1
            is_current = str(c.path) == self._current
            if shown >= self.MAX_ROWS and not is_current:      # hundreds of rows are not browsable: narrow with the filter
                continue
            name = Path(rel).name
            folder = str(Path(rel).parent)
            meta = _fmt_size(c.size) + (f" · {c.reads} reads" if c.reads else "")
            text = f"{name}    {meta}\n{folder if folder != '.' else ''}"
            it = QListWidgetItem(text)
            it.setData(Qt.ItemDataRole.UserRole, str(c.path))
            it.setToolTip(f"{c.path}\n{meta}")
            self.lst.addItem(it)
            if str(c.path) == self._current:
                select_row = shown
            shown += 1
        if shown:
            self.lst.setCurrentRow(select_row)
        more = f" — showing the first {shown}, type in the filter to narrow it" if matched > shown else ""
        self.lbl.setText(f"{matched} match(es) of {len(self._cands)} files{more}")

    def keyPressEvent(self, e):  # noqa: N802
        # Down/Up in the filter box move through the list, Enter picks.
        if e.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up) and self.edit.hasFocus():
            self.lst.setFocus()
            self.lst.keyPressEvent(e)
            return
        if e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self.lst.currentItem():
            self._accept_item(self.lst.currentItem())
            return
        super().keyPressEvent(e)

    def _accept_item(self, it):
        self.chosen = it.data(Qt.ItemDataRole.UserRole)
        self.accept()


class EntropyTab(QWidget):
    def __init__(self, theme, parent=None):
        super().__init__(parent)
        self.theme = theme
        self.game_dir: Path | None = None
        self.candidates: list[E.CandidateFile] = []
        self._pending_auto_plot = False
        self._auto_source: str | None = None     # file whose auto threshold/jump has already been applied
        self._user_picked = False                # True once the person chose a file (picker or Open file…)
        self._cache: tuple[tuple | None, E.Analysis] | None = None   # last analysis, keyed by file state and block size
        self.path: str | None = None
        self.an: E.Analysis | None = None
        self.regions: list[E.Region] = []
        self._last_data: bytes = b""
        self._last_off: int = 0
        self._token = 0
        self._jobs: set[_Worker] = set()
        self._binaries_only = True

        # ---- toolbar
        self.btn_open = QPushButton("Open file…")
        self.btn_open.setToolTip("Pick any file manually. Starts in the selected game's folder.")
        self.btn_open.clicked.connect(self._open)

        self.cmb_sort = QComboBox()
        self.cmb_sort.addItem("Auto (smart)", "smart")
        self.cmb_sort.addItem("Most reads", "reads")
        self.cmb_sort.addItem("Largest size", "size")
        self.cmb_sort.setToolTip("How files from the selected game are ranked and auto-selected.")
        # Re-ranking keeps the file you have open; it only changes which file a fresh selection picks.
        self.cmb_sort.currentIndexChanged.connect(lambda _i: self._reload_game_files(auto_plot=True, keep_current=True))

        self.chk_prefix = QCheckBox("Installed files")
        self.chk_prefix.setChecked(True)
        self.chk_prefix.setToolTip("Also list files the program installed into the Wine prefix\n"
                                   "(Program Files, ProgramData, users, windows/temp).\n"
                                   "Stock Wine files under drive_c/windows are left out.")
        self.chk_prefix.toggled.connect(lambda _c: self._reload_game_files(auto_plot=True, keep_current=True))

        self.btn_file = QPushButton("No file selected")
        self.btn_file.setMinimumWidth(180)
        self.btn_file.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.btn_file.setStyleSheet("text-align: left;")
        self.btn_file.setToolTip("Click to search the files found in the selected game.")
        self.btn_file.clicked.connect(self._pick_file)
        self._file_full = ""

        self.lbl_size = QLabel("")
        self.cmb_block = QComboBox()
        for b in E.BLOCK_SIZES:
            self.cmb_block.addItem("1 KB" if b == 1024 else "4 KB" if b == 4096 else f"{b} B", b)
        self.cmb_block.setCurrentIndex(E.BLOCK_SIZES.index(E.DEFAULT_BLOCK))
        self.cmb_block.setToolTip("How much data each point covers. 1 KB reads random data reliably; 256 B is noisy.")
        self.cmb_block.currentIndexChanged.connect(lambda _i: self.plot())
        self.cmb_zoom = QComboBox()
        for z in (1, 2, 4, 8):
            self.cmb_zoom.addItem(f"{z}x", z)
        self.cmb_zoom.setCurrentIndex(1)
        self.cmb_zoom.setToolTip("Pixels per block. Scroll along the plot to move through the file.")
        self.cmb_zoom.currentIndexChanged.connect(self._zoom_changed)
        self.spn_thr = QDoubleSpinBox()
        self.spn_thr.setRange(0.0, 8.0)
        self.spn_thr.setDecimals(1)
        self.spn_thr.setSingleStep(0.1)
        self.spn_thr.setValue(E.DEFAULT_THRESHOLD)
        self.spn_thr.setToolTip("Blocks at or above this many bits per byte are flagged.\n"
                                "7.2 is for raw/packed binary noise; ~5.2-5.6 helps spot Base64/ASCII85/hex patches.")
        self.spn_thr.valueChanged.connect(self._thr_changed)
        self.btn_auto = QPushButton("Auto")
        self.btn_auto.setEnabled(False)
        self.btn_auto.setToolTip("Estimate a peak threshold above the file's normal entropy baseline.")
        self.btn_auto.clicked.connect(self._auto_threshold)
        self.btn_plot = QPushButton("Plot entropy")
        self.btn_plot.setProperty("accent", True)
        self.btn_plot.setEnabled(False)
        self.btn_plot.clicked.connect(self.plot)
        self.btn_next = QPushButton("Next flagged")
        self.btn_next.setEnabled(False)
        self.btn_next.clicked.connect(self._next_flagged)

        # Two rows: which file (top), how to analyse it (bottom). One row got crushed on narrow windows.
        row1 = QHBoxLayout()
        row1.addWidget(self.btn_open)
        row1.addWidget(QLabel("Sort"))
        row1.addWidget(self.cmb_sort)
        row1.addWidget(self.chk_prefix)
        row1.addWidget(self.btn_file, 1)
        row1.addWidget(self.lbl_size)
        row2 = QHBoxLayout()
        for w in (QLabel("Block"), self.cmb_block, QLabel("Zoom"), self.cmb_zoom,
                  QLabel("Flag above"), self.spn_thr, self.btn_auto):
            row2.addWidget(w)
        row2.addStretch(1)
        row2.addWidget(self.btn_plot)
        row2.addWidget(self.btn_next)
        bar = QVBoxLayout()
        bar.setSpacing(6)
        bar.addLayout(row1)
        bar.addLayout(row2)

        # ---- plot area
        self.overview = _Overview(self._colors)
        self.overview.jump.connect(self._center_on)
        self.plot_w = _Plot(self._colors)
        self.plot_w.block_clicked.connect(self._select)
        self.plot_w.block_hovered.connect(self._hover)
        self.plot_w.pan.connect(lambda d: self.bar.setValue(self.bar.value() + d))
        self.plot_w.geometry_changed.connect(self._sync_scroll)
        self.bar = QScrollBar(Qt.Orientation.Horizontal)
        self.bar.valueChanged.connect(self._scrolled)
        self.readout = QLabel(" ")
        self.readout.setStyleSheet("font-family: monospace;")

        self.cmb_view = QComboBox()
        self.cmb_view.addItem("Text / code", "text")
        self.cmb_view.addItem("Hex dump", "hex")
        self.cmb_view.setToolTip("Text / code wraps lines naturally; Hex shows 16-byte rows and ASCII.")
        self.cmb_view.currentIndexChanged.connect(lambda _i: self._render_inspector())

        self.hex_head = QLabel("")
        head_row = QHBoxLayout()
        head_row.setContentsMargins(0, 0, 0, 0)
        head_row.addWidget(self.hex_head, 1)
        head_row.addWidget(self.cmb_view)

        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.hex.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.hex.setPlaceholderText("Click a point on the plot to see its bytes here.")

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(self.overview)
        lv.addWidget(self.plot_w)
        lv.addWidget(self.bar)
        lv.addWidget(self.readout)
        lv.addLayout(head_row)
        lv.addWidget(self.hex, 1)

        # ---- flagged runs
        self.lst = QListWidget()
        self.lst.setToolTip("Runs of blocks above the threshold. Click to jump there.")
        self.lst.itemClicked.connect(lambda it: self._jump_region(self.lst.row(it)))
        self.lbl_runs = QLabel("Flagged runs")
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(8, 0, 0, 0)
        rv.addWidget(self.lbl_runs)
        rv.addWidget(self.lst, 1)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 0)

        self.status = QLabel("")
        self.status.setWordWrap(True)

        # Shown only while a file is being read. A big file can take a while, and without this the tab
        # just looks stuck. Busy (moving) until the first chunk is in, then a real percentage.
        self.prog = QProgressBar()
        self.prog.setFixedSize(240, 16)
        self.prog.setRange(0, 0)
        self.prog.setFormat("%p%")
        self.prog.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.prog.setToolTip("Reading the file to measure its entropy.")
        self.prog.hide()
        status_row = QHBoxLayout()
        status_row.setContentsMargins(0, 0, 0, 0)
        status_row.addWidget(self.status, 1)
        status_row.addWidget(self.prog)

        v = QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        v.addLayout(bar)
        v.addWidget(split, 1)
        v.addLayout(status_row)

    # ---------- theme
    def _colors(self) -> dict[str, QColor]:
        t = self.theme.color
        return {
            "bg": self.palette().base().color(),
            "ink": t("on_surface"),
            "muted": t("on_surface_variant"),
            "grid": t("outline"),
            "trace": t("warn"),
            "flag": t("error"),
        }

    def refresh_theme(self):
        self.plot_w.update()
        self.overview.update()

    # ---------- game link
    def set_game(self, g):
        """Load candidate files for the selected game and auto-plot the top match.

        The main window calls this on every reload (a game starting, finishing, a setting changing), not only
        when the selection changes. Doing the work each time would throw away the file you picked and re-plot
        it, so the same game is left alone: its list is refreshed when you open the file picker."""
        new_dir = Path(g.path) if g is not None else None
        if new_dir is not None and new_dir == self.game_dir:
            return
        for w in list(self._jobs):                   # a plot of the previous game's file is stale now
            w.requestInterruption()
        self._token += 1
        self._reading(False)
        self.game_dir = new_dir
        self._pending_auto_plot = False
        self._auto_source = None
        self._user_picked = False
        self.an = None
        self.regions = []
        self.plot_w.an = None
        self.plot_w.sel = -1
        self.plot_w.update()
        self.overview.set_data(None, self.spn_thr.value())
        self.btn_next.setEnabled(False)
        self.btn_auto.setEnabled(False)
        self.lbl_size.setText("")
        self._last_data, self._last_off = b"", 0
        self.hex.setPlainText("")
        self.readout.setText("")
        if self.game_dir is None:
            self.candidates = []
            self._set_file_label(None)
            self.path = None
            self.btn_plot.setEnabled(False)
            self.status.setText("Select a game or open a file to plot entropy.")
            return
        self.path = None
        self._reload_game_files(auto_plot=True)

    def showEvent(self, e):  # noqa: N802
        super().showEvent(e)
        if self._pending_auto_plot and self.path:
            self._pending_auto_plot = False
            self.plot()

    def _refresh_candidates(self) -> list[E.CandidateFile]:
        """Re-list the game's files in the current sort order. Changes the list only, never the selection."""
        if self.game_dir is None:
            self.candidates = []
            return self.candidates
        self.candidates = E.discover_game_files(self.game_dir, include_prefix=self.chk_prefix.isChecked(),
                                                sort=self.cmb_sort.currentData())
        return self.candidates

    def _auto_pick(self, items):
        """The file to select on its own: the first in the current order that matches the programs filter."""
        if not self._binaries_only:
            return items[0] if items else None
        return next((c for c in items if Path(c.rel).suffix.lower() in _BINARY_EXTS), None)

    def _reload_game_files(self, auto_plot: bool = False, keep_current: bool = False):
        """Re-list the game's files and, unless the person chose a file, select the top one.

        keep_current: a file the person chose is never replaced here, even if it is no longer listed.
        An auto-selected file is re-picked when the sort or the installed-files filter changes."""
        if self.game_dir is None:
            return
        items = self._refresh_candidates()
        if keep_current and self._user_picked and self.path:
            return
        if items and keep_current and self.an is not None and self.an.path == str(items[0].path):
            return                               # the top file is already the one plotted: nothing to do
        if not items:
            if not keep_current:
                self.path = None                 # never keep a file of another game behind an empty list
                self._set_file_label(None)
            self.btn_plot.setEnabled(bool(self.path))
            self.status.setText(f"No readable files found under {self.game_dir}.")
            return
        top = self._auto_pick(items)
        if top is None:                          # programs-only filter on, and nothing in the list is a program
            top = items[0]
        if self.an is not None and self.an.path == str(top.path) and keep_current:
            return                               # already the file on screen
        self._set_file_label(top.path, top.size)
        self.path = str(top.path)
        self.btn_plot.setEnabled(True)
        if auto_plot:
            if self.isVisible():
                self.plot()
            else:
                self._pending_auto_plot = True

    def _set_file_label(self, path, size: int | None = None):
        """Show the picked file as 'name  (size)', elided in the middle; full path goes in the tooltip."""
        if not path:
            self._file_full = ""
            self.btn_file.setText("No file selected")
            self.btn_file.setToolTip("Click to search the files found in the selected game.")
            return
        self._file_full = str(path)
        if size is None:
            try:
                size = Path(path).stat().st_size
            except OSError:
                size = 0
        self._elide_file_btn(size)
        self.btn_file.setToolTip(f"{path}\n\nClick to search other files.")

    def _elide_file_btn(self, size: int = 0):
        name = Path(self._file_full).name
        text = f"{name}  ({_fmt_size(size)})" if size else name
        fm = self.btn_file.fontMetrics()
        self.btn_file.setText(fm.elidedText(text, Qt.TextElideMode.ElideMiddle, max(self.btn_file.width() - 24, 80)))
        self._file_text_full = text

    def resizeEvent(self, e):  # noqa: N802
        super().resizeEvent(e)
        if self._file_full:
            fm = self.btn_file.fontMetrics()
            self.btn_file.setText(fm.elidedText(getattr(self, "_file_text_full", ""),
                                                Qt.TextElideMode.ElideMiddle, max(self.btn_file.width() - 24, 80)))

    def _pick_file(self):
        self._refresh_candidates()           # pick up files a run just created; the selection stays as it is
        if not self.candidates:
            self._open()
            return
        dlg = _FilePicker(self.candidates, self._file_full, self._binaries_only, self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.chosen:
            self._binaries_only = dlg.binaries_only
            self._user_picked = True
            self.path = dlg.chosen
            c = next((c for c in self.candidates if str(c.path) == dlg.chosen), None)
            self._set_file_label(dlg.chosen, c.size if c else None)
            self.btn_plot.setEnabled(True)
            self.plot()
        else:
            self._binaries_only = dlg.binaries_only

    def shutdown(self):
        for w in list(self._jobs):
            w.requestInterruption()
        for w in list(self._jobs):
            w.wait(3000)

    # ---------- loading and analysis
    def _open(self):
        start = str(self.game_dir) if self.game_dir and self.game_dir.is_dir() else str(Path.home())
        path, _ = QFileDialog.getOpenFileName(self, "Open file", start)
        if path and Path(path).is_symlink():
            self.status.setText("That is a symlink. Open the file it points to instead: links are never followed here.")
        elif path:
            self._user_picked = True
            self.path = path
            self._set_file_label(path)
            self.btn_plot.setEnabled(True)
            self.plot()

    @staticmethod
    def _cache_key(path: str, block: int) -> tuple | None:
        """Identity of an analysis: the file's size and modification time, and the block size."""
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (str(path), block, st.st_mtime_ns, st.st_size)

    def plot(self):
        if not self.path:
            return
        self._pending_auto_plot = False
        self._token += 1
        for w in list(self._jobs):           # stop any earlier analysis; its result would be stale
            w.requestInterruption()
        block = self.cmb_block.currentData()
        key = self._cache_key(self.path, block)
        if key is not None and self._cache is not None and self._cache[0] == key:
            self._done(self._token, self._cache[1])   # same file, same block size, unchanged: no need to read it again
            return
        w = _Worker(self._token, self.path, block, self)
        w.progress.connect(self._progress)     # bound methods of this widget: always run on the GUI thread
        w.done.connect(self._done)
        w.failed.connect(self._failed)
        w.finished.connect(self._reap)
        self._jobs.add(w)
        self._reading(True)
        self.btn_plot.setEnabled(False)
        self.btn_auto.setEnabled(False)
        w.start()

    def _reap(self):
        for w in [w for w in self._jobs if w.isFinished()]:
            self._jobs.discard(w)
            w.deleteLater()

    def _reading(self, on: bool):
        """Show or hide the read-progress bar. On: busy until the first chunk reports in."""
        if on:
            self._read_name = Path(self.path).name if self.path else ""
            self.prog.setRange(0, 0)
            self.status.setText(f"Reading {self._read_name}…" if self._read_name else "Reading…")
        self.prog.setVisible(on)

    def _progress(self, token: int, done: int, total: int):
        if token != self._token or not total:
            return
        pct = min(100, 100 * done // total)
        if self.prog.maximum() == 0:                 # first report: switch from busy to a real percentage
            self.prog.setRange(0, 100)
        self.prog.setValue(pct)
        name = getattr(self, "_read_name", "")
        self.status.setText(f"Reading {name}… {_fmt_size(done)} of {_fmt_size(total)}" if name
                            else f"Reading… {pct}%")

    def _auto_threshold(self):
        if self.an is None or not self.an.ent:
            return
        val = E.suggest_threshold(self.an.ent, E.DEFAULT_THRESHOLD)
        self.spn_thr.setValue(val)

    def _done(self, token: int, an: E.Analysis):
        if token != self._token:
            return
        self._reading(False)
        prev = self.an
        self._cache = (self._cache_key(an.path, an.block), an)
        self.an = an
        new_file = an.path != self._auto_source
        self._auto_source = an.path
        self.btn_plot.setEnabled(True)
        self.btn_auto.setEnabled(bool(an.ent))
        self.lbl_size.setText(f"{an.size:,} bytes · {an.blocks:,} blocks")
        # The auto threshold and the jump to the first flagged run belong to a file's first plot. A re-plot
        # (another block size, or Plot again) keeps the threshold the user set and where they were looking.
        if new_file:
            self._auto_threshold()
        self.plot_w.an = an
        self.plot_w.thr = self.spn_thr.value()
        self.overview.set_data(an, self.spn_thr.value())
        if new_file:
            self.bar.setValue(0)             # a new file starts at its beginning
            self.plot_w.offset = 0
            self.plot_w.sel = -1
        elif prev is None or prev.block != an.block:
            self.plot_w.sel = -1             # block numbers changed meaning: drop the old selection
        self._refresh_regions()
        self.btn_next.setEnabled(bool(self.regions))
        self._sync_scroll()
        if new_file and self.regions:
            self._select(self.regions[0].first)
            self._center_on(self.regions[0].first)
        self.plot_w.update()

    def _failed(self, token: int, msg: str):
        if token != self._token:
            return
        self._reading(False)
        self.btn_plot.setEnabled(True)
        self.btn_auto.setEnabled(self.an is not None and bool(self.an.ent))
        self.status.setText(f"Could not read that file: {msg}")

    def _thr_changed(self, _v: float):
        if self.an is None:
            return
        self.plot_w.thr = self.spn_thr.value()
        self.overview.set_data(self.an, self.spn_thr.value())
        self._refresh_regions()
        self.btn_next.setEnabled(bool(self.regions))
        self.plot_w.update()

    def _refresh_regions(self):
        if self.an is None:
            self.regions = []
        else:
            self.regions = E.flag_runs(self.an.ent, self.spn_thr.value(), self.an.block, self.an.size)
        self.lst.clear()
        for r in self.regions[:500]:
            self.lst.addItem(f"{_hex(r.offset)}   {r.length:,} bytes   avg {r.avg:.2f}")
        more = f" (showing 500)" if len(self.regions) > 500 else ""
        self.lbl_runs.setText(f"Flagged runs: {len(self.regions)}{more}")
        if self.an is not None:
            self.status.setText(f"{self.an.blocks:,} blocks · {len(self.regions)} flagged run"
                                f"{'' if len(self.regions) == 1 else 's'} at {self.spn_thr.value():.1f}+")

    # ---------- scrolling
    def _zoom_changed(self, _i: int):
        new_zoom = int(self.cmb_zoom.currentData())
        if self.an is None or self.an.blocks == 0:
            self.plot_w.zoom = new_zoom
            self._sync_scroll()
            return
        old_step = self.plot_w._step()
        centre = (self.plot_w.offset + self.plot_w.width() / 2.0 - GUT) / max(old_step, 1.0)
        centre = max(0.0, min(float(self.an.blocks - 1), centre))
        self.plot_w.zoom = new_zoom
        self._sync_scroll()
        self._center_on(round(centre))

    def _sync_scroll(self):
        W = self.plot_w.width()
        total = self.plot_w.content_width()
        step = self.plot_w._step()
        self.bar.blockSignals(True)
        self.bar.setRange(0, max(0, total - W))
        self.bar.setPageStep(max(1, W))
        self.bar.setSingleStep(max(4, int(round(step * 4))))
        self.bar.blockSignals(False)
        self._scrolled(self.bar.value())

    def _scrolled(self, value: int):
        self.plot_w.offset = value
        if self.an is not None and self.an.blocks > 0:
            step = self.plot_w._step()
            first = max(0, int(value // step))
            end = min(self.an.blocks, int((value + self.plot_w.width()) // step) + 1)
            self.overview.set_view(first, end)
        else:
            self.overview.set_view(0, 0)
        self.plot_w.update()

    def _center_on(self, block: int):
        if self.an is None or self.an.blocks == 0:
            return
        step = self.plot_w._step()
        target = GUT + (block + 0.5) * step - self.plot_w.width() / 2.0
        self.bar.setValue(int(round(target)))

    def _jump_region(self, row: int):
        if 0 <= row < len(self.regions):
            r = self.regions[row]
            self._center_on(r.first + (r.end - r.first) // 2)
            self._select(r.first)

    def _next_flagged(self):
        if not self.regions:
            return
        cur = self.plot_w.sel
        nxt = next((r for r in self.regions if r.first > cur), self.regions[0])
        self._center_on(nxt.first)
        self._select(nxt.first)

    # ---------- inspection
    def _describe(self, b: int) -> str:
        return (f"{_hex(b * self.an.block)} · block {b:,} · {self.an.ent[b]:.2f} bits/byte · "
                f"{round(self.an.printable[b] * 100)}% printable")

    def _hover(self, b: int):
        if self.an is None or not (0 <= b < self.an.blocks):
            if self.an is not None and 0 <= self.plot_w.sel < self.an.blocks:
                self.readout.setText(self._describe(self.plot_w.sel))
            else:
                self.readout.setText(" ")
            return
        self.readout.setText(self._describe(b))

    def _render_inspector(self):
        if not self._last_data:
            return
        mode = self.cmb_view.currentData()
        if mode == "hex":
            self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            self.hex.setPlainText(E.hexdump(self._last_data, self._last_off))
        else:
            self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            self.hex.setPlainText(_decode_text(self._last_data))
        self.hex.verticalScrollBar().setValue(0)
        shown = "first 512 bytes" if len(self._last_data) == E.HEX_BYTES else "to the end of the file"
        label = "Hex dump" if mode == "hex" else "Text / code"
        self.hex_head.setText(f"{label} at {_hex(self._last_off)}, {shown}")

    def _select(self, b: int):
        if self.an is None or not (0 <= b < self.an.blocks):
            return
        self.plot_w.sel = b
        self.plot_w.update()
        self.readout.setText(self._describe(b))
        off = b * self.an.block
        try:
            data = E.read_bytes(self.an.path, off, E.HEX_BYTES)
        except OSError as e:
            self._last_data = b""
            self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            self.hex.setPlainText(f"Could not read the file again: {e}")
            return
        self._last_data = data
        self._last_off = off
        self._render_inspector()
