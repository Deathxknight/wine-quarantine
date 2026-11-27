"""X-Ray tab for wq-ui: a treemap of a game's writable folders, coloured by what the last run did.

green  = was already there when the baseline was taken
amber  = was there, but its size or date changed
red    = did not exist at the baseline

"Show sandbox access" lays what the profile lets the game do over those colours: hatched = read-only,
cross-hatched with a dashed edge = hidden from the game, a corner mark = a folder holding both kinds.
New or changed programs (Windows .exe/.dll, Linux ELF files, scripts, launchers) get a heavy frame and a label;
a dotted fill means the program looks packed or encrypted. Whitelisted folders and files outside the game folder (Paths tab: Add folder / Add file) get a tile of their own,
so what a game writes there is tracked too. Other places the profile blacklists, or whitelists but that are too
broad to scan, are listed under the map.

The baseline is a file list (path, size, mtime) saved under ~/.cache/wq-ui/xray/ just before each launch.
Scanning runs in a worker thread; the Qt-free logic lives in wq_xray_core.py.
"""
from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPen, QPolygonF, QTextOption
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QSlider, QVBoxLayout,
                               QWidget)

import wq_xray_core as core


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _mix(a: QColor, b: QColor, t: float) -> QColor:
    return QColor(round(a.red() * (1 - t) + b.red() * t), round(a.green() * (1 - t) + b.green() * t),
                  round(a.blue() * (1 - t) + b.blue() * t))


class _SnapThread(QThread):
    """Walks the game folders (and the profile's extra whitelisted paths); optionally saves the result as the baseline."""
    done = Signal(int, object)        # token, snapshot; connected to a bound method so it is delivered on the GUI thread

    def __init__(self, root: Path, token: int, save_to: Path | None, extra: dict | None = None, parent=None):
        super().__init__(parent)
        self.root, self.token, self.save_to, self.extra = root, token, save_to, dict(extra or {})

    def run(self):
        snap = core.snapshot(self.root, stop=self.isInterruptionRequested, extra=self.extra)
        if self.save_to is not None and not self.isInterruptionRequested():
            try:
                core.save_baseline(self.save_to, snap, tops=list(core.SCAN_DIRS) + list(self.extra))
            except OSError:
                pass            # no baseline is better than blocking the launch
        self.done.emit(self.token, snap)


class _SniffThread(QThread):
    """Looks at the first bytes of the new and modified files to find the programs among them."""
    done = Signal(int, object)        # token, {path: (kind, packed)}

    def __init__(self, root: Path, status: dict, extra: dict, token: int, parent=None):
        super().__init__(parent)
        self.root, self.status, self.extra, self.token = root, dict(status), dict(extra), token

    def run(self):
        kinds = core.sniff_changed(self.root, self.status, self.extra, stop=self.isInterruptionRequested)
        if not self.isInterruptionRequested():
            self.done.emit(self.token, kinds)


class TreemapView(QWidget):
    hovered = Signal(object)      # core.Node | None
    zoomed = Signal(object)       # core.Node now shown

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.root: core.Node | None = None
        self.zoom: core.Node | None = None
        self.boost = True
        self.power = core.BOOST       # tile area ~ size**power while boost is on
        self.cap = 1.0                # no tile may take more than this share of its folder (1.0 = off)
        self.access = True            # draw the sandbox-access overlay
        self.empty_text = ""
        self._tiles: list[core.Tile] = []
        self._key = None
        self._hover: core.Node | None = None
        self.setMouseTracking(True)
        self.setMinimumHeight(260)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    # ---- state
    def set_tree(self, root: core.Node | None):
        self.root = self.zoom = root
        self._hover = None
        self._key = None
        self.update()

    def set_scale(self, power: float, cap: float):
        """power 0..1 (0 = all tiles equal, 1 = true proportions); cap 0..1 share of a folder one tile may take."""
        self.power = min(1.0, max(0.0, power))
        self.boost = self.power < 1.0
        self.cap = min(1.0, max(0.0, cap))
        self._key = None
        self.update()

    def set_access(self, on: bool):
        self.access = on
        self._key = None              # tiles that carry a sandbox rule get a minimum size, so the layout changes
        self.update()

    def set_zoom(self, node: core.Node | None):
        if node is None or not node.kids:
            return
        self.zoom = node
        self._key = None
        self._hover = None
        self.hovered.emit(None)
        self.zoomed.emit(node)
        self.update()

    def up(self):
        if self.zoom is not None and self.zoom.parent is not None:
            self.set_zoom(self.zoom.parent)

    def tiles(self) -> list[core.Tile]:
        if self.zoom is None or self.width() < 8 or self.height() < 8:
            return []
        key = (self.width(), self.height(), id(self.zoom), self.boost, self.power, self.cap, self.access)
        if key != self._key:
            self._tiles = core.layout(self.zoom, self.width(), self.height(), boost=self.boost, pins=self.access,
                                      power=self.power, cap=self.cap)
            self._key = key
        return self._tiles

    # ---- painting
    def paintEvent(self, _e):  # noqa: N802  (Qt override)
        th = self.theme.color
        p = QPainter(self)
        p.fillRect(self.rect(), th("surface"))
        tiles = self.tiles()
        if not tiles:
            p.setPen(th("on_surface_variant"))
            opt = QTextOption(Qt.AlignmentFlag.AlignCenter)
            opt.setWrapMode(QTextOption.WrapMode.WordWrap)
            p.drawText(QRectF(self.rect()).adjusted(20, 0, -20, 0), self.empty_text, opt)
            return
        surface, panel = th("surface"), th("surface_container")
        col = {"new": th("error"), "mod": th("warn"), "old": th("ok")}
        light, dark = QColor("#f4f6f8"), QColor("#101418")
        ink = th("on_surface")
        fm = p.fontMetrics()
        for t in tiles:
            n = t.node
            r = QRectF(t.x, t.y, t.w, t.h).adjusted(0.5, 0.5, -0.5, -0.5)
            c = col[n.status]
            acc = core.uniform_access(n) if self.access else "rw"
            if t.inner:                                     # folder with its children drawn inside
                fill, edge = _mix(panel, col["old"], 0.10), (c if n.status != "old" else th("outline"))
            elif n.is_dir:                                  # folder too small to open: show its worst status
                fill, edge = _mix(panel, c, 0.30 if n.status == "old" else 0.55), surface
            else:                                           # a file (or a "…N more" group)
                fill, edge = _mix(panel, c, {"old": 0.32, "mod": 0.78, "new": 0.90}[n.status]), surface
            p.fillRect(r, fill)
            if acc == "ro":                                 # sandbox overlay: hatched = the game can only read it
                p.fillRect(r, QBrush(QColor(ink.red(), ink.green(), ink.blue(), 85), Qt.BrushStyle.BDiagPattern))
            elif acc == "hidden":                           # cross-hatched, dashed edge = the game cannot see it
                p.fillRect(r, QBrush(QColor(ink.red(), ink.green(), ink.blue(), 140), Qt.BrushStyle.DiagCrossPattern))
            pen = QPen(edge, 1)
            if acc == "hidden":
                pen.setStyle(Qt.PenStyle.DashLine)
            p.setPen(pen)
            p.drawRect(r)
            if acc == "mixed" and t.w > 14 and t.h > 14:    # a folder holding both kinds: corner mark, details on hover
                sz = min(10.0, t.w / 3, t.h / 3)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QBrush(ink))
                p.drawPolygon(QPolygonF([QPointF(t.x + t.w - sz, t.y), QPointF(t.x + t.w - 1, t.y),
                                         QPointF(t.x + t.w - 1, t.y + sz)]))
                p.setBrush(Qt.BrushStyle.NoBrush)
            if n.status == "new" and not t.inner:           # a second ring so red stands out in a sea of green
                p.setPen(QPen(c, 1))
                p.drawRect(r.adjusted(1, 1, -1, -1))
            if n.kind and n.status != "old" and not n.is_dir and not t.inner:   # a program: heavy frame
                if n.packed:                                # dotted fill: looks packed or encrypted
                    p.fillRect(r, QBrush(QColor(ink.red(), ink.green(), ink.blue(), 95), Qt.BrushStyle.Dense5Pattern))
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(c, 3))
                p.drawRect(r.adjusted(1.5, 1.5, -1.5, -1.5))
            if t.w > 44 and t.h > 15:
                text = n.name
                if t.w > 130:
                    text += f"  {core.fmt_size(n.size)}"
                if acc in ("ro", "hidden") and t.w > 170:
                    text += "  [read-only]" if acc == "ro" else "  [hidden]"
                if n.is_dir and (n.new or n.mod) and t.w > 200:
                    text += f"  ● {n.new} new" if n.new else f"  ● {n.mod} changed"
                if n.kind and n.status != "old" and t.w > 110:
                    text += f"  [{core.kind_label(n)}]"
                elif n.is_dir and n.progs and t.w > 260:
                    text += f"  ▲ {n.progs} program{'' if n.progs == 1 else 's'}"
                p.setPen(th("on_surface") if t.inner or n.status == "old" else (dark if fill.lightness() > 128 else light))
                p.drawText(QRectF(t.x + 4, t.y, t.w - 8, 16 if t.inner else t.h),
                           fm.elidedText(text, Qt.TextElideMode.ElideRight, int(t.w - 8)), QTextOption(Qt.AlignmentFlag.AlignVCenter))
        if self._hover is not None:
            for t in tiles:
                if t.node is self._hover:
                    p.setPen(QPen(th("on_surface"), 2))
                    p.setBrush(Qt.BrushStyle.NoBrush)
                    p.drawRect(QRectF(t.x + 1, t.y + 1, t.w - 2, t.h - 2))
                    break

    # ---- mouse / keys
    def mouseMoveEvent(self, e):  # noqa: N802
        t = core.tile_at(self.tiles(), e.position().x(), e.position().y())
        n = t.node if t else None
        if n is not self._hover:
            self._hover = n
            self.setCursor(Qt.CursorShape.PointingHandCursor if n is not None and n.kids else Qt.CursorShape.ArrowCursor)
            self.hovered.emit(n)
            self.update()

    def leaveEvent(self, _e):  # noqa: N802
        if self._hover is not None:
            self._hover = None
            self.hovered.emit(None)
            self.update()

    def mousePressEvent(self, e):  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            t = core.tile_at(self.tiles(), e.position().x(), e.position().y())
            if t is not None:
                self.set_zoom(t.node)
        elif e.button() in (Qt.MouseButton.RightButton, Qt.MouseButton.BackButton):
            self.up()

    def keyPressEvent(self, e):  # noqa: N802
        if e.key() in (Qt.Key.Key_Backspace, Qt.Key.Key_Escape):
            self.up()
        else:
            super().keyPressEvent(e)


class XRayTab(QWidget):
    changed = Signal(int, int)        # (new, modified) found by the latest scan

    def __init__(self, theme, settings, cache_dir: Path):
        super().__init__()
        self.theme, self.settings, self.cache_dir = theme, settings, Path(cache_dir)
        self.game = None
        self.base: core.Snap | None = None
        self.base_tops: frozenset[str] = frozenset()   # top-level folders the baseline covered
        self.base_time = 0.0
        self.now: core.Snap = {}
        self.status: dict[str, str] = {}
        self.gone: list[str] = []
        self.kinds: dict[str, tuple[str, bool]] = {}   # new/modified files that are programs (see core.sniff_changed)
        self._sniff_token = 0
        self.root: core.Node | None = None
        self.policy: core.Policy | None = None     # what the profile lets the game do (see core.build_policy)
        self._token = 0
        self._dirty = False
        self._scanning = False
        self._scan_thread: _SnapThread | None = None
        self._threads: set[_SnapThread] = set()
        self._jobs: dict[int, tuple] = {}          # token -> (game, save, then, tops scanned)
        self._trail: list[core.Node] = []

        v = QVBoxLayout(self)
        v.setContentsMargins(12, 12, 12, 12)
        head = QHBoxLayout()
        self.title = QLabel("Files this game changed")
        head.addWidget(self.title, 1)
        self.chk_auto = QCheckBox("Snapshot before each launch")
        self.chk_auto.setToolTip("Takes the baseline just before launch, so red and amber show what that run did.\n"
                                 "Untick for huge game folders if the pause is annoying.")
        self.chk_auto.setChecked(bool(settings.data.get("xray_auto", True)))
        self.chk_auto.toggled.connect(lambda on: settings.data.__setitem__("xray_auto", bool(on)))
        # tile sizing: how much a file's size counts for its tile's area, and how much one tile may take
        pw = settings.data.get("xray_power")
        if pw is None:                                   # settings written before the slider existed
            pw = 35 if settings.data.get("xray_boost", True) else 100
        self.lbl_power = QLabel("Size ratio")
        self.sld_power = QSlider(Qt.Orientation.Horizontal)
        self.sld_power.setRange(0, 100)
        self.sld_power.setFixedWidth(150)
        self.sld_power.setValue(max(0, min(100, int(pw))))
        self.sld_power.setToolTip("How much file size counts for tile area.\n"
                                  "0 = equal tiles, 35 = default, 100 = true proportions.\n"
                                  "Double-click to reset.")
        self.sld_power.valueChanged.connect(self._scale_changed)
        self.sld_power.mouseDoubleClickEvent = lambda e: self.sld_power.setValue(35)
        self.val_power = QLabel("")
        self.val_power.setMinimumWidth(46)
        self.val_power.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.lbl_cap = QLabel("Max tile share")
        self.sld_cap = QSlider(Qt.Orientation.Horizontal)
        self.sld_cap.setRange(5, 100)
        self.sld_cap.setFixedWidth(150)
        self.sld_cap.setValue(max(5, min(100, int(settings.data.get("xray_cap", 100)))))
        self.sld_cap.setToolTip("Largest share of a folder one tile can take, so a huge file doesn't squash the rest.\n"
                                "100% = off. Double-click to switch off.")
        self.sld_cap.valueChanged.connect(self._scale_changed)
        self.sld_cap.mouseDoubleClickEvent = lambda e: self.sld_cap.setValue(100)
        self.val_cap = QLabel("")
        self.val_cap.setMinimumWidth(46)
        self.val_cap.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.chk_access = QCheckBox("Show sandbox access")
        self.chk_access.setToolTip("Overlays the profile: hatched = read-only, cross-hatched = hidden, corner mark = both in one folder.\n"
                                   "Modelled from game.conf and the default profile, not read from a running sandbox.")
        self.chk_access.setChecked(bool(settings.data.get("xray_access", True)))
        self.chk_access.toggled.connect(self._access_toggled)
        self.btn_scan = QPushButton("Rescan")
        self.btn_scan.clicked.connect(self.rescan)
        self.btn_base = QPushButton("Set baseline now")
        self.btn_base.setToolTip("Treat everything that exists now as existing (green). Later changes show as red or amber.")
        self.btn_base.clicked.connect(self._set_baseline_now)
        for w in (self.btn_scan, self.btn_base):
            head.addWidget(w)
        v.addLayout(head)
        toggles = QHBoxLayout()
        toggles.addWidget(self.chk_auto)
        toggles.addWidget(self.chk_access)
        toggles.addStretch(1)
        v.addLayout(toggles)
        scale = QHBoxLayout()
        scale.setSpacing(8)
        scale.addStretch(1)
        for w in (self.lbl_power, self.sld_power, self.val_power, self.lbl_cap, self.sld_cap, self.val_cap):
            scale.addWidget(w)
        v.addLayout(scale)

        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(self.summary)
        self.crumbs = QLabel("")
        self.crumbs.setTextFormat(Qt.TextFormat.RichText)
        self.crumbs.linkActivated.connect(self._crumb_clicked)
        v.addWidget(self.crumbs)

        self.view = TreemapView(theme)
        self.view.hovered.connect(self._show_info)
        self.view.zoomed.connect(self._set_trail)
        v.addWidget(self.view, 1)

        self.info = QLabel("")
        self.info.setWordWrap(True)
        self.info.setTextFormat(Qt.TextFormat.RichText)
        self.info.setMinimumHeight(56)
        v.addWidget(self.info)
        self.reach = QLabel("")
        self.reach.setWordWrap(True)
        self.reach.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(self.reach)
        self.legend = QLabel("")
        self.legend.setTextFormat(Qt.TextFormat.RichText)
        self.legend.setWordWrap(True)
        v.addWidget(self.legend)
        self._scale_changed()
        self.view.set_access(self.chk_access.isChecked())
        self._refresh_texts()

    # ------------------------------------------------------------ public API (called by MainWindow)
    @property
    def auto_baseline(self) -> bool:
        return self.chk_auto.isChecked()

    def set_game(self, g):
        if g is None and self.game is None:
            return
        if g is not None and self.game is not None and g.path == self.game.path:
            return
        self.game = g
        self._scanning = False       # a scan of the previous game may still be running; its result is ignored, so it must not keep us "Scanning…"
        self.now, self.status, self.gone, self.root, self.policy = {}, {}, [], None, None
        self.kinds = {}
        self._sniff_token += 1                    # a sniff still running for the previous game is ignored
        self.base, self.base_time, self.base_tops = (
            core.load_baseline_info(core.baseline_path(self.cache_dir, g.path)) if g is not None
            else (None, 0.0, frozenset()))
        self.view.set_tree(None)
        self._set_trail(None)
        self._refresh_texts()
        if g is None:
            self._dirty = False
        elif self.isVisible():
            self.rescan()
        else:
            self._dirty = True

    def baseline_for(self, g, then):
        """Take the baseline for g in the background, then call then() (also if it failed)."""
        self._start(g, save=True, then=then)

    def run_finished(self, g):
        if self.game is not None and g.path == self.game.path:
            # the launcher may have replaced the baseline while the game ran (taken once Wine had populated
            # the prefix), so read it again instead of comparing with the copy held in memory
            base, t, tops = core.load_baseline_info(core.baseline_path(self.cache_dir, g.path))
            if base is not None:
                self.base, self.base_time, self.base_tops = base, t, tops
            self.rescan()

    def refresh_theme(self):
        self._refresh_texts()
        self.view.update()

    def shutdown(self):
        for th in list(self._threads):
            th.requestInterruption()
        for th in list(self._threads):
            th.wait(3000)

    # ------------------------------------------------------------ scanning
    def showEvent(self, e):  # noqa: N802
        super().showEvent(e)
        if self._dirty:
            self.rescan()
        else:
            self._sync_policy()

    def _load_policy(self) -> core.Policy | None:
        if self.game is None:
            return None
        try:
            return core.load_policy(self.game.path)
        except (OSError, KeyError):
            return None

    def _sync_policy(self):
        """The profile may have been saved while this tab was hidden: redo the overlay from the last scan."""
        if self.game is None or not self.now or self._scanning:
            return
        pol = self._load_policy()
        if (pol.signature() if pol else None) != (self.policy.signature() if self.policy else None):
            if (pol.extra_tops if pol else {}) != (self.policy.extra_tops if self.policy else {}):
                self.rescan()           # a folder was added or removed in the Paths tab: its files are not in the last scan
                return
            self.policy = pol
            self._rebuild()

    def rescan(self, *_):
        if self.game is None:
            return
        self._dirty = False
        # The launcher replaces the baseline once Wine has populated a fresh prefix, while the game is
        # still starting, so always compare with the file on disk, not the copy held in memory.
        base, t, tops = core.load_baseline_info(core.baseline_path(self.cache_dir, self.game.path))
        if base is not None:
            self.base, self.base_time, self.base_tops = base, t, tops
        if self._scan_thread is not None:
            try:
                self._scan_thread.requestInterruption()
            except RuntimeError:        # already finished and deleted
                pass
        self._scanning = True
        self._refresh_texts()
        self._start(self.game, save=False, then=None)

    def _set_baseline_now(self):
        if self.game is not None:
            self._scanning = True
            self._refresh_texts()
            self._start(self.game, save=True, then=None)

    def _start(self, g, save: bool, then):
        self._token += 1
        tok = self._token
        pol = self._load_policy()
        extra = pol.extra_tops if pol is not None else {}
        self._jobs[tok] = (g, save, then, frozenset(core.SCAN_DIRS) | set(extra))
        th = _SnapThread(Path(g.path), tok, core.baseline_path(self.cache_dir, g.path) if save else None, extra, self)
        th.done.connect(self._on_done)          # bound method of this widget: always runs on the GUI thread
        th.finished.connect(self._reap)
        self._threads.add(th)
        if not save:
            self._scan_thread = th
        th.start()

    def _reap(self):
        for th in [t for t in self._threads if t.isFinished()]:
            self._threads.discard(th)
            if self._scan_thread is th:
                self._scan_thread = None
            th.deleteLater()

    def _on_done(self, tok: int, snap):
        job = self._jobs.pop(tok, None)
        if job is None:
            return
        g, save, then, tops = job
        current = self.game is not None and self.game.path == g.path
        if save:
            if current:
                self.base, self.base_time, self.base_tops = snap, time.time(), tops
                self._use(snap)
            if then is not None:
                then()
            return
        if tok != self._token or not current:
            return                                           # a newer scan or another game took over
        self._use(snap)
        self.changed.emit(*self._counts())

    def _use(self, snap):
        self._scanning = False
        self.now = snap
        self.status, self.gone = core.diff(self.base, snap, self.base_tops)
        self.policy = self._load_policy()
        self.kinds = {}
        self._rebuild()
        self._start_sniff()

    def _start_sniff(self):
        """Find the programs among the changed files in the background and mark them when done."""
        self._sniff_token += 1
        if self.game is None or not self.status:
            return
        extra = self.policy.extra_tops if self.policy is not None else {}
        th = _SniffThread(Path(self.game.path), self.status, extra, self._sniff_token, self)
        th.done.connect(self._on_sniffed)
        th.finished.connect(self._reap)
        self._threads.add(th)
        th.start()

    def _on_sniffed(self, tok: int, kinds):
        if tok != self._sniff_token or self.root is None:
            return
        self.kinds = kinds
        zoom = self.view.zoom.path if self.view.zoom is not None else ""
        self._rebuild()
        node = self.root
        for part in [x for x in zoom.split("/") if x]:         # stay where the user had zoomed to
            node = next((k for k in node.kids if k.name == part), None)
            if node is None:
                return
        if node is not self.root:
            self.view.set_zoom(node)

    def _rebuild(self):
        pol = self.policy
        self.root = core.build_tree(self.now, self.status, pins=core.pin_paths(pol), kinds=self.kinds)
        if pol is not None:
            core.apply_policy(self.root, pol)
        self.view.set_tree(self.root)
        self._set_trail(self.root)
        self._refresh_texts()

    def _counts(self) -> tuple[int, int]:
        s = core.summary(self.now, self.status, self.gone)
        return s["new"], s["mod"]

    # ------------------------------------------------------------ texts
    def _hex(self, key: str) -> str:
        return self.theme.color(key).name()

    def _refresh_texts(self):
        ok, warn, bad, mut = self._hex("ok"), self._hex("warn"), self._hex("error"), self._hex("on_surface_variant")
        self.legend.setText(f'<span style="color:{mut}">Click a tile to open it, right-click or Backspace to go up. &nbsp; '
                            f'<span style="color:{ok}">■</span> existing &nbsp; '
                            f'<span style="color:{warn}">■</span> modified &nbsp; '
                            f'<span style="color:{bad}">■</span> new &nbsp; ▣ program (heavy frame) &nbsp; ▦ looks packed'
                            + (" &nbsp; ▨ read-only &nbsp; ▩ hidden from the game &nbsp; ◥ folder with both"
                               if self.chk_access.isChecked() else "") + "</span>")
        self.btn_base.setEnabled(self.game is not None and not self._scanning)
        self.btn_scan.setEnabled(self.game is not None and not self._scanning)
        if self.game is None:
            self.title.setText("Files this game changed")
            self.summary.setText(f'<span style="color:{mut}">Select one game to see its files.</span>')
            self.view.empty_text = "Select one game."
            return
        self.title.setText(f"Files {self.game.name} changed")
        if self._scanning:
            self.summary.setText(f'<span style="color:{mut}">Scanning…</span>')
            self.view.empty_text = "Scanning…"
        elif self._dirty:
            self.summary.setText("")
        elif not self.now:
            self.summary.setText(f'<span style="color:{mut}">Nothing found in game/, prefix/, home/ or the whitelisted folders.</span>')
            self.view.empty_text = "This game has no files yet."
        elif self.base is None:
            self.summary.setText(f'<span style="color:{mut}">No baseline yet, so everything shows as existing. One is taken '
                                 f'just before the next launch, or press “Set baseline now”.</span>')
        else:
            s = core.summary(self.now, self.status, self.gone)
            ago = core.fmt_ago(time.time() - self.base_time) if self.base_time else "earlier"
            parts = [f'<b style="color:{bad if s["new"] else mut}">{s["new"]} new</b> ({core.fmt_size(s["new_bytes"])})',
                     f'<b style="color:{warn if s["mod"] else mut}">{s["mod"]} modified</b> ({core.fmt_size(s["mod_bytes"])})',
                     f'<span style="color:{mut}">{s["gone"]} removed</span>']
            pc = core.program_counts(self.kinds, self.status)
            if pc["new"] or pc["mod"]:
                n_prog = pc["new"] + pc["mod"]
                parts.insert(2, f'<b style="color:{bad if pc["new"] else warn}">▣ {n_prog} program{"" if n_prog == 1 else "s"}</b>'
                                + (f' <span style="color:{bad}">({pc["packed"]} look packed)</span>' if pc["packed"] else ""))
            self.summary.setText(" · ".join(parts) + f'<span style="color:{mut}"> &nbsp; since the baseline ({ago}) · '
                                 f'{s["files"]:,} files, {core.fmt_size(s["bytes"])}</span>')
            fresh = sorted(set(self.policy.extra_tops) - set(self.base_tops)) if self.policy is not None else []
            if fresh:
                self.summary.setText(self.summary.text() + f'<br><span style="color:{warn}">Not in the baseline yet, so '
                                     f'shown as existing: {_esc(", ".join(fresh))}. Press “Set baseline now” to start tracking '
                                     f'changes there.</span>')
        extra = self._access_summary()
        if extra and self.now and not self._scanning and not self._dirty:
            self.summary.setText(self.summary.text() + "<br>" + extra)
        self._refresh_reach()
        self.view.update()

    def _access_summary(self) -> str:
        if not self.chk_access.isChecked() or self.policy is None or self.root is None:
            return ""
        mut, warn = self._hex("on_surface_variant"), self._hex("warn")
        r = self.root
        bits = ([f"{r.n_ro:,} file{'' if r.n_ro == 1 else 's'} read-only"] if r.n_ro else []) \
            + ([f"{r.n_hid:,} hidden from the game"] if r.n_hid else [])
        out = (f'<span style="color:{mut}">Sandbox: ' + " · ".join(bits) + "</span>") if bits else \
            f'<span style="color:{mut}">Sandbox: everything on this map is read-write for the game.</span>'
        if r.n_bad:
            one = r.n_bad == 1
            out += (f' <b style="color:{warn}">⚠ {r.n_bad:,} changed file{"" if one else "s"} {"sits" if one else "sit"} where the profile '
                    f'does not let the game write</b><span style="color:{mut}"> (a host-side script, an installer outside the '
                    f'sandbox, or the profile changed since the run)</span>')
        return out

    def _refresh_reach(self):
        pol = self.policy
        text = ""
        if self.chk_access.isChecked() and pol is not None:
            mut, warn = self._hex("on_surface_variant"), self._hex("warn")
            parts = []
            for mode, paths, more in core.outside_summary(pol):
                label = {"rw": "writable", "ro": "read-only", "hide": "hidden", "noexec": "no-exec"}[mode]
                shown = ", ".join(_esc(x) for x in paths) + (f" (+{more} more)" if more else "")
                parts.append(f'<b style="color:{warn if mode == "rw" else mut}">{label}</b>: {shown}')
            if pol.notes:
                parts.append(f"{len(pol.notes)} entr{'y' if len(pol.notes) == 1 else 'ies'} ignored at launch (hover)")
            if parts:
                text = f'<span style="color:{mut}">Also in the profile, off this map &nbsp;—&nbsp; ' + " &nbsp;·&nbsp; ".join(parts) + "</span>"
        self.reach.setToolTip("\n".join(pol.notes) if pol is not None and pol.notes else "")
        self.reach.setText(text)
        self.reach.setVisible(bool(text))

    def _show_info(self, n):
        if n is None:
            self.info.setText("")
            return
        mut = self._hex("on_surface_variant")
        word = {"new": ("new", "error"), "mod": ("modified", "warn"), "old": ("existing", "ok")}[n.status]
        what = f"{n.files:,} files" if n.is_dir or n.more else "file"
        extra = ""
        if n.is_dir or n.more:
            bits = ([f"{n.new} new"] if n.new else []) + ([f"{n.mod} modified"] if n.mod else [])
            extra = f" · {', '.join(bits)}" if bits else ""
        path = (n.path or n.name).replace("&", "&amp;").replace("<", "&lt;")
        if n.kind and n.status != "old":
            what += f" · {core.kind_label(n)}" + (" (high entropy: packed, encrypted or compressed)" if n.packed else "")
        elif n.is_dir and n.progs:
            extra += f" · {n.progs} new or changed program{'' if n.progs == 1 else 's'}"
        acc = ""
        if self.chk_access.isChecked() and self.policy is not None and n.acc:
            kind, why = core.access_info(self.policy, n)
            label = {"rw": "read-write", "ro": "read-only", "hidden": "hidden from the game", "mixed": "mixed access"}[kind]
            acc = f'<br><b>sandbox: {label}</b>' + (f' <span style="color:{mut}">· {_esc(why)}</span>' if why else "")
        self.info.setText(f'<b style="color:{self._hex(word[1])}">{word[0]}</b> &nbsp; <b>{path}</b><br>'
                          f'<span style="color:{mut}">{core.fmt_size(n.size)} · {what}{extra}</span>{acc}')

    def _set_trail(self, node):
        self._trail = []
        n = node
        while n is not None:
            self._trail.insert(0, n)
            n = n.parent
        mut = self._hex("on_surface_variant")
        bits = []
        for i, t in enumerate(self._trail):
            nm = (t.name or "game folder").replace("&", "&amp;").replace("<", "&lt;")
            bits.append(nm if i == len(self._trail) - 1 else f'<a href="{i}">{nm}</a>')
        self.crumbs.setText(f'<span style="color:{mut}">' + " / ".join(bits) + "</span>" if bits else "")

    def _crumb_clicked(self, href: str):
        try:
            self.view.set_zoom(self._trail[int(href)])
        except (ValueError, IndexError):
            pass

    def _access_toggled(self, on: bool):
        self.settings.data["xray_access"] = bool(on)
        self.view.set_access(on)
        self.info.setText("")
        self._refresh_texts()

    def _scale_changed(self, *_):
        power, cap = self.sld_power.value(), self.sld_cap.value()
        self.settings.data["xray_power"] = power
        self.settings.data["xray_cap"] = cap
        self.val_power.setText("equal" if power == 0 else "true" if power == 100 else f"{power}%")
        self.val_cap.setText("off" if cap == 100 else f"{cap}%")
        self.view.set_scale(power / 100.0, cap / 100.0)
