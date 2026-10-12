#!/usr/bin/env python3
"""wq-ui - Qt front end for wine-quarantine.

Lists your quarantined games, shows where they live (and whether firejail's
--private will hide them), edits the per-game firejail profile, launches them
and shows what the sandbox blocked so you can whitelist it.

Needs PySide6.  Put this folder at <wine-quarantine>/wq-ui/ and run
    python3 wq-ui/integrate.py     (once)
    python3 wq-ui/wq_ui.py
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import sys
import time
from pathlib import Path

from PySide6.QtCore import (QFile, QFileSystemWatcher, QObject, QPointF, QProcess, QRectF, QSize, Qt, QTimer,
                            QUrl, Signal)
from PySide6.QtGui import (QAction, QBrush, QColor, QDesktopServices, QGuiApplication, QIcon, QImage,
                           QKeySequence, QPainter, QPainterPath, QPalette, QPen, QPixmap, QPolygonF)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSizePolicy, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget,
    QToolBar, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_core as core  # noqa: E402
import wq_debug  # noqa: E402
import wq_dialogs  # noqa: E402

APP_NAME = "wq-ui"
CONF_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / APP_NAME
SETTINGS_FILE = CONF_DIR / "settings.json"
DEFAULT_CSS = CONF_DIR / "style.css"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / APP_NAME
MARK = "wq-ui integration"

Checked, Unchecked, Partial = (Qt.CheckState.Checked, Qt.CheckState.Unchecked,
                               Qt.CheckState.PartiallyChecked)


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------
class Settings:
    DEFAULTS = {"qroot": "", "theme": "system", "css_enabled": True, "css_path": str(DEFAULT_CSS)}

    def __init__(self):
        self.data = dict(self.DEFAULTS)
        try:
            self.data.update(json.loads(SETTINGS_FILE.read_text()))
        except (OSError, ValueError):
            pass

    def save(self):
        CONF_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(self.data, indent=2))


# ---------------------------------------------------------------------------
# theme: built-in light/dark + user CSS that reloads when the file changes
# ---------------------------------------------------------------------------
class ThemeManager(QObject):
    changed = Signal()

    def __init__(self, app: QApplication, settings: Settings):
        super().__init__()
        self.app, self.settings = app, settings
        self.tokens = dict(core.DARK)
        self.mode = "dark"
        self._sys_palette = QPalette(app.palette())   # before we override it
        app.setStyle("Fusion")

        self.watcher = QFileSystemWatcher(self)
        self.watcher.fileChanged.connect(self._schedule)
        self.watcher.directoryChanged.connect(self._schedule)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(150)          # editors / matugen write in bursts
        self.timer.timeout.connect(self.apply)

        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(lambda *_: self._schedule())

    def _schedule(self, *_):
        self.timer.start()

    def resolve_mode(self) -> str:
        t = self.settings.data["theme"]
        if t in ("light", "dark"):
            return t
        try:
            cs = QGuiApplication.styleHints().colorScheme()
            if cs == Qt.ColorScheme.Dark:
                return "dark"
            if cs == Qt.ColorScheme.Light:
                return "light"
        except AttributeError:
            pass
        return "dark" if self._sys_palette.color(QPalette.ColorRole.Window).lightness() < 128 else "light"

    def css_file(self) -> Path | None:
        raw = (self.settings.data.get("css_path") or "").strip()
        if not raw or not self.settings.data.get("css_enabled", True):
            return None
        return Path(raw.replace("{mode}", self.mode)).expanduser()

    def _watch(self, path: Path | None):
        want = []
        if path is not None:
            if path.exists():
                want.append(str(path))
            if path.parent.exists():
                want.append(str(path.parent))
        have = set(self.watcher.files()) | set(self.watcher.directories())
        stale = [p for p in have if p not in want]
        if stale:
            self.watcher.removePaths(stale)
        new = [p for p in want if p not in have]
        if new:
            self.watcher.addPaths(new)

    def apply(self):
        self.mode = self.resolve_mode()
        tokens = dict(core.DARK if self.mode == "dark" else core.LIGHT)
        extra = ""
        path = self.css_file()
        if path is not None and not path.exists() and path == DEFAULT_CSS:
            try:
                CONF_DIR.mkdir(parents=True, exist_ok=True)
                path.write_text(core.SAMPLE_CSS)
            except OSError:
                pass
        if path is not None and path.is_file():
            try:
                defs, extra = core.split_css(path.read_text(errors="replace"))
                tokens.update(defs)
            except OSError:
                pass
        self._watch(path)
        tokens.update(ensure_checkbox_icons(tokens))
        self.tokens = tokens
        self.app.setPalette(self._palette(tokens))
        self.app.setStyleSheet(core.substitute_tokens(core.BUILTIN_QSS + "\n" + extra, tokens))
        self.changed.emit()

    @staticmethod
    def _palette(t: dict[str, str]) -> QPalette:
        p = QPalette()
        CR, CG = QPalette.ColorRole, QPalette.ColorGroup
        roles = {
            CR.Window: "surface", CR.WindowText: "on_surface", CR.Base: "surface_container",
            CR.AlternateBase: "surface_container_high", CR.Text: "on_surface",
            CR.Button: "surface_container_high", CR.ButtonText: "on_surface",
            CR.Highlight: "primary", CR.HighlightedText: "on_primary",
            CR.ToolTipBase: "surface_container_high", CR.ToolTipText: "on_surface",
            CR.PlaceholderText: "on_surface_variant", CR.Link: "primary",
        }
        for role, key in roles.items():
            c = QColor(t.get(key, ""))
            if c.isValid():
                p.setColor(role, c)
        dis = QColor(t.get("on_surface_variant", ""))
        if dis.isValid():
            for role in (CR.Text, CR.WindowText, CR.ButtonText):
                p.setColor(CG.Disabled, role, dis)
        return p

    def color(self, key: str) -> QColor:
        c = QColor(self.tokens.get(key, ""))
        return c if c.isValid() else QColor("#888888")


def set_prop(w: QWidget, name: str, value):
    w.setProperty(name, value)
    w.style().unpolish(w)
    w.style().polish(w)


# ---------------------------------------------------------------------------
# checkbox boxes and toolbar icons are drawn here
# qss can't load data: URIs, and the rescan glyph wasn't in the font
# ---------------------------------------------------------------------------
def _qcolor(tokens: dict[str, str], key: str, fallback: str = "#888888") -> QColor:
    c = QColor(tokens.get(key, ""))
    return c if c.isValid() else QColor(fallback)


def _draw_checkbox_png(path: Path, border: QColor, fill: QColor, glyph: str | None,
                       glyph_color: QColor | None, scale: int):
    size = 16 * scale
    img = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(scale, scale)
    pen = QPen(border)
    pen.setWidthF(2.0)
    p.setPen(pen)
    p.setBrush(fill)
    p.drawRoundedRect(QRectF(1, 1, 14, 14), 3.5, 3.5)
    if glyph and glyph_color is not None:
        pen = QPen(glyph_color)
        pen.setWidthF(2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        if glyph == "check":
            path_ = QPainterPath()
            path_.moveTo(4.2, 8.4)
            path_.lineTo(7.0, 11.0)
            path_.lineTo(11.8, 5.0)
            p.drawPath(path_)
        else:
            p.drawLine(QPointF(4.5, 8.0), QPointF(11.5, 8.0))
    p.end()
    img.save(str(path), "PNG")


def ensure_checkbox_icons(tokens: dict[str, str]) -> dict[str, str]:
    """Write the checkbox PNGs (1x and @2x) and return {token: path}. The file
    names have a colour hash so a theme change doesn't hit Qt's pixmap cache.
    Returns {} if the cache dir isn't writable."""
    out_dir = CACHE_DIR / "icons"
    sig = core.icon_signature(tokens)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for old in out_dir.glob("cb_*.png"):
            if sig not in old.name:
                old.unlink(missing_ok=True)
        paths: dict[str, str] = {}
        for token, (bk, fk, glyph, gk) in core.CB_ICONS.items():
            base = out_dir / f"{token}-{sig}.png"
            if not base.exists():
                args = (_qcolor(tokens, bk), _qcolor(tokens, fk), glyph, _qcolor(tokens, gk) if gk else None)
                _draw_checkbox_png(base, *args, 1)
                _draw_checkbox_png(out_dir / f"{token}-{sig}@2x.png", *args, 2)
            paths[token] = base.as_posix()
        return paths
    except OSError:
        return {}


def _toolbar_pixmap(name: str, color: QColor, size: int = 18, scale: int = 2) -> QPixmap:
    pm = QPixmap(size * scale, size * scale)
    pm.fill(Qt.GlobalColor.transparent)
    pm.setDevicePixelRatio(scale)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(color)
    pen.setWidthF(1.8)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    if name == "launch":
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(color)
        p.drawPolygon(QPolygonF([QPointF(5.5, 3.5), QPointF(14.5, 9), QPointF(5.5, 14.5)]))
    elif name == "stop":
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(color)
        p.drawRoundedRect(QRectF(4, 4, 10, 10), 1.8, 1.8)
    elif name == "rescan":
        import math
        cx, cy, r = 9.0, 9.0, 5.5
        start, span = 40, 290                       # degrees, ccw from 3 o'clock
        p.drawArc(QRectF(cx - r, cy - r, 2 * r, 2 * r), start * 16, span * 16)
        th = math.radians(start + span)
        tip = QPointF(cx + r * math.cos(th), cy - r * math.sin(th))
        t = QPointF(-math.sin(th), -math.cos(th))   # tangent at the end of the arc
        n = QPointF(-t.y(), t.x())
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(color)
        p.drawPolygon(QPolygonF([
            QPointF(tip.x() + t.x() * 3.2, tip.y() + t.y() * 3.2),
            QPointF(tip.x() - t.x() * 0.8 + n.x() * 3.0, tip.y() - t.y() * 0.8 + n.y() * 3.0),
            QPointF(tip.x() - t.x() * 0.8 - n.x() * 3.0, tip.y() - t.y() * 0.8 - n.y() * 3.0)]))
    elif name == "settings":                        # three sliders
        for y, knob in ((4.5, 6.5), (9.0, 12.0), (13.5, 8.0)):
            p.drawLine(QPointF(3, y), QPointF(15, y))
            p.setBrush(color)
            p.drawEllipse(QPointF(knob, y), 2.0, 2.0)
            p.setBrush(Qt.BrushStyle.NoBrush)
    elif name == "remove":                          # trash can
        p.drawLine(QPointF(3.5, 5.0), QPointF(14.5, 5.0))
        lid = QPainterPath()
        lid.moveTo(7.0, 5.0)
        lid.lineTo(7.0, 3.2)
        lid.lineTo(11.0, 3.2)
        lid.lineTo(11.0, 5.0)
        p.drawPath(lid)
        body = QPainterPath()
        body.moveTo(4.8, 5.0)
        body.lineTo(5.6, 14.8)
        body.lineTo(12.4, 14.8)
        body.lineTo(13.2, 5.0)
        p.drawPath(body)
        p.drawLine(QPointF(7.6, 7.4), QPointF(7.8, 12.4))
        p.drawLine(QPointF(10.4, 7.4), QPointF(10.2, 12.4))
    elif name == "add":
        p.drawLine(QPointF(9, 3.5), QPointF(9, 14.5))
        p.drawLine(QPointF(3.5, 9), QPointF(14.5, 9))
    p.end()
    return pm


def make_toolbar_icon(name: str, normal: QColor, disabled: QColor) -> QIcon:
    ic = QIcon()
    ic.addPixmap(_toolbar_pixmap(name, normal), QIcon.Mode.Normal)
    ic.addPixmap(_toolbar_pixmap(name, disabled), QIcon.Mode.Disabled)
    return ic


# ---------------------------------------------------------------------------
# widgets
# ---------------------------------------------------------------------------
class TriBox(QCheckBox):
    """Checkbox that shows a partial state when the selected games disagree,
    but a user click only ever goes checked <-> unchecked."""

    def __init__(self, text: str, key: str):
        super().__init__(text)
        self.key = key
        self.setTristate(True)

    def nextCheckState(self):  # noqa: N802  (Qt override)
        self.setCheckState(Unchecked if self.checkState() == Checked else Checked)


def label(text="", status: str | None = None, name: str | None = None, wrap=True) -> QLabel:
    l = QLabel(text)
    l.setWordWrap(wrap)
    if name:
        l.setObjectName(name)
    if status:
        l.setProperty("status", status)
    return l


def make_table(headers: list[str], stretch_col: int | None = None) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.verticalHeader().setVisible(False)
    t.setShowGrid(False)
    t.horizontalHeader().setHighlightSections(False)
    for i in range(len(headers)):
        mode = (QHeaderView.ResizeMode.Stretch if i == stretch_col
                else QHeaderView.ResizeMode.ResizeToContents)
        t.horizontalHeader().setSectionResizeMode(i, mode)
    return t


# ---------------------------------------------------------------------------
# settings dialog
# ---------------------------------------------------------------------------
class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(560)
        s = settings.data
        form = QFormLayout(self)

        self.root = QLineEdit(s["qroot"])
        b = QPushButton("Browse…")
        b.clicked.connect(lambda: self._browse_dir(self.root))
        form.addRow("wine-quarantine folder", self._row(self.root, b))

        self.theme = QComboBox()
        for text, val in (("Follow system", "system"), ("Light", "light"), ("Dark", "dark")):
            self.theme.addItem(text, val)
        self.theme.setCurrentIndex(max(0, self.theme.findData(s["theme"])))
        form.addRow("Theme", self.theme)

        self.css_on = QCheckBox("Load custom CSS (reloads live when the file changes)")
        self.css_on.setChecked(bool(s["css_enabled"]))
        form.addRow("", self.css_on)
        self.css = QLineEdit(s["css_path"])
        b2 = QPushButton("Browse…")
        b2.clicked.connect(self._browse_css)
        form.addRow("CSS file", self._row(self.css, b2))
        form.addRow("", label("{mode} in the path becomes “light” or “dark”, e.g. "
                              "~/.config/wq-ui/matugen-{mode}.css, so matugen can write one file "
                              "per mode and the Theme setting above picks between them.",
                              name="hint"))

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    @staticmethod
    def _row(*ws) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        for x in ws:
            h.addWidget(x)
        return w

    def _browse_dir(self, edit: QLineEdit):
        d = QFileDialog.getExistingDirectory(self, "wine-quarantine folder", edit.text() or str(Path.home()))
        if d:
            edit.setText(d)

    def _browse_css(self):
        f, _ = QFileDialog.getOpenFileName(self, "CSS file", str(Path(self.css.text()).expanduser().parent),
                                           "Stylesheets (*.css *.qss);;All files (*)")
        if f:
            self.css.setText(f)

    def values(self) -> dict:
        return {"qroot": self.root.text().strip(), "theme": self.theme.currentData(),
                "css_enabled": self.css_on.isChecked(), "css_path": self.css.text().strip()}


# ---------------------------------------------------------------------------
# main window
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    COLS = ["Game", "Executable", "Location", "Network", "Display", "State"]

    def __init__(self, settings: Settings, theme: ThemeManager, qroot: Path):
        super().__init__()
        self.settings, self.theme, self.qroot = settings, theme, qroot
        self.setWindowTitle("wine-quarantine")
        self.resize(1280, 800)

        self.games: list[core.Game] = []
        self.by_name: dict[str, core.Game] = {}
        self.defaults: dict[str, list[str]] = {}
        self.loaded: list[str] = []                       # games the panel currently shows
        self.dirty: set[str] = set()                      # scalar keys touched in the panel
        self.staged: dict[str, dict[str, list[str]]] = {}  # list keys edited, per game
        self.procs: dict[str, dict] = {}
        self.attempts: dict[tuple, int] = {}              # (game, addr, port) -> table row
        self._loading = False
        self._busy = False
        self._alert_sig: tuple | None = None

        self.boxes: dict[str, TriBox] = {}
        self.texts: dict[str, QComboBox] = {}
        self.orig_boxes: dict[str, Qt.CheckState] = {}    # as loaded, so undoing an edit isn't a change
        self.orig_texts: dict[str, str] = {}
        self.hook_edits: dict[str, QLineEdit] = {}
        self.icon_targets: list[tuple[str, object]] = []
        self._col0_sized = False

        self._build_ui()
        theme.changed.connect(self.on_theme_changed)
        self.rescan()

        self.alert_timer = QTimer(self)
        self.alert_timer.timeout.connect(self.refresh_alerts)
        self.alert_timer.start(1500)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        tb = QToolBar()
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(tb)

        # everything you can add lives in this menu
        self.act_new = QAction("New game…", self)
        self.act_new.setShortcut(QKeySequence("Ctrl+N"))
        self.act_new.triggered.connect(self.new_game)
        self.act_exe = QAction("Set executable…", self)
        self.act_exe.triggered.connect(self.set_executable_selected)
        self.act_hook_pre = QAction("Script before launch…", self)
        self.act_hook_pre.triggered.connect(lambda: self.choose_hook("FJ_HOOK_PRE"))
        self.act_hook_post = QAction("Script after exit…", self)
        self.act_hook_post.triggered.connect(lambda: self.choose_hook("FJ_HOOK_POST"))
        self.act_dev = QAction("Hide a /dev device…", self)
        self.act_dev.triggered.connect(self.add_device)
        self.act_remove = QAction("Remove", self)
        self.act_remove.setToolTip("Remove the selected game (moved to the Trash)")
        self.act_remove.triggered.connect(self.remove_game)
        self.act_folder = QAction("Open game folder", self)
        self.act_folder.triggered.connect(self.open_game_folder)

        add_menu = QMenu(self)
        add_menu.addAction(self.act_new)
        add_menu.addSeparator()
        add_menu.addAction(self.act_exe)
        sub = add_menu.addMenu("Attach a shell script")
        sub.addAction(self.act_hook_pre)
        sub.addAction(self.act_hook_post)
        add_menu.addAction(self.act_dev)
        add_menu.addSeparator()
        add_menu.addAction(self.act_folder)
        self.add_menu_scripts = sub
        self.add_btn = QToolButton()
        self.add_btn.setText("Add")
        self.add_btn.setToolTip("Add a game, a launch script or a hidden /dev device")
        self.add_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.add_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.add_btn.setMenu(add_menu)
        tb.addWidget(self.add_btn)
        tb.addSeparator()

        self.act_launch = QAction("Launch", self)
        self.act_launch.setShortcut(QKeySequence("Ctrl+Return"))
        self.act_launch.triggered.connect(self.launch_selected)
        self.act_stop = QAction("Stop", self)
        self.act_stop.triggered.connect(self.stop_selected)
        act_rescan = QAction("Rescan", self)
        act_rescan.setShortcut(QKeySequence("F5"))
        act_rescan.triggered.connect(lambda: self.rescan())
        act_settings = QAction("Settings", self)
        act_settings.triggered.connect(self.open_settings)
        for a in (self.act_launch, self.act_stop):
            tb.addAction(a)
        tb.addSeparator()
        tb.addAction(act_rescan)
        tb.addSeparator()
        tb.addAction(self.act_remove)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)
        tb.addAction(act_settings)
        act_debug = QAction("Debug", self)
        act_debug.triggered.connect(self.open_debug)
        tb.addAction(act_debug)
        self.icon_targets = [("add", self.add_btn), ("launch", self.act_launch), ("stop", self.act_stop),
                             ("rescan", act_rescan), ("remove", self.act_remove), ("settings", act_settings)]

        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 8)

        self.integration_banner = label("", "warn", "banner")
        root.addWidget(self.integration_banner)

        split = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split, 1)

        # left: game list
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 8, 0)
        self.tree = QTreeWidget()
        self.tree.setObjectName("gameList")
        self.tree.setColumnCount(len(self.COLS))
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setUniformRowHeights(True)
        # exe column stretches, game name gets its own width (set in populate()).
        # no more "7 Da... Die" and no horizontal scrollbar
        hdr = self.tree.header()
        hdr.setStretchLastSection(False)
        hdr.setMinimumSectionSize(60)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.setColumnWidth(0, 180)
        for i, w in ((2, 92), (3, 80), (4, 88), (5, 96)):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
            self.tree.setColumnWidth(i, w)
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.tree_menu)
        self.tree.itemSelectionChanged.connect(self.on_selection_changed)
        self.tree.itemDoubleClicked.connect(lambda *_: self.launch_selected())
        lv.addWidget(self.tree, 1)
        lv.addWidget(label("Ctrl/Shift-click to select several games and change them together. "
                           "Double-click launches.", name="hint"))
        split.addWidget(left)

        # right: tabs + apply bar
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(8, 0, 0, 0)
        self.tabs = QTabWidget()
        rv.addWidget(self.tabs, 1)
        self.tabs.addTab(self._build_protection_tab(), "Protection")
        self.tabs.addTab(self._build_paths_tab(), "Paths")
        self.tabs.addTab(self._build_network_tab(), "Network")
        self.tabs.addTab(self._build_monitor_tab(), "Monitor")

        bar = QHBoxLayout()
        self.pending_label = label("", "muted", wrap=False)
        bar.addWidget(self.pending_label, 1)
        self.btn_reset = QPushButton("Reset to defaults")
        self.btn_reset.clicked.connect(self.reset_to_defaults)
        self.btn_save_defaults = QPushButton("Save as default profile")
        self.btn_save_defaults.setToolTip("Writes the ticked/unticked boxes shown now to profile.defaults.conf.\n"
                                          "Games without their own setting use these.")
        self.btn_save_defaults.clicked.connect(self.save_as_defaults)
        self.btn_apply = QPushButton("Apply")
        self.btn_apply.setProperty("accent", True)
        self.btn_apply.setShortcut(QKeySequence("Ctrl+S"))
        self.btn_apply.clicked.connect(lambda: self.apply_changes())
        for b in (self.btn_reset, self.btn_save_defaults, self.btn_apply):
            bar.addWidget(b)
        rv.addLayout(bar)
        split.addWidget(right)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 6)
        split.setSizes([560, 700])

        self.statusBar().showMessage(self._tool_status())
        self.refresh_icons()

    def refresh_icons(self):
        normal, dis = self.theme.color("on_surface"), self.theme.color("on_surface_variant")
        for name, target in self.icon_targets:
            target.setIcon(make_toolbar_icon(name, normal, dis))

    def _tool_status(self) -> str:
        missing = [t for t in ("firejail", "inotifywait", "Xephyr") if not shutil.which(t)]
        return ("Missing tools: " + ", ".join(missing)) if missing else "firejail, inotify-tools, Xephyr found"

    # ---- protection tab
    def _build_protection_tab(self) -> QWidget:
        outer = QScrollArea()
        outer.setWidgetResizable(True)
        self.prot = QWidget()
        v = QVBoxLayout(self.prot)
        v.setContentsMargins(12, 12, 12, 12)
        self.sel_banner = label("Select one or more games.", None, "banner")
        v.addWidget(self.sel_banner)

        def group(title, opts):
            g = QGroupBox(title)
            gl = QVBoxLayout(g)
            for o in opts:
                b = self._tribox(o.label, o.key, o.tip)
                gl.addWidget(b)
            v.addWidget(g)
            return gl

        group("Isolation", [o for o in core.BOOL_OPTS if o.group == "isolation"])
        gl_dev = group("Devices", [o for o in core.BOOL_OPTS if o.group == "devices"])

        # hide single /dev nodes (--blacklist)
        gl_dev.addWidget(label("Hidden /dev devices (one game at a time)", name="hint"))
        self.dev_list = QListWidget()
        self.dev_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.dev_list.setMaximumHeight(96)
        self.dev_list.setToolTip("These /dev nodes do not exist inside the sandbox. Everything not listed stays visible.")
        gl_dev.addWidget(self.dev_list)
        drow = QHBoxLayout()
        self.btn_dev_add = QPushButton("Add device…")
        self.btn_dev_rm = QPushButton("Remove")
        self.btn_dev_add.clicked.connect(self.add_device)
        self.btn_dev_rm.clicked.connect(self.remove_device)
        drow.addWidget(self.btn_dev_add)
        drow.addWidget(self.btn_dev_rm)
        drow.addStretch(1)
        gl_dev.addLayout(drow)
        self.dev_note = label("", "muted")
        gl_dev.addWidget(self.dev_note)

        # network
        g = QGroupBox("Network")
        gl = QVBoxLayout(g)
        gl.addWidget(self._tribox("Allow network access", "FJ_NET",
                                  "Off = --net=none (stock behaviour). On = the sandbox gets its own interface behind a "
                                  "default-deny filter; only the whitelist (Network tab) gets out."))
        row = QHBoxLayout()
        row.addSpacing(24)
        row.addWidget(QLabel("Interface"))
        self.iface = QComboBox()
        self.iface.setEditable(True)
        self.iface.setMinimumWidth(180)
        for name, kind in core.list_interfaces():
            self.iface.addItem(name)
            self.iface.setItemData(self.iface.count() - 1, kind, Qt.ItemDataRole.ToolTipRole)
        self.iface.lineEdit().setPlaceholderText("e.g. enp5s0 or br0")
        self.iface.editTextChanged.connect(lambda *_: self._text_edited("FJ_NET_IFACE"))
        self.texts["FJ_NET_IFACE"] = self.iface
        row.addWidget(self.iface, 1)
        gl.addLayout(row)
        self.iface_note = label("", "warn")
        gl.addWidget(self.iface_note)
        gl.addWidget(self._tribox("Allow DNS lookups (udp/53)", "FJ_NET_DNS",
                                  "Needed if the game resolves hostnames. The whitelist itself is by IP."))
        gl.addWidget(self._tribox("Log connection attempts (shown in the Network tab)", "FJ_NET_LOG",
                                  "Logs every new outgoing connection through the kernel firewall log (needs "
                                  "net.netfilter.nf_log_all_netns=1). Only recorded while network access is on "
                                  "(filtered or learn mode)."))
        gl.addWidget(self._tribox("Learn mode — allow everything, log it", "FJ_NET_LEARN",
                                  "Filtered network, but nothing is blocked: every connection is allowed and, with logging "
                                  "on, listed in the Network tab. Collect IPs, then untick this to enforce the whitelist."))
        gl.addWidget(self._tribox("Unrestricted — no filtering at all", "FJ_NET_OPEN",
                                  "Shares the host network namespace. The game can reach anything you can. Not recommended."))
        self.boxes["FJ_NET_OPEN"].setProperty("danger", True)
        v.addWidget(g)

        # display
        g = QGroupBox("Display")
        gl = QVBoxLayout(g)
        gl.addWidget(self._tribox("Isolated X11 (Xephyr)", "FJ_XEPHYR",
                                  "--x11=xephyr: the game gets its own X server in a window. It can no longer read your "
                                  "keystrokes or screen from the real X session."))
        row = QHBoxLayout()
        row.addSpacing(24)
        row.addWidget(QLabel("Monitor size"))
        self.xsize = QComboBox()
        self.xsize.setEditable(True)
        self.xsize.addItem("Auto (firejail default)", "")
        dpr_screens = QGuiApplication.screens()
        for s in dpr_screens:
            w, h = int(s.size().width() * s.devicePixelRatio()), int(s.size().height() * s.devicePixelRatio())
            self.xsize.addItem(f"{s.name()} — {w}x{h}", f"{w}x{h}")
        for extra in ("1920x1080", "2560x1440", "1280x720"):
            if self.xsize.findData(extra) < 0:
                self.xsize.addItem(extra, extra)
        self.xsize.lineEdit().setPlaceholderText("WIDTHxHEIGHT")
        self.xsize.editTextChanged.connect(lambda *_: self._text_edited("FJ_XEPHYR_SIZE"))
        self.texts["FJ_XEPHYR_SIZE"] = self.xsize
        row.addWidget(self.xsize, 1)
        gl.addLayout(row)
        self.x_note = label("", "warn")
        gl.addWidget(self.x_note)
        gl.addWidget(label("The window opens wherever your compositor puts it; the size only sets Xephyr's resolution. "
                           "Pick a monitor to match its resolution.", name="hint"))
        v.addWidget(g)
        v.addStretch(1)

        for k in ("FJ_NET", "FJ_NET_OPEN", "FJ_XEPHYR"):
            # stateChanged is deprecated in Qt >= 6.9 in favour of checkStateChanged
            sig = getattr(self.boxes[k], "checkStateChanged", None) or self.boxes[k].stateChanged
            sig.connect(lambda *_: self.refresh_dependents())
        self.iface.editTextChanged.connect(lambda *_: self.refresh_dependents())
        outer.setWidget(self.prot)
        return outer

    def _tribox(self, text: str, key: str, tip: str) -> TriBox:
        b = TriBox(text, key)
        b.setToolTip(tip)
        b.clicked.connect(lambda *_, k=key: self._mark(k))
        self.boxes[key] = b
        return b

    def _mark(self, key: str):
        """A key only counts as changed while it differs from what was loaded."""
        if self._loading:
            return
        if key in self.boxes:
            same = self.boxes[key].checkState() == self.orig_boxes.get(key)
        else:
            same = self.text_value(key) == self.orig_texts.get(key, "")
        if same:
            self.dirty.discard(key)
        else:
            self.dirty.add(key)
        self.update_apply_bar()

    def _text_edited(self, key: str):
        if not self._loading:
            self._mark(key)

    def text_value(self, key: str) -> str:
        c = self.texts[key]
        txt = c.currentText().strip()
        i = c.currentIndex()
        if i >= 0 and txt == c.itemText(i) and c.itemData(i) is not None:
            return c.itemData(i)
        return txt

    # ---- paths tab
    def _build_paths_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(12, 12, 12, 12)
        self.paths_banner = label("Select a single game to see its paths.", None, "banner")
        v.addWidget(self.paths_banner)
        self.loc_table = make_table(["", "Path", "Status"], stretch_col=1)
        v.addWidget(self.loc_table, 2)
        v.addWidget(label("Only game/ and prefix/ are writable inside the sandbox, and --private hides the rest of "
                          "$HOME. Anything else the game needs (save folders, a shared library of assets) has to be "
                          "whitelisted below.", name="hint"))

        g = QGroupBox("Extra whitelisted paths")
        gl = QVBoxLayout(g)
        self.wl_table = make_table(["Access", "Path", "Status"], stretch_col=1)
        gl.addWidget(self.wl_table)
        row = QHBoxLayout()
        self.btn_add_rw = QPushButton("Add folder (read-write)…")
        self.btn_add_ro = QPushButton("Add folder (read-only)…")
        self.btn_add_file = QPushButton("Add file (read-only)…")
        self.btn_rm_path = QPushButton("Remove")
        self.btn_add_rw.clicked.connect(lambda: self.add_path("FJ_WL_RW", "dir"))
        self.btn_add_ro.clicked.connect(lambda: self.add_path("FJ_WL_RO", "dir"))
        self.btn_add_file.clicked.connect(lambda: self.add_path("FJ_WL_RO", "file"))
        self.btn_rm_path.clicked.connect(self.remove_path)
        for b in (self.btn_add_rw, self.btn_add_ro, self.btn_add_file, self.btn_rm_path):
            row.addWidget(b)
        row.addStretch(1)
        gl.addLayout(row)
        v.addWidget(g, 2)

        g3 = QGroupBox("Launch scripts")
        g3l = QVBoxLayout(g3)
        g3l.addWidget(label("Shell scripts run by the launcher on your machine with your normal permissions - NOT "
                            "inside the sandbox. “Before launch” runs just before the sandbox starts and cancels the "
                            "launch if it fails; “After exit” runs when the launcher finishes. They get WQ_GAME, "
                            "WQ_GAMEDIR and WQ_QROOT in the environment. Per game only.", "warn"))
        grid = QFormLayout()
        for key, text in (("FJ_HOOK_PRE", "Before launch"), ("FJ_HOOK_POST", "After exit")):
            row = QWidget()
            hl = QHBoxLayout(row)
            hl.setContentsMargins(0, 0, 0, 0)
            ed = QLineEdit()
            ed.setReadOnly(True)
            ed.setPlaceholderText("none")
            self.hook_edits[key] = ed
            bc, bx = QPushButton("Choose…"), QPushButton("Clear")
            bc.clicked.connect(lambda _=False, k=key: self.choose_hook(k))
            bx.clicked.connect(lambda _=False, k=key: self.clear_hook(k))
            for x in (ed, bc, bx):
                hl.addWidget(x, 1 if x is ed else 0)
            grid.addRow(text, row)
        g3l.addLayout(grid)
        self.hook_box = g3
        v.addWidget(g3)
        return w

    # ---- network tab
    def _build_network_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(12, 12, 12, 12)
        self.net_banner = label("", None, "banner")
        v.addWidget(self.net_banner)

        g = QGroupBox("Connection attempts")
        gl = QVBoxLayout(g)
        self.att_table = make_table(["Game", "Last seen", "Destination", "Port", "Hits", "Status", ""], stretch_col=2)
        gl.addWidget(self.att_table)
        row = QHBoxLayout()
        clear = QPushButton("Clear")
        clear.clicked.connect(self.clear_attempts)
        row.addWidget(label("Read live from the kernel firewall log (journalctl -k) while this window is open, so "
                            "it needs network access on (filtered or learn mode) and net.netfilter.nf_log_all_netns=1. "
                            "IPv4 only; connections made before this window opened are not listed.", name="hint"), 1)
        row.addWidget(clear)
        gl.addLayout(row)
        v.addWidget(g, 3)

        g2 = QGroupBox("Whitelist for the selected game (IPv4)")
        g2l = QVBoxLayout(g2)
        self.allow_list = QListWidget()
        self.allow_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        g2l.addWidget(self.allow_list)
        row = QHBoxLayout()
        self.allow_edit = QLineEdit()
        self.allow_edit.setPlaceholderText("tcp:93.184.216.34:443   or   udp:10.0.0.0/8:*")
        self.allow_edit.returnPressed.connect(self.add_allow_manual)
        self.btn_allow_add = QPushButton("Add")
        self.btn_allow_add.clicked.connect(self.add_allow_manual)
        self.btn_allow_rm = QPushButton("Remove selected")
        self.btn_allow_rm.clicked.connect(self.remove_allow)
        row.addWidget(self.allow_edit, 1)
        row.addWidget(self.btn_allow_add)
        row.addWidget(self.btn_allow_rm)
        g2l.addLayout(row)
        v.addWidget(g2, 2)
        return w

    # ---- monitor tab
    def _build_monitor_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(12, 12, 12, 12)
        sp = QSplitter(Qt.Orientation.Vertical)
        v.addWidget(sp)

        top = QWidget()
        tv = QVBoxLayout(top)
        tv.setContentsMargins(0, 0, 0, 0)
        h = QHBoxLayout()
        h.addWidget(QLabel("Launcher output"), 1)
        b = QPushButton("Clear")
        b.clicked.connect(lambda: self.console.clear())
        h.addWidget(b)
        tv.addLayout(h)
        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(5000)
        tv.addWidget(self.console)
        sp.addWidget(top)

        bot = QWidget()
        bv = QVBoxLayout(bot)
        bv.setContentsMargins(0, 0, 0, 0)
        self.alert_title = QLabel("Monitor alerts")
        bv.addWidget(self.alert_title)
        self.alerts = QPlainTextEdit()
        self.alerts.setObjectName("alerts")
        self.alerts.setReadOnly(True)
        bv.addWidget(self.alerts)
        sp.addWidget(bot)
        return w

    # ------------------------------------------------------------ scanning
    def integration_status(self) -> str:
        files = [self.qroot / n for n in ("config.sh", "_launch-core.sh", "verify-sandbox.sh")]
        if not (self.qroot / "wq-ui" / "profile.sh").is_file():
            return ("wq-ui/profile.sh not found inside the wine-quarantine folder. Copy this folder to "
                    f"{self.qroot}/wq-ui/ and run integrate.py.")
        for f in files:
            try:
                if MARK not in f.read_text(errors="replace"):
                    return (f"{f.name} is not patched yet. Settings are saved but launches ignore them until you run "
                            "python3 wq-ui/integrate.py")
            except OSError:
                return f"cannot read {f}"
        return ""

    def rescan(self, *_):
        if not self.resolve_pending("Apply them before rescanning?"):
            return
        self.defaults = core.parse_kv(self.qroot / core.DEFAULTS_NAME)
        self.games = core.scan_games(self.qroot)
        self.by_name = {g.name: g for g in self.games}
        msg = self.integration_status()
        self.integration_banner.setText(msg)
        self.integration_banner.setVisible(bool(msg))
        self.populate()
        self.on_selection_changed(force=True)

    def populate(self):
        keep = {i.data(0, Qt.ItemDataRole.UserRole) for i in self.tree.selectedItems()}
        self.tree.blockSignals(True)
        self.tree.clear()
        for g in self.games:
            exe_short = os.path.basename(g.exe) if g.exe else "—"
            if g.runner == "native":
                exe_short = f"native: {exe_short}"
            it = QTreeWidgetItem([g.name, exe_short, "", "", "", ""])
            it.setData(0, Qt.ItemDataRole.UserRole, g.name)
            it.setToolTip(0, g.name)
            self.tree.addTopLevelItem(it)
            if g.name in keep:
                it.setSelected(True)
        self.tree.blockSignals(False)
        if self.games:
            fm = self.tree.fontMetrics()
            need = min(max(max(fm.horizontalAdvance(g.name) for g in self.games) + 30, 140), 300)
            if not self._col0_sized or need > self.tree.columnWidth(0):
                self.tree.setColumnWidth(0, need)
                self._col0_sized = True
        self.refresh_rows()

    def refresh_rows(self):
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            g = self.by_name.get(it.data(0, Qt.ItemDataRole.UserRole))
            if g is None:
                continue
            kind, why = core.classify_path(g.path)
            loc = {"home": ("⚠ in $HOME", "warn"), "ok": ("✓ ok", "ok"), "system": ("system dir", "muted"),
                   "unsupported": ("✗ unsupported", "bad"), "missing": ("✗ missing", "bad")}[kind]
            mode = g.net_mode(self.defaults)
            net = {"off": ("off", "ok"), "filtered": ("filtered", "warn"), "learn": ("learning", "warn"),
                   "open": ("OPEN", "bad")}[mode]
            xe = ("Xephyr", "ok") if g.flag("FJ_XEPHYR", self.defaults) else ("host X11", "muted")
            if g.name in self.procs:
                st = ("● running", "ok")
            elif not g.exe_ready:
                st = ("needs EXE", "bad")
            elif not g.has_launcher:
                st = ("no launcher", "bad")
            else:
                st = ("ready", "muted")
            it.setData(2, Qt.ItemDataRole.UserRole, loc[1])
            for col, (text, status) in ((2, loc), (3, net), (4, xe), (5, st)):
                it.setText(col, text)
                it.setData(col, Qt.ItemDataRole.UserRole + 1, status)
            it.setToolTip(2, f"{g.path}\n\n{why}")
            it.setToolTip(1, str(g.path / "game" / g.exe) if g.exe else "")
        self.refresh_colors()

    def on_theme_changed(self):
        self.refresh_icons()
        self.refresh_colors()
        self.refresh_paths()
        self.refresh_attempt_rows()

    def refresh_colors(self):
        m = {"ok": "ok", "warn": "warn", "bad": "error", "muted": "on_surface_variant"}
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            for col in range(2, len(self.COLS)):
                st = it.data(col, Qt.ItemDataRole.UserRole + 1)
                if st:
                    it.setForeground(col, QBrush(self.theme.color(m[st])))

    # ----------------------------------------------------------- selection
    def selected_games(self) -> list[core.Game]:
        names = [i.data(0, Qt.ItemDataRole.UserRole) for i in self.tree.selectedItems()]
        return [g for g in self.games if g.name in names]

    def loaded_games(self) -> list[core.Game]:
        return [self.by_name[n] for n in self.loaded if n in self.by_name]

    def pending_count(self) -> int:
        return len(self.dirty) + sum(len(v) for v in self.staged.values())

    def resolve_pending(self, text: str) -> bool:
        """Ask what to do with unapplied edits. False if cancelled or the apply failed."""
        if not (self.pending_count() and self.loaded):
            return True
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Unapplied changes")
        box.setText(f"{self.pending_count()} unapplied change(s) for {', '.join(self.loaded)}.")
        box.setInformativeText(text)
        b_apply = box.addButton("Apply", QMessageBox.ButtonRole.AcceptRole)
        b_drop = box.addButton("Discard", QMessageBox.ButtonRole.DestructiveRole)
        b_cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(b_apply)
        box.setEscapeButton(b_cancel)
        box.exec()
        c = box.clickedButton()
        if c is b_apply:
            return self.apply_changes(quiet=True)
        if c is b_drop:
            self.dirty.clear()
            self.staged.clear()
            return True
        return False

    def _restore_selection(self):
        names = set(self.loaded)
        self.tree.blockSignals(True)
        self.tree.clearSelection()
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            if it.data(0, Qt.ItemDataRole.UserRole) in names:
                it.setSelected(True)
        self.tree.blockSignals(False)

    def on_selection_changed(self, force: bool = False):
        if self._busy:
            return
        if not force and not self.resolve_pending("Apply them before switching games?"):
            self._restore_selection()
            return
        self.dirty.clear()
        self.staged.clear()
        self.loaded = [g.name for g in self.selected_games()]
        self.load_all()

    def load_all(self):
        self.load_panel()
        self.refresh_paths()
        self.refresh_allow()
        self.refresh_net_banner()
        self.refresh_attempts()
        self.refresh_alerts(force=True)
        self.refresh_extras()
        sel = self.loaded_games()
        one = len(sel) == 1
        for a in (self.act_exe, self.act_hook_pre, self.act_hook_post, self.act_dev, self.act_folder,
                  self.act_remove):
            a.setEnabled(one)
        self.add_menu_scripts.setEnabled(one)
        self.act_launch.setEnabled(bool(sel))
        self.act_stop.setEnabled(any(g.name in self.procs for g in sel))
        self.update_apply_bar()

    def load_panel(self):
        sel = self.loaded_games()
        self._loading = True
        self.prot.setEnabled(bool(sel))
        for key, box in self.boxes.items():
            vals = {g.flag(key, self.defaults) for g in sel}
            box.setCheckState(Checked if vals == {True} else Partial if len(vals) > 1 else Unchecked)
        for key, combo in self.texts.items():
            vals = {g.scalar(key, self.defaults, core.TEXT_KEYS[key]) for g in sel}
            le = combo.lineEdit()
            if len(vals) == 1:
                v = vals.pop()
                i = combo.findData(v)
                if i >= 0:
                    combo.setCurrentIndex(i)
                else:
                    combo.setCurrentIndex(-1)
                    combo.setEditText(v)
                le.setPlaceholderText("e.g. enp5s0 or br0" if key == "FJ_NET_IFACE" else "WIDTHxHEIGHT")
            else:
                combo.setCurrentIndex(-1)
                combo.setEditText("")
                le.setPlaceholderText("(differs between selected games)")
        self.orig_boxes = {k: b.checkState() for k, b in self.boxes.items()}
        self.orig_texts = {k: self.text_value(k) for k in self.texts}
        self._loading = False
        if len(sel) == 0:
            self.sel_banner.setText("Select one or more games.")
        elif len(sel) == 1:
            self.sel_banner.setText(f"Editing {sel[0].name}. Boxes show the effective value "
                                    "(this game's setting, else the default profile, else stock).")
        else:
            self.sel_banner.setText(f"Editing {len(sel)} games at once. A half-ticked box means they differ; "
                                    "only boxes you click are changed.")
        self.refresh_dependents()

    def refresh_dependents(self):
        net = self.boxes["FJ_NET"].checkState() != Unchecked
        opened = self.boxes["FJ_NET_OPEN"].checkState() == Checked
        self.boxes["FJ_NET_OPEN"].setEnabled(net)
        self.boxes["FJ_NET_DNS"].setEnabled(net and not opened)
        self.boxes["FJ_NET_LEARN"].setEnabled(net and not opened)
        self.iface.setEnabled(net and not opened)
        x = self.boxes["FJ_XEPHYR"].checkState() != Unchecked
        self.xsize.setEnabled(x)

        note, wanted = "", self.iface.currentText().strip()
        if net and not opened:
            kinds = dict(core.list_interfaces())
            if not wanted:
                note = "No interface chosen — the game will stay offline until you pick one."
            elif wanted not in kinds:
                note = f"“{wanted}” does not exist on this machine — the game will stay offline."
            elif kinds[wanted] == "wireless":
                note = ("Wi-Fi interfaces generally cannot be used with --net=IFACE (macvlan). "
                        "Use a bridge or an ethernet interface.")
        self.iface_note.setText(note)
        self.iface_note.setVisible(bool(note))
        xm = "" if shutil.which("Xephyr") else "Xephyr is not installed (package: xorg-server-xephyr / xserver-xephyr)."
        self.x_note.setText(xm)
        self.x_note.setVisible(bool(xm) and x)

    def update_apply_bar(self):
        n = len(self.loaded)
        pend = self.pending_count()
        self.btn_apply.setText(f"Apply to {n} game{'s' if n != 1 else ''}" if n else "Apply")
        self.btn_apply.setEnabled(bool(n) and pend > 0)
        self.btn_reset.setEnabled(bool(n))
        self.btn_save_defaults.setEnabled(bool(n))
        self.pending_label.setText(f"● {pend} unapplied change{'s' if pend != 1 else ''}" if pend else "")
        set_prop(self.pending_label, "status", "warn" if pend else "muted")

    # ------------------------------------------------------------- applying
    def collect_changes(self) -> dict[str, str | None]:
        ch: dict[str, str | None] = {}
        for key in self.dirty:
            if key in self.boxes:
                st = self.boxes[key].checkState()
                if st != Partial:
                    ch[key] = "1" if st == Checked else "0"
            elif key in self.texts:
                v = self.text_value(key)
                ch[key] = v or None
        return ch

    def validate(self, ch: dict) -> str:
        s = ch.get("FJ_XEPHYR_SIZE")
        if s and not core.valid_size(s):
            return f"“{s}” is not a valid size. Use WIDTHxHEIGHT, e.g. 1920x1080."
        i = ch.get("FJ_NET_IFACE")
        if i and not all(c.isalnum() or c in "_.-" for c in i):
            return f"“{i}” is not a valid interface name."
        return ""

    def apply_changes(self, quiet: bool = False) -> bool:
        games = self.loaded_games()
        ch = self.collect_changes()
        err = self.validate(ch)
        if err:
            QMessageBox.warning(self, "Cannot apply", err)
            return False
        if ch.get("FJ_NET_OPEN") == "1" and not quiet:
            r = QMessageBox.warning(
                self, "Unrestricted network",
                "This lets the game talk to anything you can reach, with no filtering.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                return False
        names = set(self.staged) | ({g.name for g in games} if ch else set())
        try:
            for name in names:
                g = self.by_name.get(name)
                if g is None:
                    continue
                upd: dict = {}
                if g in games:
                    upd.update(ch)
                upd.update(self.staged.get(name, {}))
                if upd:
                    core.write_kv(g.path / "game.conf", upd)
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "Could not write game.conf", str(e))
            return False
        self.dirty.clear()
        self.staged.clear()
        self.reload_keep_selection()
        self.statusBar().showMessage(f"Applied to {', '.join(g.name for g in games) or 'nothing'}", 5000)
        return True

    def reload_keep_selection(self):
        self._busy = True
        try:
            self.defaults = core.parse_kv(self.qroot / core.DEFAULTS_NAME)
            self.games = core.scan_games(self.qroot)
            self.by_name = {g.name: g for g in self.games}
            self.populate()
        finally:
            self._busy = False
        self.loaded = [g.name for g in self.selected_games()]
        self.load_all()

    def reset_to_defaults(self):
        games = self.loaded_games()
        if not games:
            return
        r = QMessageBox.question(
            self, "Reset to defaults",
            f"Remove the per-game profile settings of {', '.join(g.name for g in games)}?\n"
            "They fall back to the default profile. Whitelists are kept.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if r != QMessageBox.StandardButton.Yes:
            return
        try:
            for g in games:
                core.write_kv(g.path / "game.conf", {k: None for k in core.MANAGED_SCALARS})
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "Could not write game.conf", str(e))
            return
        self.dirty.clear()
        self.reload_keep_selection()

    def save_as_defaults(self):
        if not self.loaded_games():
            return
        err = self.validate({k: self.text_value(k) for k in self.texts})
        if err:
            QMessageBox.warning(self, "Cannot save", err)
            return
        upd: dict = {}
        for key, box in self.boxes.items():
            if box.checkState() != Partial:
                upd[key] = "1" if box.checkState() == Checked else "0"
        for key in self.texts:
            v = self.text_value(key)
            upd[key] = v or None
        if upd.get("FJ_NET_OPEN") == "1":
            r = QMessageBox.warning(self, "Unrestricted network by default",
                                    "Every game without its own setting would get unfiltered network access. Continue?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                return
        try:
            core.write_kv(self.qroot / core.DEFAULTS_NAME, upd)
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "Could not write defaults", str(e))
            return
        self.statusBar().showMessage("Saved as default profile (profile.defaults.conf). "
                                     "Games with their own settings keep them.", 6000)
        self.reload_keep_selection()

    # ---------------------------------------------------------------- paths
    def single(self) -> core.Game | None:
        s = self.loaded_games()
        return s[0] if len(s) == 1 else None

    def list_for(self, g: core.Game, key: str) -> list[str]:
        staged = self.staged.get(g.name, {})
        return list(staged[key]) if key in staged else list(g.conf.get(key, []))

    def _prune_staged(self, g: core.Game):
        """Drop staged lists that match what is saved."""
        st = self.staged.get(g.name)
        if st:
            for k in list(st):
                if list(st[k]) == list(g.conf.get(k, [])):
                    del st[k]
        if not st:
            self.staged.pop(g.name, None)

    def stage_list(self, g: core.Game, key: str, values: list[str]):
        self.staged.setdefault(g.name, {})[key] = values
        self._prune_staged(g)
        self.refresh_extras()
        self.refresh_paths()
        self.refresh_allow()
        self.refresh_attempt_rows()
        self.update_apply_bar()

    def _status_cell(self, text: str, status: str, tip: str = "") -> QTableWidgetItem:
        it = QTableWidgetItem(text)
        m = {"ok": "ok", "warn": "warn", "bad": "error", "muted": "on_surface_variant"}
        it.setForeground(QBrush(self.theme.color(m[status])))
        it.setToolTip(tip)
        return it

    def refresh_paths(self):
        g = self.single()
        self.loc_table.setRowCount(0)
        self.wl_table.setRowCount(0)
        for b in (self.btn_add_rw, self.btn_add_ro, self.btn_add_file, self.btn_rm_path):
            b.setEnabled(g is not None)
        if g is None:
            self.paths_banner.setText("Select a single game to see and edit its paths." if not self.loaded
                                      else "Paths are per game — select just one game.")
            return
        hides = g.flag("FJ_PRIVATE_HOME", self.defaults)
        self.paths_banner.setText(
            f"{g.name} — home is {'hidden by --private' if hides else 'NOT hidden (private home is off)'}.")
        rows = [("game folder", g.path, False), ("game/  (read-write)", g.path / "game", True)]
        if g.runner == "native":
            if (g.path / "home").exists():
                rows.append(("home/  (private $HOME)", g.path / "home", True))
        else:
            rows.append(("prefix/  (read-write)", g.path / "prefix", True))
        if g.exe_ready:
            rows.append(("executable", g.path / "game" / g.exe, True))
        for lab, p, auto in rows:
            kind, why = core.classify_path(p)
            if kind == "home":
                text = ("⚠ in $HOME — hidden by --private, "
                        + ("whitelisted automatically" if auto else "only game/ and prefix/ are whitelisted"))
                st = "warn"
            else:
                text, st = {"ok": ("✓ whitelist-able location", "ok"), "system": ("visible read-only", "muted"),
                            "unsupported": ("✗ firejail cannot whitelist here", "bad"),
                            "missing": ("✗ missing", "bad")}[kind]
            r = self.loc_table.rowCount()
            self.loc_table.insertRow(r)
            self.loc_table.setItem(r, 0, QTableWidgetItem(lab))
            real = os.path.realpath(p)
            shown = str(p) if real == str(p) else f"{p}  →  {real}"
            self.loc_table.setItem(r, 1, QTableWidgetItem(shown))
            self.loc_table.setItem(r, 2, self._status_cell(text, st, why))
        for key, acc in (("FJ_WL_RW", "read-write"), ("FJ_WL_RO", "read-only")):
            for p in self.list_for(g, key):
                kind, why = core.classify_path(p)
                text, st = {"home": ("⚠ in $HOME — visible only because it is whitelisted", "warn"),
                            "ok": ("✓", "ok"), "system": ("already visible read-only", "muted"),
                            "unsupported": ("✗ firejail cannot whitelist here", "bad"),
                            "missing": ("✗ missing — skipped at launch", "bad")}[kind]
                r = self.wl_table.rowCount()
                self.wl_table.insertRow(r)
                a = QTableWidgetItem(acc)
                a.setData(Qt.ItemDataRole.UserRole, (key, p))
                self.wl_table.setItem(r, 0, a)
                self.wl_table.setItem(r, 1, QTableWidgetItem(p))
                self.wl_table.setItem(r, 2, self._status_cell(text, st, why))

    def add_path(self, key: str, kind: str):
        g = self.single()
        if g is None:
            return
        start = str(Path.home())
        p = (QFileDialog.getExistingDirectory(self, "Choose folder", start) if kind == "dir"
             else QFileDialog.getOpenFileName(self, "Choose file", start)[0])
        if not p:
            return
        p = os.path.realpath(p)
        ckind, why = core.classify_path(p)
        if ckind == "unsupported":
            QMessageBox.warning(self, "Cannot whitelist", why)
            return
        if ckind == "system":
            QMessageBox.information(self, "Already visible", why)
            return
        if p == "/" or p == os.path.realpath(Path.home()):
            r = QMessageBox.warning(
                self, "That defeats the sandbox",
                f"Whitelisting {p} exposes everything in it to the game"
                f"{' (read-write!)' if key == 'FJ_WL_RW' else ''}.\n\nAre you sure?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                return
        for k in ("FJ_WL_RW", "FJ_WL_RO"):
            vals = [x for x in self.list_for(g, k) if x != p]
            if k == key:
                vals.append(p)
            if vals != self.list_for(g, k):
                self.staged.setdefault(g.name, {})[k] = vals
        self._prune_staged(g)
        self.refresh_paths()
        self.update_apply_bar()

    def remove_path(self):
        g = self.single()
        rows = {i.row() for i in self.wl_table.selectedItems()}
        if g is None or not rows:
            return
        for r in sorted(rows):
            key, p = self.wl_table.item(r, 0).data(Qt.ItemDataRole.UserRole)
            self.staged.setdefault(g.name, {})[key] = [x for x in self.list_for(g, key) if x != p]
        self._prune_staged(g)
        self.refresh_paths()
        self.update_apply_bar()

    # -------------------------------------------------------------- network
    def refresh_net_banner(self):
        g = self.single()
        if g is None:
            self.net_banner.setText("Select a single game to manage its whitelist. Attempts from every launched game "
                                    "are listed below.")
            set_prop(self.net_banner, "status", "")
            return
        mode = g.net_mode(self.defaults)
        log = g.flag("FJ_NET_LOG", self.defaults)
        if mode == "off":
            txt, st = f"{g.name}: network is OFF (--net=none). Nothing gets out, whitelist or not.", "ok"
        elif mode == "open":
            txt, st = f"{g.name}: network is UNRESTRICTED. The whitelist is not used.", "bad"
        elif mode == "learn":
            txt, st = (f"{g.name}: LEARN MODE. Nothing is blocked; every connection is allowed and logged. "
                       "Untick “Learn mode” in Protection to enforce the whitelist.", "warn")
        else:
            txt, st = (f"{g.name}: network is FILTERED. Everything is blocked except the whitelist below "
                       f"(and DNS if allowed).", "warn")
        if not log:
            txt += "  Connection logging is off — tick “Log connection attempts” in Protection to see what it tries."
        self.net_banner.setText(txt)
        set_prop(self.net_banner, "status", st)

    def refresh_allow(self):
        g = self.single()
        self.allow_list.clear()
        for w in (self.allow_edit, self.btn_allow_add, self.btn_allow_rm, self.allow_list):
            w.setEnabled(g is not None)
        if g is not None:
            for e in self.list_for(g, "FJ_NET_ALLOW"):
                self.allow_list.addItem(e)

    def add_allow_manual(self):
        g = self.single()
        e = self.allow_edit.text().strip()
        if g is None or not e:
            return
        if not core.valid_allow(e):
            QMessageBox.warning(self, "Invalid entry",
                                "Use proto:ipv4[/prefix]:port  — e.g. tcp:93.184.216.34:443 or udp:10.0.0.0/8:*")
            return
        vals = self.list_for(g, "FJ_NET_ALLOW")
        if e not in vals:
            vals.append(e)
            self.stage_list(g, "FJ_NET_ALLOW", vals)
        self.allow_edit.clear()

    def remove_allow(self):
        g = self.single()
        if g is None:
            return
        gone = {i.text() for i in self.allow_list.selectedItems()}
        if gone:
            self.stage_list(g, "FJ_NET_ALLOW", [x for x in self.list_for(g, "FJ_NET_ALLOW") if x not in gone])

    def record_attempt(self, gname: str, addr: str, port: int):
        key = (gname, addr, port)
        t = self.att_table
        if key not in self.attempts:
            if t.rowCount() >= 500:          # a port scan must not be able to freeze the UI
                return
            r = t.rowCount()
            t.insertRow(r)
            self.attempts[key] = r
            t.setItem(r, 0, QTableWidgetItem(gname))
            t.setItem(r, 1, QTableWidgetItem(""))
            t.setItem(r, 2, QTableWidgetItem(addr))
            t.setItem(r, 3, QTableWidgetItem(str(port)))
            t.setItem(r, 4, QTableWidgetItem("0"))
            t.setItem(r, 5, QTableWidgetItem(""))
            b = QPushButton("Whitelist…")
            b.clicked.connect(lambda _=False, k=key: self.whitelist_attempt(k))
            t.setCellWidget(r, 6, b)
        r = self.attempts[key]
        t.item(r, 1).setText(time.strftime("%H:%M:%S"))
        t.item(r, 4).setText(str(int(t.item(r, 4).text()) + 1))
        self.refresh_attempt_row(key)
        self.refresh_attempts()
        if self.tabs.currentIndex() != 2:
            sel = self.single()
            if sel is None or sel.name == gname:
                self.tabs.tabBar().setTabText(2, "Network ●")

    def refresh_attempt_rows(self):
        for k in self.attempts:
            self.refresh_attempt_row(k)

    def refresh_attempts(self):
        """Show only attempts belonging to the selected game (or all if none selected).
        Rows for games that disappeared from disk are always hidden."""
        sel = self.single()
        for key, r in self.attempts.items():
            gname = key[0]
            if gname not in self.by_name:
                self.att_table.setRowHidden(r, True)
                continue
            self.att_table.setRowHidden(r, sel is not None and gname != sel.name)

    def refresh_attempt_row(self, key: tuple):
        gname, addr, port = key
        g = self.by_name.get(gname)
        r = self.attempts[key]
        if g is None:
            return
        mode = g.net_mode(self.defaults)
        listed = core.allow_matches(self.list_for(g, "FJ_NET_ALLOW"), addr, port)
        if core.allow_matches([], addr, port):
            text, st = "loopback (always allowed)", "muted"
        elif mode == "open":
            text, st = "allowed (unrestricted)", "bad"
        elif mode == "off":
            text, st = ("blocked — whitelisted, but network is off" if listed else "blocked (network off)"), "warn"
        elif mode == "learn":
            text, st = ("allowed (whitelisted)", "ok") if listed else ("allowed (learn mode)", "warn")
        elif listed:
            text, st = "allowed (whitelisted)", "ok"
        else:
            text, st = "blocked", "bad"
        self.att_table.setItem(r, 5, self._status_cell(text, st))
        btn = self.att_table.cellWidget(r, 6)
        special = core.is_special_addr(addr)
        can = ":" not in addr and not listed and mode != "open" and not special
        btn.setEnabled(can)
        btn.setToolTip("" if can else ("IPv6 is not supported by the generated filter" if ":" in addr
                                       else "multicast/broadcast address - nothing to whitelist" if special else ""))

    def whitelist_attempt(self, key: tuple):
        gname, addr, port = key
        g = self.by_name.get(gname)
        if g is None:
            return
        proto, ok = QInputDialog.getItem(self, "Whitelist destination",
                                         f"{gname} → {addr}:{port}\n\nProtocol (firejail's trace does not say):",
                                         ["tcp", "udp"], 0, False)
        if not ok:
            return
        e = f"{proto}:{addr}:{port}"
        vals = self.list_for(g, "FJ_NET_ALLOW")
        if e not in vals:
            vals.append(e)
        self.stage_list(g, "FJ_NET_ALLOW", vals)
        extra = ""
        if g.net_mode(self.defaults) == "off":
            extra = " The game's network is still OFF — enable “Allow network access” in Protection for it to take effect."
        self.statusBar().showMessage(f"Staged {e} for {gname}. Press Apply to save.{extra}", 9000)

    def clear_attempts(self):
        self.att_table.setRowCount(0)
        self.attempts.clear()
        self.tabs.tabBar().setTabText(2, "Network")

    # ----------------------------------------------------- launching/monitor
    def launch_selected(self):
        games = self.loaded_games()
        if not games:
            return
        if self.pending_count():
            r = QMessageBox.question(self, "Unapplied changes", "Apply pending changes before launching?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                                     | QMessageBox.StandardButton.Cancel)
            if r == QMessageBox.StandardButton.Cancel:
                return
            if r == QMessageBox.StandardButton.Yes:
                self.apply_changes(quiet=True)
        if len(games) > 1:
            r = QMessageBox.question(self, "Launch several?", f"Launch {len(games)} games at once?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                return
        for g in games:
            self.launch(g)
        self.tabs.setCurrentIndex(3)

    def launch(self, g: core.Game):
        if g.name in self.procs:
            return
        script = g.path / "launch-quarantine.sh"
        if not script.exists():
            QMessageBox.warning(self, "No launcher", f"{script} does not exist. Re-create the game with Add > New game.")
            return
        if not g.exe_ready:
            QMessageBox.warning(self, "Executable not set", f"Set EXE= in {g.path / 'game.conf'} first.")
            return
        p = QProcess(self)
        p.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        p.setWorkingDirectory(str(g.path))
        p.setStandardInputFile(os.devnull)
        self.procs[g.name] = {"proc": p, "buf": ""}
        p.readyReadStandardOutput.connect(lambda n=g.name: self.on_output(n))
        p.finished.connect(lambda code, _st, n=g.name: self.on_finished(n, code))
        p.errorOccurred.connect(lambda _e, n=g.name: self.console.appendPlainText(f"[{n}] failed to start"))
        # own session + process group so Stop can signal the whole tree;
        # no controlling terminal, so nothing leaks to the terminal the UI was started from
        if hasattr(p, "setChildProcessModifier"):
            p.setChildProcessModifier(lambda: os.setsid())
            p.start(str(script), [])
        else:
            # older Qt: keep setsid, but stdin is already /dev/null above
            p.start("setsid", [str(script)])
        self.console.appendPlainText(f"[{g.name}] launching {script}")
        self.refresh_rows()
        self.load_all()

    # ------------------------------------------------------- kernel log tail
    def showEvent(self, e):
        super().showEvent(e)
        self._start_klog()

    def _start_klog(self):
        if getattr(self, "_klog", None) is not None:
            return
        p = QProcess(self)
        p.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        p.readyReadStandardOutput.connect(self._on_klog)
        p.errorOccurred.connect(lambda _e: self.console.appendPlainText("[wq] could not follow kernel log (journalctl)"))
        self._klog = p
        self._klog_buf = ""
        p.start("journalctl", ["-k", "-f", "-n", "0", "-o", "cat"])

    def _klog_game(self, tag: str):
        import re as _re
        for n in self.by_name:
            if _re.sub(r"[^A-Za-z0-9 ._-]", "_", n)[:19] == tag:
                return n
        return None

    def _on_klog(self):
        self._klog_buf += bytes(self._klog.readAllStandardOutput()).decode("utf-8", "replace")
        *lines, self._klog_buf = self._klog_buf.split("\n")
        for line in lines:
            if "wq-net[" not in line:
                continue
            hit = core.parse_klog(line)
            if not hit:
                continue
            gname = self._klog_game(hit[0])
            if gname:
                self.record_attempt(gname, hit[1], hit[2])

    def on_output(self, name: str):
        d = self.procs.get(name)
        if not d:
            return
        d["buf"] += bytes(d["proc"].readAllStandardOutput()).decode("utf-8", "replace")
        *lines, d["buf"] = d["buf"].split("\n")
        for raw in lines:
            line = core.strip_ansi(raw).rstrip("\r")
            if not line:
                continue
            self.console.appendPlainText(f"[{name}] {line}")
            hit = core.parse_connect(line)
            if hit:
                self.record_attempt(name, *hit)

    def on_finished(self, name: str, code: int):
        self.on_output(name)
        self.console.appendPlainText(f"[{name}] exited with code {code}")
        self.procs.pop(name, None)
        self.refresh_rows()
        self.load_all()

    def stop_selected(self):
        for g in self.loaded_games():
            d = self.procs.get(g.name)
            if d:
                try:
                    os.killpg(d["proc"].processId(), signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    d["proc"].terminate()

    def refresh_trace(self):
        """Tail <game>/logs/firejail-trace.log and feed connect() lines to the attempts table."""
        g = self.single()
        if g is None:
            return
        logs = sorted((g.path / "logs").glob("firejail-trace*.log")) if (g.path / "logs").is_dir() else []
        if not logs:
            return
        p = logs[-1]
        try:
            st = p.stat()
        except OSError:
            return
        sig = (g.name, str(p), st.st_mtime_ns, st.st_size)
        if getattr(self, "_trace_sig", None) == sig:
            return
        self._trace_sig = sig
        try:
            with p.open("rb") as f:
                f.seek(max(0, st.st_size - 65536))
                text = f.read().decode("utf-8", "replace")
        except OSError:
            return
        for raw in text.splitlines():
            hit = core.parse_connect(core.strip_ansi(raw))
            if hit:
                self.record_attempt(g.name, *hit)

    def refresh_alerts(self, force: bool = False):
        self.refresh_trace()
        g = self.single()
        if g is None:
            if force:
                self.alerts.clear()
                self.alert_title.setText("Monitor alerts — select a single game")
                self._alert_sig = None
            return
        logs = sorted((g.path / "logs").glob("alerts-*.log")) if (g.path / "logs").is_dir() else []
        if not logs:
            if force or self._alert_sig != (g.name, None):
                self.alerts.setPlainText("")
                self.alert_title.setText(f"Monitor alerts — {g.name}: no alert logs yet")
                self._alert_sig = (g.name, None)
            return
        latest = logs[-1]
        try:
            st = latest.stat()
        except OSError:
            return
        sig = (g.name, str(latest), st.st_mtime_ns, st.st_size)
        if sig == self._alert_sig:
            return
        self._alert_sig = sig
        try:
            with latest.open("rb") as f:
                f.seek(max(0, st.st_size - 65536))
                text = f.read().decode("utf-8", "replace")
        except OSError:
            return
        self.alerts.setPlainText(text)
        self.alerts.verticalScrollBar().setValue(self.alerts.verticalScrollBar().maximum())
        self.alert_title.setText(f"Monitor alerts — {g.name} / {latest.name}")

    # ------------------------------------------------- add game / exe / folder
    def refresh_game_list(self):
        """Re-read the games from disk, leave the panel alone so pending edits stay."""
        self._busy = True
        try:
            self.defaults = core.parse_kv(self.qroot / core.DEFAULTS_NAME)
            self.games = core.scan_games(self.qroot)
            self.by_name = {g.name: g for g in self.games}
            self.populate()
        finally:
            self._busy = False

    def select_game(self, name: str):
        self.tree.blockSignals(True)
        self.tree.clearSelection()
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            if it.data(0, Qt.ItemDataRole.UserRole) == name:
                it.setSelected(True)
                self.tree.setCurrentItem(it)
                self.tree.scrollToItem(it)
        self.tree.blockSignals(False)
        self.on_selection_changed()

    def new_game(self):
        dlg = wq_dialogs.NewGameDialog(self.qroot, {g.name for g in self.games}, self)
        dlg.exec()
        name = dlg.created_name
        if not name:
            return
        self.refresh_game_list()
        self.select_game(name)
        g = self.by_name.get(name)
        if g is None or self.loaded != [name]:
            return
        cands = core.find_exes(g.path, g.runner)
        if len(cands) > 1 or not g.exe_ready:
            note = (f"“{g.exe}” was picked automatically. Choose another if that is wrong."
                    if g.exe_ready else "")
            QTimer.singleShot(0, lambda: self.set_executable(g, note))
        self.statusBar().showMessage(f"Added {name}. Review its protection settings, then Launch.", 8000)

    def set_executable_selected(self):
        g = self.single()
        if g is None:
            QMessageBox.information(self, "Select a game", "Select exactly one game first.")
            return
        self.set_executable(g)

    def set_executable(self, g: core.Game, note: str = ""):
        if not self.resolve_pending("Apply them before changing the executable?"):
            return
        dlg = wq_dialogs.ExePickerDialog(g.path, g.exe, self, note, g.runner)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        rel = dlg.chosen()
        if not rel or rel == g.exe:
            return
        if not core.exe_inside_game(g.path, rel):
            QMessageBox.warning(self, "Not usable",
                                f"{rel} is not a file inside {g.name}/game/ (symlinks out of game/ are refused).")
            return
        try:
            core.write_kv(g.path / "game.conf", {"EXE": rel})
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "Could not write game.conf", str(e))
            return
        self.reload_keep_selection()
        self.statusBar().showMessage(f"{g.name}: executable set to {rel}", 6000)

    def remove_game(self):
        """Move the selected game to the Trash. No Trash on this drive: delete it
        for good, but only after typing the name."""
        g = self.single()
        if g is None:
            QMessageBox.information(self, "Select a game", "Select exactly one game to remove.")
            return
        if g.name in self.procs:
            QMessageBox.warning(self, "Game is running", f"Stop {g.name} before removing it.")
            return
        err = core.validate_removal(self.qroot, g.name)
        if err:
            QMessageBox.warning(self, "Cannot remove", err)
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            size, truncated = core.dir_size(g.path)
        finally:
            QApplication.restoreOverrideCursor()
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Remove game")
        box.setText(f"Remove “{g.name}”?")
        box.setInformativeText(
            f"{g.path}\n\nAbout {core.human_size(size)}{'+' if truncated else ''}: the game files, the Wine "
            f"prefix, saves and logs. The folder is moved to the Trash.")
        b_go = box.addButton("Move to Trash", QMessageBox.ButtonRole.DestructiveRole)
        b_cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(b_cancel)
        box.setEscapeButton(b_cancel)
        box.exec()
        if box.clickedButton() is not b_go:
            return
        res = QFile.moveToTrash(str(g.path))
        ok = res[0] if isinstance(res, tuple) else bool(res)        # PySide gives back (ok, trash path)
        if not ok:
            text, accepted = QInputDialog.getText(
                self, "Delete permanently",
                f"The Trash is not available for this location, so {g.path} would be deleted for good.\n\n"
                f"Type the game name ({g.name}) to confirm:")
            if not accepted or text != g.name:
                return
            if core.validate_removal(self.qroot, g.name):        # re-check right before deleting
                return
            try:
                shutil.rmtree(g.path)                            # does not follow symlinks
            except OSError as e:
                QMessageBox.critical(self, "Could not delete everything", f"{e}\n\nThe folder may be partly deleted.")
        self.staged.pop(g.name, None)
        self.dirty.clear()
        self.refresh_game_list()
        self.loaded = []
        self.on_selection_changed(force=True)
        self.statusBar().showMessage(f"Removed {g.name}", 8000)

    def open_game_folder(self):
        g = self.single()
        if g is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(g.path)))

    def tree_menu(self, pos):
        it = self.tree.itemAt(pos)
        if it is None:
            return
        if not it.isSelected():
            self.tree.blockSignals(True)
            self.tree.clearSelection()
            it.setSelected(True)
            self.tree.setCurrentItem(it)
            self.tree.blockSignals(False)
            self.on_selection_changed()
            if self.loaded != [it.data(0, Qt.ItemDataRole.UserRole)]:
                return                      # user cancelled the "unapplied changes" prompt
        m = QMenu(self)
        m.addAction(self.act_launch)
        m.addAction(self.act_stop)
        m.addSeparator()
        m.addAction(self.act_exe)
        m.addAction(self.act_folder)
        m.addSeparator()
        m.addAction("Remove game…", self.remove_game)
        m.exec(self.tree.viewport().mapToGlobal(pos))

    # ------------------------------------------------- /dev devices, scripts
    def refresh_extras(self):
        """Hidden devices and launch script fields, one game only."""
        g = self.single()
        one = g is not None
        self.dev_list.clear()
        for w in (self.dev_list, self.btn_dev_add, self.btn_dev_rm):
            w.setEnabled(one)
        for ed in self.hook_edits.values():
            ed.clear()
            ed.setToolTip("")
        self.hook_box.setEnabled(one)
        if not one:
            self.dev_note.setText("Select a single game to edit its hidden devices."
                                  if self.loaded else "Select a game first.")
            return
        for path in self.list_for(g, "FJ_DEV_BLOCK"):
            exists = os.path.lexists(path)
            it = QListWidgetItem(path if exists else f"{path}   (not present - skipped at launch)")
            it.setData(Qt.ItemDataRole.UserRole, path)
            lvl, note = core.device_risk(os.path.realpath(path)) if exists else ("ok", "")
            it.setToolTip(note or ("Hidden from the sandbox with --blacklist." if exists else "Does not exist right now."))
            if not exists or lvl == "notable":
                it.setForeground(QBrush(self.theme.color("warn")))
            self.dev_list.addItem(it)
        self.dev_note.setText("" if self.dev_list.count() else "Nothing hidden beyond the boxes above.")
        for key, ed in self.hook_edits.items():
            vals = self.list_for(g, key)
            path = vals[0] if vals else ""
            ed.setText(path)
            if path and not os.path.isfile(path):
                ed.setToolTip("File not found - the launcher will skip it.")
                ed.setText(f"{path}   (missing)")

    def add_device(self):
        g = self.single()
        if g is None:
            QMessageBox.information(self, "Select a game", "Select exactly one game first.")
            return
        have = set(self.list_for(g, "FJ_DEV_BLOCK"))
        dlg = wq_dialogs.DevicePickerDialog(have, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        vals = self.list_for(g, "FJ_DEV_BLOCK")
        before = list(vals)
        for raw in dlg.chosen():
            p = os.path.normpath(raw.strip())
            ok, msg = core.validate_device_path(p)
            if not ok:
                QMessageBox.warning(self, "Cannot hide this device", f"{raw}\n\n{msg}")
                continue
            lvl, note = core.device_risk(p)
            if lvl != "notable":
                lvl, note = core.device_risk(os.path.realpath(p))
            if lvl == "notable":
                r = QMessageBox.question(self, "Hide this device?", f"{p}\n\n{note}\n\nHide it anyway?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.No)
                if r != QMessageBox.StandardButton.Yes:
                    continue
            if p not in vals:
                vals.append(p)
        if vals != before:
            self.stage_list(g, "FJ_DEV_BLOCK", vals)

    def remove_device(self):
        g = self.single()
        if g is None:
            return
        gone = {i.data(Qt.ItemDataRole.UserRole) for i in self.dev_list.selectedItems()}
        if gone:
            self.stage_list(g, "FJ_DEV_BLOCK", [x for x in self.list_for(g, "FJ_DEV_BLOCK") if x not in gone])

    HOOK_TEXT = {"FJ_HOOK_PRE": "before launch", "FJ_HOOK_POST": "after exit"}

    def choose_hook(self, key: str):
        g = self.single()
        if g is None:
            QMessageBox.information(self, "Select a game", "Select exactly one game first.")
            return
        cur = (self.list_for(g, key) or [""])[0]
        start = os.path.dirname(cur) if cur else str(Path.home())
        f, _ = QFileDialog.getOpenFileName(self, f"Shell script to run {self.HOOK_TEXT[key]}", start,
                                           "Shell scripts (*.sh);;All files (*)")
        if not f:
            return
        f = os.path.abspath(f)
        ok, msg = core.validate_hook_path(f)
        if not ok:
            QMessageBox.warning(self, "Cannot use this script", msg)
            return
        r = QMessageBox.warning(
            self, "Run outside the sandbox?",
            f"{f}\n\nThis script will run on your machine, with your normal permissions and no sandbox, "
            f"every time {g.name} is launched ({self.HOOK_TEXT[key]}). Only attach scripts you wrote or trust.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if r != QMessageBox.StandardButton.Yes:
            return
        self.stage_list(g, key, [f])
        self.tabs.setCurrentIndex(1)

    def clear_hook(self, key: str):
        g = self.single()
        if g is not None and self.list_for(g, key):
            self.stage_list(g, key, [])

    # ---------------------------------------------------------------- misc
    def open_debug(self):
        wq_debug.DebugDialog(self.qroot, self).exec()

    def open_settings(self):
        d = SettingsDialog(self.settings, self)
        if d.exec() != QDialog.DialogCode.Accepted:
            return
        new = d.values()
        root_changed = new["qroot"] and new["qroot"] != str(self.qroot)
        if root_changed and not (Path(new["qroot"]) / "config.sh").is_file():
            QMessageBox.warning(self, "Not a wine-quarantine folder", f"No config.sh in {new['qroot']}.")
            new["qroot"] = str(self.qroot)
            root_changed = False
        self.settings.data.update(new)
        self.settings.save()
        self.theme.apply()
        if root_changed:
            self.qroot = Path(new["qroot"])
            self.rescan()

    def tabChanged(self, i):  # noqa: N802
        if i == 2:
            self.tabs.tabBar().setTabText(2, "Network")

    def closeEvent(self, e):  # noqa: N802
        if self.procs:
            r = QMessageBox.question(self, "Games running",
                                     "Games are still running. Stop them and quit?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                e.ignore()
                return
            for d in list(self.procs.values()):
                try:
                    os.killpg(d["proc"].processId(), signal.SIGTERM)
                except OSError:
                    d["proc"].terminate()
                d["proc"].waitForFinished(3000)
        k = getattr(self, "_klog", None)
        if k is not None:
            k.terminate()
            k.waitForFinished(1000)
        super().closeEvent(e)


# ---------------------------------------------------------------------------
def find_qroot(settings: Settings) -> Path | None:
    cands = [os.environ.get("WQ_ROOT"), str(Path(__file__).resolve().parent.parent),
             settings.data.get("qroot"), os.getcwd()]
    for c in cands:
        if c and (Path(c) / "config.sh").is_file() and (Path(c) / "_launch-core.sh").is_file():
            return Path(c).resolve()
    return None


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    settings = Settings()

    qroot = find_qroot(settings)
    while qroot is None:
        d = QFileDialog.getExistingDirectory(None, "Select your wine-quarantine folder (contains config.sh)",
                                             str(Path.home()))
        if not d:
            return 1
        if (Path(d) / "config.sh").is_file() and (Path(d) / "_launch-core.sh").is_file():
            qroot = Path(d).resolve()
        else:
            QMessageBox.warning(None, "Not a wine-quarantine folder", "config.sh / _launch-core.sh not found there.")
    settings.data["qroot"] = str(qroot)
    settings.save()

    theme = ThemeManager(app, settings)
    theme.apply()
    win = MainWindow(settings, theme, qroot)
    win.tabs.currentChanged.connect(win.tabChanged)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

