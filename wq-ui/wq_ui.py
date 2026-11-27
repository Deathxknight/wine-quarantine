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
import sys
import time
from pathlib import Path

from PySide6.QtCore import (QByteArray, QEvent, QFile, QFileSystemWatcher, QObject, QPointF, QProcess, QProcessEnvironment, QRectF, QSize, Qt, QTimer,
                            QUrl, Signal)
from PySide6.QtGui import (QAction, QBrush, QColor, QDesktopServices, QGuiApplication, QIcon, QImage,
                           QFontDatabase, QKeySequence, QPainter, QPainterPath, QPalette, QPen, QPixmap, QPolygonF,
                           QFont, QSyntaxHighlighter, QTextCharFormat)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QPushButton, QScrollArea, QSizePolicy, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget,
    QToolBar, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_core as core  # noqa: E402
import wq_debug  # noqa: E402
import wq_dialogs  # noqa: E402
import wq_posture  # noqa: E402
import wq_runlog as runlog  # noqa: E402
import wq_visuals  # noqa: E402
import wq_sandboxtest  # noqa: E402
import wq_relax_dialog  # noqa: E402
import wq_notify  # noqa: E402
import wq_themes  # noqa: E402
import wq_xray  # noqa: E402
import wq_entropy_tab  # noqa: E402
import wq_findings_tab  # noqa: E402

APP_NAME = "wq-ui"
DESKTOP_ID = "wine-quarantine"     # app id on Wayland / WM_CLASS on X11: must match wine-quarantine.desktop
ICON_DIR = Path(__file__).resolve().parent / "icons"
CONF_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / APP_NAME
SETTINGS_FILE = CONF_DIR / "settings.json"
DEFAULT_CSS = CONF_DIR / "style.css"
THEMES_DIR = CONF_DIR / "themes"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / APP_NAME
MARK = "wq-ui integration"

Checked, Unchecked, Partial = (Qt.CheckState.Checked, Qt.CheckState.Unchecked,
                               Qt.CheckState.PartiallyChecked)


# settings
class Settings:
    DEFAULTS = {"qroot": "", "theme": "system", "css_enabled": True, "css_path": str(DEFAULT_CSS),
                # remembered between sessions (written on close)
                "geometry": "", "splitter": [], "tab": 0, "last_games": [],
                "notify": True, "notify_clean": False, "notify_unfocused_only": True,   # desktop notifications
                "hidden_cols": [4],     # Display is off by default; right-click the list header to change
                "xray_auto": True, "xray_access": True,           # X-Ray tab checkboxes
                "xray_power": None, "xray_cap": 100}               # X-Ray tile sizing (power None: migrate old "xray_boost")

    def __init__(self):
        self.data = dict(self.DEFAULTS)
        try:
            self.data.update(json.loads(SETTINGS_FILE.read_text()))
        except (OSError, ValueError):
            pass

    def save(self):
        CONF_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(self.data, indent=2))


# theme: built-in light/dark + user CSS that reloads when the file changes
class ThemeManager(QObject):
    changed = Signal()

    def __init__(self, app: QApplication, settings: Settings):
        super().__init__()
        self.app, self.settings = app, settings
        self.tokens = dict(core.DARK)
        self.mode = "dark"
        self.theme_id = ""            # "" = plain light/dark, else a wq_themes id
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

    def available_themes(self) -> dict:
        return wq_themes.all_themes(THEMES_DIR)

    def resolve_mode(self) -> str:
        t = self.settings.data["theme"]
        if t in ("light", "dark"):
            return t
        named = self.available_themes().get(t)
        if named is not None:
            return named.mode
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

    def _watch(self, path: Path | None, named=None):
        want = []
        if named is not None and named.id.startswith("user:"):
            f = THEMES_DIR / (named.id[5:] + ".css")
            if f.exists():
                want.append(str(f))
        if THEMES_DIR.is_dir():
            want.append(str(THEMES_DIR))
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
        named = self.available_themes().get(self.settings.data["theme"])
        self.theme_id = named.id if named else ""
        tokens, theme_qss = wq_themes.resolve_tokens(named, self.mode)
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
        self._watch(path, named)
        tokens.update(ensure_checkbox_icons(tokens))
        self.tokens = tokens
        self.app.setPalette(self._palette(tokens))
        self.app.setStyleSheet(core.substitute_tokens(
            core.BUILTIN_QSS + "\n" + theme_qss + "\n" + extra, tokens))
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


# checkbox boxes and toolbar icons are drawn here
# qss can't load data: URIs, and the rescan glyph wasn't in the font
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
    elif name == "test":                            # shield with a check mark
        sh = QPainterPath()
        sh.moveTo(9.0, 2.8)
        sh.lineTo(14.5, 4.8)
        sh.lineTo(14.5, 9.0)
        sh.cubicTo(14.5, 12.5, 12.0, 14.5, 9.0, 15.8)
        sh.cubicTo(6.0, 14.5, 3.5, 12.5, 3.5, 9.0)
        sh.lineTo(3.5, 4.8)
        sh.closeSubpath()
        p.drawPath(sh)
        p.drawLine(QPointF(6.4, 9.2), QPointF(8.4, 11.2))
        p.drawLine(QPointF(8.4, 11.2), QPointF(11.8, 7.0))
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


def app_icon() -> QIcon:
    """The Wine Quarantine logo: the SVG plus fixed-size PNGs (the SVG alone blurs in some taskbars)."""
    ic = QIcon()
    svg = ICON_DIR / f"{DESKTOP_ID}.svg"
    if svg.is_file():
        ic.addFile(str(svg))
    for n in (16, 24, 32, 48, 64, 128, 256, 512):
        png = ICON_DIR / f"{DESKTOP_ID}-{n}.png"
        if png.is_file():
            ic.addFile(str(png))
    return ic if not ic.isNull() else QIcon.fromTheme(DESKTOP_ID)


# widgets
class TriBox(QCheckBox):
    """Checkbox that shows a partial state when the selected games disagree,
    but a user click only ever goes checked <-> unchecked."""

    def __init__(self, text: str, key: str):
        super().__init__(text)
        self.key = key
        self.setTristate(True)

    def nextCheckState(self):  # noqa: N802  (Qt override)
        self.setCheckState(Unchecked if self.checkState() == Checked else Checked)


class CollapsibleGroup(QGroupBox):
    """A group with a clickable header: arrow, title, an "N/M on" count and a "k relaxed" badge
    (settings weaker than the Strict preset). Collapsed groups still show both at a glance."""

    def __init__(self, title: str, open_: bool = False, counted: bool = True):
        super().__init__()
        self.title_text = title
        self.counted = counted
        self.setStyleSheet("QGroupBox { margin-top: 0; padding: 0; }")   # no title strip, the header is a row
        self.boxes: list[TriBox] = []
        self._open = open_
        outer = QVBoxLayout(self)
        self._outer = outer
        outer.setContentsMargins(8, 2, 8, 2)
        outer.setSpacing(2)
        head = QHBoxLayout()
        self.toggle = QToolButton()
        self.toggle.setText(title)
        self.toggle.setAutoRaise(True)
        self.toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.clicked.connect(lambda: self.set_open(not self._open))
        self.count = label("", "muted", wrap=False)
        self.relaxed = label("", "warn", name="badge", wrap=False)
        head.addWidget(self.toggle)
        head.addStretch(1)
        head.addWidget(self.count)
        head.addWidget(self.relaxed)
        outer.addLayout(head)
        self.body_w = QWidget()
        self.body = QVBoxLayout(self.body_w)
        self.body.setContentsMargins(4, 0, 4, 0)
        outer.addWidget(self.body_w)
        self.set_open(open_)

    def set_open(self, on: bool):
        self._open = on
        self.body_w.setVisible(on)
        self._outer.setContentsMargins(8, 2, 8, 8 if on else 2)
        self.toggle.setArrowType(Qt.ArrowType.DownArrow if on else Qt.ArrowType.RightArrow)

    def add_boxes(self, boxes: list[TriBox], cols: int = 2):
        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(4)
        for i, b in enumerate(boxes):
            grid.addWidget(b, i // cols, i % cols)
        for c in range(cols):
            grid.setColumnStretch(c, 1)
        self.body.addLayout(grid)

    def collect(self):
        self.boxes = self.findChildren(TriBox)

    def refresh(self) -> int:
        """Update the header badges and the per-box markers. Returns how many boxes are relaxed."""
        relaxed = on = 0
        for b in self.boxes:
            st = b.checkState()
            rel = core.is_relaxed(b.key, None if st == Partial else st == Checked)
            relaxed += rel
            on += st == Checked
            if bool(b.property("relaxed")) != rel:
                set_prop(b, "relaxed", rel)
        shown = self.counted and bool(self.boxes)
        self.count.setText(f"{on}/{len(self.boxes)} on" if shown else "")
        self.count.setVisible(shown)
        self.relaxed.setText(f"{relaxed} relaxed")
        self.relaxed.setVisible(relaxed > 0)
        return relaxed

    def apply_filter(self, query: str, relaxed_only: bool):
        q = query.strip().lower()
        if not q and not relaxed_only:
            for b in self.boxes:
                b.setVisible(True)
            self.setVisible(True)
            self.body_w.setVisible(self._open)
            return
        title_hit = bool(q) and q in self.title_text.lower()
        shown = 0
        for b in self.boxes:
            hit = not q or title_hit or q in b.text().lower() or q in b.toolTip().lower()
            if relaxed_only:
                hit = hit and bool(b.property("relaxed"))
            b.setVisible(hit)
            shown += hit
        self.setVisible(shown > 0 or (title_hit and not relaxed_only and not self.boxes))
        if shown:
            self.body_w.setVisible(True)


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


# settings dialog
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
        themes = wq_themes.all_themes(THEMES_DIR)
        for group, mode in (("Dark themes", "dark"), ("Light themes", "light")):
            ids = [t for t in themes.values() if t.mode == mode]
            if ids:
                self.theme.insertSeparator(self.theme.count())
                for t in ids:
                    self.theme.addItem(t.label + ("  (yours)" if t.id.startswith("user:") else ""), t.id)
        self.theme.setCurrentIndex(max(0, self.theme.findData(s["theme"])))
        form.addRow("Theme", self.theme)
        self.theme_hint = label("", name="hint")
        self.theme.currentIndexChanged.connect(lambda *_: self._theme_hint(themes))
        form.addRow("", self.theme_hint)
        self._theme_hint(themes)

        self.css_on = QCheckBox("Load custom CSS (reloads live when the file changes)")
        self.css_on.setChecked(bool(s["css_enabled"]))
        form.addRow("", self.css_on)
        self.css = QLineEdit(s["css_path"])
        b2 = QPushButton("Browse…")
        b2.clicked.connect(self._browse_css)
        form.addRow("CSS file", self._row(self.css, b2))
        form.addRow("", label("{mode} in the path becomes “light” or “dark” (the theme's base), e.g. "
                              "~/.config/wq-ui/matugen-{mode}.css. Lets matugen write one file per mode.",
                              name="hint"))

        self.notify_on = QCheckBox("Notify me about alerts and warnings")
        self.notify_on.setChecked(bool(s.get("notify", True)))
        form.addRow("Notifications", self.notify_on)
        self.notify_bg = QCheckBox("Only while this window is not in focus")
        self.notify_bg.setChecked(bool(s.get("notify_unfocused_only", True)))
        form.addRow("", self.notify_bg)
        self.notify_clean = QCheckBox("Also tell me when a run ends clean")
        self.notify_clean.setChecked(bool(s.get("notify_clean", False)))
        form.addRow("", self.notify_clean)
        test = QPushButton("Send test notification")
        self._notifier = wq_notify.Notifier()
        test.clicked.connect(lambda: self._test_notify(test))
        form.addRow("", test)
        if not self._notifier.available:
            test.setEnabled(False)
            form.addRow("", label("notify-send was not found. Install libnotify (Arch: pacman -S libnotify) "
                                  "to get notifications.", "warn", "hint"))

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def _test_notify(self, btn: QPushButton):
        ok = self._notifier.send("wine-quarantine", "Notifications are working.", "normal")
        btn.setText("Sent" if ok else "Could not run notify-send")
        def _reset():
            try:
                btn.setText("Send test notification")
            except RuntimeError:                           # the dialog was closed meanwhile
                pass
        QTimer.singleShot(2500, _reset)

    def _theme_hint(self, themes: dict):
        t = themes.get(self.theme.currentData())
        base = "Add your own: put a .css file with @define-color lines in ~/.config/wq-ui/themes/."
        self.theme_hint.setText((f"Colours from {t.source}. " if t else "") + base)

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
                "css_enabled": self.css_on.isChecked(), "css_path": self.css.text().strip(),
                "notify": self.notify_on.isChecked(), "notify_unfocused_only": self.notify_bg.isChecked(),
                "notify_clean": self.notify_clean.isChecked()}


# main window
# ---- wq-log-highlighter begin
# log colouring for the Launcher output and Monitor alerts panes.
# Display only: pane text, log files and copy/paste are untouched.
import re as _re

_LOG_TS = _re.compile(r"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]")
_LOG_PREFIX = _re.compile(r"^\[[^\]\s][^\]]*\](?= )")
_LOG_HEAD = _re.compile(r"^(?:\[[^\]]+\] )?(?:--- .+ ---|-- .+)$")
_LOG_BAR = _re.compile(r"^(?:\[[^\]]+\] )?={5,}\s*$")
_LOG_ERR = _re.compile(r"^(?:\[[^\]]+\] )?(FATAL|ERROR|Error)\b")
_LOG_VERDICT = _re.compile(r"VERDICT: (REVIEW NEEDED|CLEAN|OK|PASS)")
_LOG_TAGS = (("[ALERT]", "alert_tag"), ("[WARN]", "warn_tag"), ("[LEAK]", "alert_tag"),
             ("[INFO]", "info"), ("[info]", "info"), ("[ok]", "ok"))


def log_spans(line: str, prefix: bool = False) -> list[tuple[int, int, str]]:
    """(start, length, style) in the order they are applied; later spans win."""
    n = len(line)
    out: list[tuple[int, int, str]] = []
    if "[ALERT]" in line or "[LEAK]" in line:
        out.append((0, n, "alert_line"))
    elif "[WARN]" in line:
        out.append((0, n, "warn_line"))
    if _LOG_HEAD.match(line):
        out.append((0, n, "heading"))
    elif _LOG_BAR.match(line):
        out.append((0, n, "dim"))
    m = _LOG_ERR.match(line)
    if m:
        out.append((m.start(1), m.end(1) - m.start(1), "bad"))
    if prefix:
        m = _LOG_PREFIX.match(line)
        if m:
            out.append((0, m.end(), "dim"))
    for m in _LOG_TS.finditer(line):
        out.append((m.start(), m.end() - m.start(), "dim"))
    for tag, style in _LOG_TAGS:
        i = line.find(tag)
        while i != -1:
            out.append((i, len(tag), style))
            i = line.find(tag, i + len(tag))
    m = _LOG_VERDICT.search(line)
    if m:
        out.append((m.start(1), m.end(1) - m.start(1), "bad" if m.group(1) == "REVIEW NEEDED" else "verdict_ok"))
    return out


class LogHighlighter(QSyntaxHighlighter):
    _fmt: dict = {}
    _prefix = False

    def __init__(self, document, theme, prefix: bool = False):
        super().__init__(document)
        self._theme, self._prefix = theme, prefix
        self.refresh()

    def refresh(self):
        c = self._theme.color

        def f(fg=None, bg=None, bold=False):
            t = QTextCharFormat()
            if fg:
                t.setForeground(c(fg))
            if bg:
                t.setBackground(c(bg))
            if bold:
                t.setFontWeight(QFont.Weight.Bold)
            return t

        self._fmt = {
            "alert_line": f("error"), "warn_line": f("warn"),
            "alert_tag": f("surface", "error", True), "warn_tag": f("surface", "warn", True),
            "heading": f("primary", bold=True), "dim": f("on_surface_variant"),
            "info": f("primary"), "ok": f("ok"), "bad": f("error", bold=True),
            "verdict_ok": f("ok", bold=True),
        }
        self.rehighlight()

    def highlightBlock(self, text):
        for start, length, style in log_spans(text, self._prefix):
            fmt = self._fmt.get(style)
            if fmt is not None:
                self.setFormat(start, length, fmt)
# ---- wq-log-highlighter end


class _ClickOpensCombo(QObject):
    """Editable combo boxes only open their list from the arrow. A plain click on the text opens it
    too; Ctrl+click (or Tab into the field) puts the caret in to type a custom value."""

    def __init__(self, combo):
        super().__init__(combo)
        self.combo = combo
        combo.lineEdit().installEventFilter(self)

    def eventFilter(self, obj, ev):
        if (ev.type() == QEvent.Type.MouseButtonPress
                and ev.button() == Qt.MouseButton.LeftButton
                and not (ev.modifiers() & Qt.KeyboardModifier.ControlModifier)
                and self.combo.isEnabled()):
            self.combo.showPopup()
            return True
        return False


class _KeepSelection(QObject):
    """Clicking empty space in the game list (or Ctrl-clicking the only selected game) would
    clear the selection, which greys out every tab. Swallow those clicks instead."""

    def __init__(self, tree):
        super().__init__(tree)
        self.tree = tree

    def eventFilter(self, obj, ev):  # noqa: N802  (Qt override)
        if (ev.type() in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonRelease,
                          QEvent.Type.MouseButtonDblClick)
                and ev.button() == Qt.MouseButton.LeftButton):
            it = self.tree.itemAt(ev.position().toPoint())
            if it is None:
                return True
            if (ev.modifiers() & Qt.KeyboardModifier.ControlModifier) and it.isSelected() \
                    and len(self.tree.selectedItems()) == 1:
                return True
        return False


class MainWindow(QMainWindow):
    COLS = ["Game", "Executable", "Location", "Network", "Display", "State", "Last run"]

    def __init__(self, settings: Settings, theme: ThemeManager, qroot: Path):
        super().__init__()
        self.settings, self.theme, self.qroot = settings, theme, qroot
        self.setWindowTitle("wine-quarantine")
        self.resize(1280, 800)
        self.setAcceptDrops(True)                         # drop a folder, exe, script or archive on the window

        self.games: list[core.Game] = []
        self.by_name: dict[str, core.Game] = {}
        self.defaults: dict[str, list[str]] = {}
        self.loaded: list[str] = []                       # games the panel currently shows
        self.dirty: set[str] = set()                      # scalar keys touched in the panel
        self.staged: dict[str, dict[str, list[str]]] = {}  # list keys edited, per game
        self.procs: dict[str, dict] = {}
        self.baselining: set[str] = set()                 # waiting for the X-Ray baseline before they start
        self.stopping: set[str] = set()                   # Stop pressed, launcher still finishing its checks
        self.attempts: dict[tuple, int] = {}              # (game, addr, port) -> table row
        self.attempt_proto: dict[tuple, str] = {}         # (game, addr, port) -> "tcp" / "udp" when the kernel log said
        self._learn_entries: list[str] = []               # allow-list entries the host map could stage
        self._loading = False
        self._busy = False
        self._alert_sig: tuple | None = None
        self.notifier = wq_notify.Notifier()
        self.watch = wq_notify.AlertWatch()               # new alerts of running games -> notify-send

        self.boxes: dict[str, TriBox] = {}
        self.texts: dict[str, QComboBox] = {}
        self.plains: dict[str, QPlainTextEdit] = {}       # multi-line list keys edited as text (FJ_EXTRA_ARGS)
        self.orig_boxes: dict[str, Qt.CheckState] = {}    # as loaded, so undoing an edit isn't a change
        self.orig_texts: dict[str, str] = {}
        self.hook_edits: dict[str, QLineEdit] = {}
        self.icon_targets: list[tuple[str, object]] = []
        self._col0_sized = False

        self._build_ui()
        theme.changed.connect(self.on_theme_changed)
        self.rescan()
        self._restore_session()

        self.alert_timer = QTimer(self)
        self.alert_timer.timeout.connect(self.refresh_alerts)
        self.alert_timer.timeout.connect(self.poll_notifications)
        self.alert_timer.start(1500)
        self.age_timer = QTimer(self)                  # keeps "5m ago" in the Last run column honest
        self.age_timer.timeout.connect(self.refresh_rows)
        self.age_timer.start(60000)

    # UI
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
        self.act_setup = QAction("Run setup file…", self)
        self.act_setup.setToolTip("Run an installer once inside the sandbox. The game's executable is not changed.")
        self.act_setup.triggered.connect(self.run_setup_selected)
        self.act_hook_pre = QAction("Script before launch…", self)
        self.act_hook_pre.triggered.connect(lambda: self.choose_hook("FJ_HOOK_PRE"))
        self.act_hook_post = QAction("Script after exit…", self)
        self.act_hook_post.triggered.connect(lambda: self.choose_hook("FJ_HOOK_POST"))
        self.act_dev = QAction("Hide a /dev device…", self)
        self.act_dev.triggered.connect(self.add_device)
        self.act_remove = QAction("Remove", self)
        self.act_remove.setToolTip("Move the selected game to the Trash")
        self.act_remove.triggered.connect(self.remove_game)
        self.act_folder = QAction("Open game folder", self)
        self.act_folder.triggered.connect(self.open_game_folder)

        add_menu = QMenu(self)
        add_menu.addAction(self.act_new)
        add_menu.addSeparator()
        add_menu.addAction(self.act_setup)
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
        self.add_btn.setToolTip("New game, launch script or hidden /dev device")
        self.add_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.add_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.add_btn.setMenu(add_menu)
        tb.addWidget(self.add_btn)
        tb.addSeparator()

        self.act_launch = QAction("Launch", self)
        self.act_launch.setShortcut(QKeySequence("Ctrl+Return"))
        self.act_launch.setToolTip("Launch (Ctrl+Enter)")
        self.act_launch.triggered.connect(self.launch_selected)
        self.act_stop = QAction("Stop", self)
        self.act_stop.setShortcut(QKeySequence("Ctrl+."))
        self.act_stop.setToolTip("Stop (Ctrl+.)")
        self.act_stop.triggered.connect(self.stop_selected)
        self.act_test = QAction("Test sandbox", self)
        self.act_test.setShortcut(QKeySequence("Ctrl+T"))
        self.act_test.setToolTip("Run a probe inside the sandbox with the selected game's profile and show what gets through (Ctrl+T)")
        self.act_test.triggered.connect(self.test_sandbox)
        self.act_relax = QAction("Relax…", self)
        self.act_relax.setShortcut(QKeySequence("Ctrl+R"))
        self.act_relax.setToolTip("Launch the selected game and, each time it exits right away, switch off the next "
                                  "restriction and try again until it stays up (Ctrl+R)")
        self.act_relax.triggered.connect(self.relax_selected)
        act_rescan = QAction("Rescan", self)
        act_rescan.setShortcut(QKeySequence("F5"))
        act_rescan.setToolTip("Rescan games (F5)")
        act_rescan.triggered.connect(lambda: self.rescan())
        act_settings = QAction("Settings", self)
        act_settings.setShortcut(QKeySequence("Ctrl+,"))
        act_settings.setToolTip("Settings (Ctrl+,)")
        act_settings.triggered.connect(self.open_settings)
        for a in (self.act_launch, self.act_stop, self.act_test, self.act_relax):
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
                             ("test", self.act_test),
                             ("rescan", act_rescan), ("remove", self.act_remove), ("settings", act_settings)]

        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 8)

        self.integration_banner = label("", "warn", "banner")
        root.addWidget(self.integration_banner)

        split = self.split = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(split, 1)

        # left: game list
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 8, 0)
        self.filter = QLineEdit()
        self.filter.setObjectName("gameFilter")
        self.filter.setPlaceholderText("Filter games…  (Ctrl+F)")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self.apply_filter)
        lv.addWidget(self.filter)
        act_find = QAction(self)
        act_find.setShortcut(QKeySequence("Ctrl+F"))
        act_find.triggered.connect(self._focus_filter)
        self.addAction(act_find)
        self.tree = QTreeWidget()
        self.tree.setObjectName("gameList")
        self.tree.setColumnCount(len(self.COLS))
        self.tree.setHeaderLabels(self.COLS)
        self.tree.setRootIsDecorated(False)
        self.tree.setIconSize(QSize(20, 20))          # the shield ring next to each game's name
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setUniformRowHeights(True)
        # exe column stretches, game name gets its own width (set in populate()).
        # no more "7 Da... Die" and no horizontal scrollbar
        hdr = self.tree.header()
        hdr.setStretchLastSection(False)
        hdr.setMinimumSectionSize(60)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.setColumnWidth(0, 160)
        for i, w in ((2, 112), (3, 68), (4, 80), (5, 84), (6, 116)):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)
            self.tree.setColumnWidth(i, w)
        for i in self.settings.data.get("hidden_cols") or []:
            if isinstance(i, int) and 0 < i < len(self.COLS):
                self.tree.setColumnHidden(i, True)
        hdr.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        hdr.customContextMenuRequested.connect(self.header_menu)
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.tree.viewport().installEventFilter(_KeepSelection(self.tree))
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.tree_menu)
        self.tree.itemSelectionChanged.connect(self.on_selection_changed)
        self.tree.itemSelectionChanged.connect(self.apply_filter)
        self.tree.itemDoubleClicked.connect(lambda *_: self.launch_selected())
        lv.addWidget(self.tree, 1)
        self.empty_hint = label("No games yet. Use Add > New game… (Ctrl+N) to quarantine your first one.",
                                "muted", "hint")
        lv.addWidget(self.empty_hint)
        lv.addWidget(label("Ctrl/Shift-click selects several games · double-click launches", name="hint"))
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
        self.monitor_tab = self._build_monitor_tab()
        self.tabs.addTab(self.monitor_tab, "Monitor")
        self.xray_tab = wq_xray.XRayTab(self.theme, self.settings, CACHE_DIR)
        self.xray_tab.changed.connect(self.on_xray_changed)
        self.tabs.addTab(self.xray_tab, "X-Ray")
        self.runs_tab = wq_visuals.RunsTab(self.theme)
        self.tabs.addTab(self.runs_tab, "Runs")
        self.entropy_tab = wq_entropy_tab.EntropyTab(self.theme)   # last, so Ctrl+1..6 keep their meaning
        self.tabs.addTab(self.entropy_tab, "Entropy")
        self.findings_tab = wq_findings_tab.FindingsTab(self.theme, self.qroot)   # what YARA/capa/ClamAV/pre-launch found
        self.tabs.addTab(self.findings_tab, "Findings")
        for i in range(self.tabs.count()):
            a = QAction(self)
            a.setShortcut(QKeySequence(f"Ctrl+{i + 1}"))
            a.triggered.connect(lambda _=False, i=i: self.tabs.setCurrentIndex(i))
            self.addAction(a)

        self.apply_bar = QWidget()
        bar = QHBoxLayout(self.apply_bar)
        bar.setContentsMargins(0, 0, 0, 0)
        self.pending_label = label("", "muted", wrap=False)
        bar.addWidget(self.pending_label, 1)
        self.btn_reset = QPushButton("Reset to defaults")
        self.btn_reset.clicked.connect(self.reset_to_defaults)
        self.btn_save_defaults = QPushButton("Save as default profile")
        self.btn_save_defaults.setToolTip("Save the boxes as shown to profile.defaults.conf.\n"
                                          "Games without their own setting use it.")
        self.btn_save_defaults.clicked.connect(self.save_as_defaults)
        self.btn_apply = QPushButton("Apply")
        self.btn_apply.setProperty("accent", True)
        self.btn_apply.setShortcut(QKeySequence("Ctrl+S"))
        self.btn_apply.clicked.connect(lambda: self.apply_changes())
        for b in (self.btn_reset, self.btn_save_defaults, self.btn_apply):
            bar.addWidget(b)
        rv.addWidget(self.apply_bar)
        # Apply / Reset / Save only mean something for the profile tabs, not for the log view
        self.tabs.currentChanged.connect(lambda i: self.apply_bar.setVisible(self.tabs.widget(i) not in (self.monitor_tab, self.xray_tab, self.runs_tab)))
        split.addWidget(right)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 6)
        left.setMinimumWidth(300)                      # the game list never collapses to a sliver
        right.setMinimumWidth(480)
        split.setCollapsible(0, False)
        split.setCollapsible(1, False)
        split.setHandleWidth(6)
        split.setSizes([680, 600])

        self.statusBar().addWidget(QLabel(self._tool_status()))
        self.summary = QLabel("")
        self.statusBar().addPermanentWidget(self.summary)
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
        self.posture_card = wq_visuals.PostureCard(self.theme)
        v.addWidget(self.posture_card)

        # presets: they only tick boxes, nothing is saved until Apply
        self.preset_btns: dict[str, QPushButton] = {}
        self.preset_group = QButtonGroup(self)
        self.preset_group.setExclusive(True)
        prow = QHBoxLayout()
        prow.setSpacing(0)
        for name in (*core.PRESETS, "Custom"):
            b = QPushButton(name)
            b.setCheckable(True)
            b.setProperty("seg", True)
            b.setToolTip(core.PRESET_NOTES.get(name, "Your own mix. Tick a preset to start from it."))
            self.preset_group.addButton(b)
            self.preset_btns[name] = b
            b.clicked.connect(lambda _=False, n=name: self._apply_preset(n))
            prow.addWidget(b)
        prow.addStretch(1)
        v.addLayout(prow)
        self.preset_note = label("", name="hint")
        v.addWidget(self.preset_note)

        frow = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search settings")
        self.search.setClearButtonEnabled(True)
        self.relaxed_only = QCheckBox("Relaxed only")
        self.relaxed_only.setToolTip("Show only the settings that are weaker than Strict.")
        self.search.textChanged.connect(self._apply_filter)
        self.relaxed_only.toggled.connect(self._apply_filter)
        frow.addWidget(self.search, 1)
        frow.addWidget(self.relaxed_only)
        v.addLayout(frow)
        self.groups: list[CollapsibleGroup] = []

        def group(title, opts, open_=False):
            g = CollapsibleGroup(title, open_)
            g.add_boxes([self._tribox(o.label, o.key, o.tip) for o in opts])
            self._add_group(g, v)
            return g.body

        iso = [o for o in core.BOOL_OPTS if o.group == "isolation"]
        group("Isolation", [o for o in iso if o.key not in core.ADVANCED_KEYS], open_=True)
        gl_dev = group("Devices", [o for o in core.BOOL_OPTS if o.group == "devices"])
        group("Monitoring", [o for o in core.BOOL_OPTS if o.group == "monitoring"])
        group("Advanced", [o for o in iso if o.key in core.ADVANCED_KEYS])

        # hide single /dev nodes (--blacklist)
        gl_dev.addWidget(label("Hidden /dev devices (one game at a time)", name="hint"))
        self.dev_list = QListWidget()
        self.dev_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.dev_list.setMaximumHeight(96)
        self.dev_list.setToolTip("Hidden from the sandbox. Everything else in /dev stays visible.")
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

        # resource limits + free-form options
        g = CollapsibleGroup("Limits and extra options", counted=False)
        gl = g.body
        gl.addWidget(label("Limits count only this game's processes (firejail, Wine, the game) and are enforced by a systemd "
                           "cgroup scope. Without a systemd user session the launch is cancelled.",
                           name="hint"))
        for key, text, tip, presets in (
            ("FJ_TASKS_MAX", "Max processes and threads",
             "Caps processes and threads so a fork bomb can't freeze the desktop. "
             "Wine games use up to ~1500, so 4096 is a safe start.",
             [("No limit", ""), ("2048", "2048"), ("4096", "4096"), ("8192", "8192")]),
            ("FJ_MEMORY_MAX", "Max memory",
             "The game is throttled, then killed, above this, so your desktop stays out of swap.",
             [("No limit", ""), ("2G", "2G"), ("4G", "4G"), ("8G", "8G"), ("16G", "16G")]),
            ("FJ_SECCOMP_EXTRA", "Extra blocked syscalls",
             "Added to SECCOMP_DROP from config.sh. Needs the seccomp filter on. "
             "Anti-cheat and some games need ptrace.",
             [("None", ""), ("ptrace + cross-process memory", "ptrace,process_vm_readv,process_vm_writev"),
              ("mount family", "mount,umount2,pivot_root")]),
        ):
            row = QHBoxLayout()
            lab = QLabel(text)
            lab.setMinimumWidth(170)
            row.addWidget(lab)
            c = QComboBox()
            c.setEditable(True)
            c.setMinimumWidth(180)
            for t, val in presets:
                c.addItem(t, val)
            c.lineEdit().setPlaceholderText(core.TEXT_HINTS[key])
            _ClickOpensCombo(c)
            c.setToolTip(tip)
            c.editTextChanged.connect(lambda *_, k=key: self._text_edited(k))
            self.texts[key] = c
            row.addWidget(c, 1)
            gl.addLayout(row)
        gl.addWidget(label("Extra firejail options (one per line)", name="hint"))
        self.extra_edit = QPlainTextEdit()
        self.extra_edit.setMaximumHeight(104)
        self.extra_edit.setPlaceholderText("--timeout=02:00:00\n--rlimit-fsize=2000000000\n--blacklist=/mnt/private")
        self.extra_edit.setToolTip(
            "Only options that tighten the sandbox are accepted:\n"
            "  --rlimit-nofile|fsize|cpu|as|sigpending=N   --timeout=hh:mm:ss   --nice=0..19   --cpu=0,1\n"
            "  --blacklist=/path   --noexec=/path   --read-only=/path   --rmenv=NAME\n"
            "  --machine-id --nosound --novideo --nou2f --notv --nodvd --noroot\n"
            "Anything else cancels the launch. For a fork-bomb limit use Max processes, not --rlimit-nproc.")
        self.extra_edit.textChanged.connect(lambda: self._text_edited("FJ_EXTRA_ARGS"))
        self.extra_edit.textChanged.connect(self.refresh_dependents)
        self.plains["FJ_EXTRA_ARGS"] = self.extra_edit
        gl.addWidget(self.extra_edit)
        self.extra_note = label("", "warn")
        gl.addWidget(self.extra_note)
        self._add_group(g, v)

        # network
        g = CollapsibleGroup("Network", counted=False)
        gl = g.body
        gl.addWidget(self._tribox("Allow network access", "FJ_NET",
                                  "Off: no network (--net=none). On: own interface behind a default-deny filter, "
                                  "only the Network tab whitelist gets out."))
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
        _ClickOpensCombo(self.iface)
        self.iface.editTextChanged.connect(lambda *_: self._text_edited("FJ_NET_IFACE"))
        self.texts["FJ_NET_IFACE"] = self.iface
        row.addWidget(self.iface, 1)
        gl.addLayout(row)
        self.iface_note = label("", "warn")
        gl.addWidget(self.iface_note)
        gl.addWidget(self._tribox("Allow DNS lookups (udp/53)", "FJ_NET_DNS",
                                  "Needed if the game looks up hostnames. The whitelist itself is by IP."))
        gl.addWidget(self._tribox("Log connection attempts (shown in the Network tab)", "FJ_NET_LOG",
                                  "Logs new outgoing connections via the kernel firewall log (needs "
                                  "net.netfilter.nf_log_all_netns=1). Only works with network on."))
        gl.addWidget(self._tribox("Learn mode — allow everything, log it", "FJ_NET_LEARN",
                                  "Allows and logs every connection, blocks nothing. Collect IPs, then untick "
                                  "to enforce the whitelist."))
        gl.addWidget(self._tribox("Unrestricted — no filtering at all", "FJ_NET_OPEN",
                                  "Shares the host network. The game can reach anything you can."))
        self.boxes["FJ_NET_OPEN"].setProperty("danger", True)
        self._add_group(g, v)

        # display
        g = CollapsibleGroup("Display", counted=False)
        gl = g.body
        gl.addWidget(self._tribox("Isolated X11 (Xephyr)", "FJ_XEPHYR",
                                  "Own X server in a window (--x11=xephyr), so the game can't read your keystrokes or screen."))
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
        _ClickOpensCombo(self.xsize)
        self.xsize.editTextChanged.connect(lambda *_: self._text_edited("FJ_XEPHYR_SIZE"))
        self.texts["FJ_XEPHYR_SIZE"] = self.xsize
        row.addWidget(self.xsize, 1)
        gl.addLayout(row)
        self.x_note = label("", "warn")
        gl.addWidget(self.x_note)
        gl.addWidget(label("Only sets Xephyr's resolution. The window opens wherever your compositor puts it.", name="hint"))
        self._add_group(g, v)
        v.addStretch(1)

        for k in ("FJ_NET", "FJ_NET_OPEN", "FJ_XEPHYR"):
            # stateChanged is deprecated in Qt >= 6.9 in favour of checkStateChanged
            sig = getattr(self.boxes[k], "checkStateChanged", None) or self.boxes[k].stateChanged
            sig.connect(lambda *_: self.refresh_dependents())
        self.iface.editTextChanged.connect(lambda *_: self.refresh_dependents())
        outer.setWidget(self.prot)
        return outer

    def _add_group(self, g: CollapsibleGroup, layout: QVBoxLayout):
        g.collect()
        self.groups.append(g)
        layout.addWidget(g)

    def _refresh_summaries(self):
        total = sum(g.refresh() for g in self.groups)
        self._sync_preset(total)
        self._apply_filter()
        self._refresh_posture()

    def _refresh_posture(self):
        """The shield card follows the boxes as they are ticked, before anything is applied."""
        sel = self.loaded_games()
        if not sel:
            self.posture_card.set_posture(None)
            return
        keys = {k for k, *_ in wq_posture.PENALTY} | {"FJ_NET", "FJ_NET_OPEN", "FJ_NET_LEARN", "FJ_NET_DNS", "FJ_XEPHYR"}
        flags: dict[str, bool | None] = {}
        for k in keys:
            b = self.boxes.get(k)
            if b is not None:
                st = b.checkState()
                flags[k] = None if st == Partial else st == Checked

        def lines(key: str) -> tuple[str, ...]:
            seen: dict[str, None] = {}
            for g in sel:
                src = self.list_for(g, key) if len(sel) == 1 else g.effective_lines(key, self.defaults)
                seen.update(dict.fromkeys(v.strip() for v in src if v.strip()))
            return tuple(seen)

        hooks = max(sum(1 for k in ("FJ_HOOK_PRE", "FJ_HOOK_POST") if any(v.strip() for v in g.conf.get(k, []))) for g in sel)
        inp = wq_posture.PostureInputs(
            flags=flags, runner="native" if all(g.runner == "native" for g in sel) else "wine",
            wl_rw=lines("FJ_WL_RW"), wl_ro=lines("FJ_WL_RO"), net_allow=lines("FJ_NET_ALLOW"),
            hooks=hooks, home=os.path.expanduser("~"))
        self.posture_card.set_posture(wq_posture.score(inp), sel[0].name if len(sel) == 1 else f"{len(sel)} games")

    def _sync_preset(self, relaxed: int = 0):
        states = {}
        for k, b in self.boxes.items():
            st = b.checkState()
            states[k] = None if st == Partial else st == Checked
        name = core.preset_match(states)
        self.preset_btns[name].setChecked(True)
        self.preset_note.setText(core.PRESET_NOTES[name] if name in core.PRESET_NOTES else
                                 f"{relaxed} setting{'s' if relaxed != 1 else ''} weaker than Strict. "
                                 "Tooltips explain each one.")

    def _apply_preset(self, name: str):
        want = core.PRESETS.get(name)
        if want is None:                 # "Custom" is a result, not an action
            self._sync_preset()
            return
        for key, on in want.items():
            box = self.boxes.get(key)
            state = Checked if on else Unchecked
            if box is not None and box.checkState() != state:
                box.setCheckState(state)
                self._mark(key)
        self.refresh_dependents()
        self._refresh_summaries()

    def _apply_filter(self, *_):
        q, rel = self.search.text(), self.relaxed_only.isChecked()
        for g in self.groups:
            g.apply_filter(q, rel)

    def _tribox(self, text: str, key: str, tip: str) -> TriBox:
        b = TriBox(text, key)
        plain = core.PLAIN.get(key)
        b.setToolTip(f"{plain}\n\n{tip}" if plain else tip)
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
        self._refresh_summaries()

    def _text_edited(self, key: str):
        if not self._loading:
            self._mark(key)

    def extra_lines(self) -> list[str]:
        return [ln.strip() for ln in self.extra_edit.toPlainText().splitlines() if ln.strip()]

    def text_value(self, key: str) -> str:
        if key in self.plains:
            return "\n".join(self.extra_lines())
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
        v.addWidget(label("Only game/ and prefix/ are writable, and --private hides the rest of $HOME. "
                          "Anything else the game needs (saves, asset libraries) must be whitelisted below.", name="hint"))

        g = QGroupBox("Extra whitelisted paths")
        gl = QVBoxLayout(g)
        self.wl_table = make_table(["Access", "Path", "Status"], stretch_col=1)
        gl.addWidget(self.wl_table)
        row = QHBoxLayout()
        self.btn_add_rw = QPushButton("Add folder (rw)…")
        self.btn_add_ro = QPushButton("Add folder (ro)…")
        self.btn_add_file = QPushButton("Add file (ro)…")
        self.btn_add_rw.setToolTip("Whitelist a folder the game may read and write")
        self.btn_add_ro.setToolTip("Whitelist a folder the game may only read")
        self.btn_add_file.setToolTip("Whitelist a single file the game may only read")
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
        g3l.addWidget(label("These run on your machine, outside the sandbox. “Before launch” cancels the launch if it "
                            "fails. Both get WQ_GAME, WQ_GAMEDIR and WQ_QROOT. Per game only.", "warn"))
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
        row.addWidget(label("Read live from the kernel firewall log (journalctl -k) while this window is open. Needs "
                            "network on (filtered or learn mode) and net.netfilter.nf_log_all_netns=1. IPv4 only; "
                            "earlier connections are not listed.", name="hint"), 1)
        row.addWidget(clear)
        gl.addLayout(row)
        v.addWidget(g, 3)

        g3 = QGroupBox("Destinations the selected game has tried to reach (last 30 days)")
        g3l = QVBoxLayout(g3)
        self.host_map = wq_visuals.HostMapView(self.theme)
        g3l.addWidget(self.host_map)
        row = QHBoxLayout()
        self.learn_note = label("", name="hint")
        row.addWidget(self.learn_note, 1)
        self.btn_learn = QPushButton("Stage learned entries…")
        self.btn_learn.setToolTip("Add the destinations seen so far to this game's whitelist (you confirm the list first,\n"
                                  "and nothing is saved until you press Apply).")
        self.btn_learn.clicked.connect(self.stage_learned)
        row.addWidget(self.btn_learn)
        g3l.addLayout(row)
        v.addWidget(g3)
        self.host_timer = QTimer(self)                    # redraw the map a moment after a burst of attempts
        self.host_timer.setSingleShot(True)
        self.host_timer.setInterval(600)
        self.host_timer.timeout.connect(self.refresh_hosts)

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
        self.console.setPlaceholderText("Nothing yet. Output from the launcher and the kernel log appears here while a game runs.")
        self.hl_console = LogHighlighter(self.console.document(), self.theme, prefix=True)
        tv.addWidget(self.console)
        sp.addWidget(top)

        bot = QWidget()
        bv = QVBoxLayout(bot)
        bv.setContentsMargins(0, 0, 0, 0)
        title_row = QHBoxLayout()
        self.alert_title = QLabel("Monitor alerts")
        title_row.addWidget(self.alert_title, 1)
        self.alert_badge = QLabel("")
        self.alert_badge.setObjectName("badge")
        self.alert_badge.setVisible(False)
        title_row.addWidget(self.alert_badge)
        bv.addLayout(title_row)
        self.alerts = QPlainTextEdit()
        self.alerts.setObjectName("alerts")
        self.alerts.setReadOnly(True)
        self.alerts.setPlaceholderText("No alerts. Select a game to see what the monitor flagged in its last run.")
        self.hl_alerts = LogHighlighter(self.alerts.document(), self.theme)
        bv.addWidget(self.alerts)
        sp.addWidget(bot)
        return w

    # scanning
    def integration_status(self) -> str:
        files = [self.qroot / n for n in ("config.sh", "_launch-core.sh", "verify-sandbox.sh")]
        if not (self.qroot / "wq-ui" / "profile.sh").is_file():
            return ("wq-ui/profile.sh not found. Copy this folder to "
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
            it = QTreeWidgetItem([g.name, exe_short, "", "", "", "", ""])
            it.setData(0, Qt.ItemDataRole.UserRole, g.name)
            it.setToolTip(0, g.name)
            it.setToolTip(1, g.exe or "No executable set")
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
        self.apply_filter()

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
            if g.name in self.stopping and g.name in self.procs:
                st = ("■ stopping, checking…", "warn")
            elif g.name in self.procs:
                st = ("● running", "ok")
            elif not g.exe_ready:
                st = ("needs EXE", "bad")
            elif not g.has_launcher:
                st = ("no launcher", "bad")
            else:
                st = ("ready", "muted")
            it.setData(2, Qt.ItemDataRole.UserRole, loc[1])
            run_status, run_text, run_time = core.last_run(g.path)
            lr_text = run_text if not run_time else f"{run_text} · {core.human_ago(time.time() - run_time)}"
            lr = (lr_text, {"never": "muted", "clean": "ok", "notes": "warn"}.get(run_status, "bad"))
            it.setToolTip(6, "No run recorded yet." if not run_time else
                          f"Latest run, from {g.path / 'logs'}.\nDetails are in the Monitor tab.")
            for col, (text, status) in ((2, loc), (3, net), (4, xe), (5, st), (6, lr)):
                it.setText(col, text)
                it.setData(col, Qt.ItemDataRole.UserRole + 1, status)
            it.setToolTip(2, f"{g.path}\n\n{why}")
            it.setToolTip(1, str(core.exe_path(g.path, g.exe)) if g.exe else "")
            post = wq_posture.posture_for_game(g, self.defaults)
            it.setIcon(0, wq_visuals.shield_icon(post, self.theme))
            it.setToolTip(0, f"{g.path}\n\n{post.tooltip(g.name)}")
        self.refresh_colors()

    def header_menu(self, pos):
        m = QMenu(self)
        for i, name in enumerate(self.COLS):
            a = m.addAction(name)
            a.setCheckable(True)
            a.setChecked(not self.tree.isColumnHidden(i))
            a.setEnabled(i != 0)                       # the game name always stays
            a.triggered.connect(lambda checked, i=i: self.tree.setColumnHidden(i, not checked))
        m.exec(self.tree.header().mapToGlobal(pos))

    def _focus_filter(self):
        self.filter.setFocus()
        self.filter.selectAll()

    def apply_filter(self, *_):
        """Hide games that don't match the filter box. Selected rows always stay visible,
        so Apply/Launch never act on a game you can't see."""
        q = self.filter.text().strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            hay = f"{it.text(0)} {it.text(1)}".lower()
            it.setHidden(bool(q) and q not in hay and not it.isSelected())
        self.update_summary()

    def update_summary(self):
        total = self.tree.topLevelItemCount()
        shown = sum(1 for i in range(total) if not self.tree.topLevelItem(i).isHidden())
        running = len(self.procs)
        parts = [f"{total} game{'s' if total != 1 else ''}"]
        if shown != total:
            parts.append(f"{shown} shown")
        if running:
            parts.append(f"{running} running")
        self.summary.setText("  ·  ".join(parts))
        self.setWindowTitle(f"wine-quarantine — {running} running" if running else "wine-quarantine")
        self.empty_hint.setVisible(total == 0)

    def _restore_session(self):
        s = self.settings.data
        try:
            if s.get("geometry"):
                self.restoreGeometry(QByteArray.fromBase64(str(s["geometry"]).encode()))
            sizes = s.get("splitter")
            if isinstance(sizes, list) and len(sizes) == 2 and all(isinstance(x, int) and x > 0 for x in sizes):
                self.split.setSizes(sizes)
            tab = s.get("tab")
            if isinstance(tab, int) and 0 <= tab < self.tabs.count():
                self.tabs.setCurrentIndex(tab)
        except (TypeError, ValueError):
            pass
        names = {n for n in (s.get("last_games") or []) if n in self.by_name}
        if names:
            self.tree.blockSignals(True)
            self.tree.clearSelection()
            first = None
            for i in range(self.tree.topLevelItemCount()):
                it = self.tree.topLevelItem(i)
                if it.data(0, Qt.ItemDataRole.UserRole) in names:
                    it.setSelected(True)
                    first = first or it
            if first is not None:
                self.tree.setCurrentItem(first)
                self.tree.scrollToItem(first)
            self.tree.blockSignals(False)
            self.on_selection_changed(force=True)

    def _save_session(self):
        d = self.settings.data
        d["geometry"] = bytes(self.saveGeometry().toBase64()).decode()
        d["splitter"] = self.split.sizes()
        d["tab"] = self.tabs.currentIndex()
        d["last_games"] = list(self.loaded)
        d["hidden_cols"] = [i for i in range(len(self.COLS)) if self.tree.isColumnHidden(i)]
        try:
            self.settings.save()
        except OSError:
            pass

    def on_theme_changed(self):
        self.refresh_icons()
        for hl in (getattr(self, "hl_console", None), getattr(self, "hl_alerts", None)):
            if hl is not None:
                hl.refresh()
        self.refresh_colors()
        self.refresh_paths()
        self.refresh_attempt_rows()
        self.xray_tab.refresh_theme()
        self.runs_tab.refresh_theme()
        self.entropy_tab.refresh_theme()
        self.findings_tab.refresh_theme()
        self.refresh_rows()                            # shield icons are drawn in theme colours
        self.posture_card.set_posture(self.posture_card.post, self.posture_card.who)
        self.host_map.update()

    def refresh_colors(self):
        m = {"ok": "ok", "warn": "warn", "bad": "error", "muted": "on_surface_variant"}
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            for col in range(2, len(self.COLS)):
                st = it.data(col, Qt.ItemDataRole.UserRole + 1)
                if st:
                    it.setForeground(col, QBrush(self.theme.color(m[st])))
        self.update_summary()

    # selection
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
            return self.apply_changes()
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
        self.refresh_hosts()
        self.refresh_alerts(force=True)
        self.refresh_extras()
        sel = self.loaded_games()
        one = len(sel) == 1
        for a in (self.act_setup, self.act_exe, self.act_hook_pre, self.act_hook_post, self.act_dev, self.act_folder,
                  self.act_remove):
            a.setEnabled(one)
        self.add_menu_scripts.setEnabled(one)
        self.act_launch.setEnabled(bool(sel))
        self.act_relax.setEnabled(one)
        self.act_stop.setEnabled(any(g.name in self.procs for g in sel))
        self.xray_tab.set_game(self.single())
        self.runs_tab.set_game(self.single())
        self.entropy_tab.set_game(self.single())
        self.findings_tab.set_game(self.single())
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
                le.setPlaceholderText(core.TEXT_HINTS[key])
            else:
                combo.setCurrentIndex(-1)
                combo.setEditText("")
                le.setPlaceholderText("(differs between selected games)")
        for key, edit in self.plains.items():
            vals = {tuple(g.effective_lines(key, self.defaults)) for g in sel}
            if len(vals) > 1:
                edit.setPlainText("")
                edit.setPlaceholderText("(differs between selected games)")
            else:
                edit.setPlainText("\n".join(next(iter(vals), ())))
                edit.setPlaceholderText("--timeout=02:00:00\n--rlimit-fsize=2000000000\n--blacklist=/mnt/private")
        self.orig_boxes = {k: b.checkState() for k, b in self.boxes.items()}
        self.orig_texts = {k: self.text_value(k) for k in (*self.texts, *self.plains)}
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
        self._refresh_summaries()

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

        em = ""
        for ln in self.extra_lines():
            why = core.check_extra_arg(ln)
            if why:
                em = f"“{ln}”: {why}. Launch is blocked until this is fixed."
                break
            if ln.startswith("--rlimit-nproc="):
                em = ("--rlimit-nproc counts all your processes, so a low value stops the game from starting. "
                      "Use “Max processes and threads” instead.")
        self.extra_note.setText(em)
        self.extra_note.setVisible(bool(em))

    def update_apply_bar(self):
        n = len(self.loaded)
        pend = self.pending_count()
        self.btn_apply.setText(f"Apply to {n} game{'s' if n != 1 else ''}" if n else "Apply")
        self.btn_apply.setEnabled(bool(n) and pend > 0)
        self.btn_reset.setEnabled(bool(n))
        self.btn_save_defaults.setEnabled(bool(n))
        self.pending_label.setText(f"● {pend} unapplied change{'s' if pend != 1 else ''}" if pend else "")
        set_prop(self.pending_label, "status", "warn" if pend else "muted")

    # applying
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
            elif key in self.plains:
                ch[key] = self._extra_for_write()
        return ch

    def _extra_for_write(self) -> list[str] | None:
        """Lines to store. With nothing typed, a bare `FJ_EXTRA_ARGS=` is written when the
        default profile has options, so "none" does not silently fall back to them."""
        lines = self.extra_lines()
        if lines:
            return lines
        return [""] if any(x.strip() for x in self.defaults.get("FJ_EXTRA_ARGS", [])) else None

    def validate(self, ch: dict) -> str:
        s = ch.get("FJ_XEPHYR_SIZE")
        if s and not core.valid_size(s):
            return f"“{s}” is not a valid size. Use WIDTHxHEIGHT, e.g. 1920x1080."
        i = ch.get("FJ_NET_IFACE")
        if i and not all(c.isalnum() or c in "_.-" for c in i):
            return f"“{i}” is not a valid interface name."
        for k, ok, hint in (("FJ_TASKS_MAX", core.valid_tasks, "a whole number such as 4096"),
                            ("FJ_MEMORY_MAX", core.valid_memory, "a number with optional K, M, G or T, such as 8G"),
                            ("FJ_SECCOMP_EXTRA", core.valid_syscalls, "syscall names separated by commas")):
            v = ch.get(k)
            if v and not ok(v):
                return f"“{v}” is not valid here. Use {hint}."
        for ln in ch.get("FJ_EXTRA_ARGS") or []:
            why = core.check_extra_arg(ln)
            if why:
                return f"Extra firejail option “{ln}”: {why}."
        return ""

    def apply_changes(self) -> bool:
        games = self.loaded_games()
        ch = self.collect_changes()
        err = self.validate(ch)
        if err:
            QMessageBox.warning(self, "Cannot apply", err)
            return False
        if ch.get("FJ_NET_OPEN") == "1":
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
        err = self.validate({**{k: self.text_value(k) for k in self.texts}, "FJ_EXTRA_ARGS": self.extra_lines()})
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
        upd["FJ_EXTRA_ARGS"] = self.extra_lines() or None
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

    # paths
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
        self.refresh_hosts()
        self._refresh_posture()
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
            rows.append(("executable", core.exe_path(g.path, g.exe), True))
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

    # network
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
            txt, st = f"{g.name}: network is OFF. Nothing gets out.", "ok"
        elif mode == "open":
            txt, st = f"{g.name}: network is UNRESTRICTED. The whitelist is ignored.", "bad"
        elif mode == "learn":
            txt, st = (f"{g.name}: LEARN MODE. Everything is allowed and logged. "
                       "Untick “Learn mode” in Protection to enforce the whitelist.", "warn")
        else:
            txt, st = (f"{g.name}: network is FILTERED. Only the whitelist below (and DNS if allowed) gets out.", "warn")
        if not log:
            txt += "  Logging is off. Tick “Log connection attempts” in Protection to see what it tries."
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

    def record_attempt(self, gname: str, addr: str, port: int, proto: str = ""):
        key = (gname, addr, port)
        if proto:
            self.attempt_proto[key] = proto
        g = self.by_name.get(gname)
        if g is not None:                                  # kept for the host map and the Runs timeline
            mode = g.net_mode(self.defaults)
            listed = core.allow_matches(self.list_for(g, "FJ_NET_ALLOW"), addr, port)
            blocked = mode == "off" or (mode == "filtered" and not listed)
            if runlog.append_attempt(g.path, addr, port, blocked, mode, proto) and not self.host_timer.isActive():
                self.host_timer.start()
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
        btn.setToolTip("" if can else ("IPv6 can't be whitelisted" if ":" in addr
                                       else "Multicast/broadcast, nothing to whitelist" if special else ""))

    def whitelist_attempt(self, key: tuple):
        gname, addr, port = key
        g = self.by_name.get(gname)
        if g is None:
            return
        proto = self.attempt_proto.get(key)             # the kernel log says tcp or udp; the old trace format doesn't
        if not proto:
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

    def refresh_hosts(self):
        """The Network tab's destination map, from the persisted attempts of the selected game."""
        g = self.single()
        self._learn_entries = []
        if g is None:
            self.host_map.set_hosts([], "Select one game to see where it has tried to connect.")
            self.learn_note.setText("")
            self.btn_learn.setEnabled(False)
            return
        atts = runlog.read_attempts(g.path, since=time.time() - runlog.NET_KEEP_DAYS * 86400)
        runs = runlog.list_runs(g.path, 1)
        hosts = runlog.host_stats(atts, runs[-1].start if runs else None)
        self.host_map.set_hosts(hosts, "No connection attempts recorded for this game yet. They are logged while wq-ui is open "
                                       "and the game's network is on (filtered or learn mode).")
        pv = runlog.learn_preview(atts, self.list_for(g, "FJ_NET_ALLOW"))
        self._learn_entries = [e for e in pv["entries"] if core.valid_allow(e)]
        bits = []
        if hosts:
            bits.append(f"{len(hosts)} destination{'s' if len(hosts) != 1 else ''} seen")
        if pv["covered"]:
            bits.append(f"{pv['covered']} already whitelisted")
        if self._learn_entries:
            bits.append(f"{len(self._learn_entries)} can be added now")
        if pv["unknown_proto"]:
            bits.append(f"{len(pv['unknown_proto'])} need tcp or udp chosen (use Whitelist… in the table)")
        if pv["not_whitelistable"]:
            bits.append(f"{pv['not_whitelistable']} can't be whitelisted (IPv6, multicast)")
        self.learn_note.setText(" · ".join(bits))
        self.btn_learn.setEnabled(bool(self._learn_entries) and g.net_mode(self.defaults) != "open")

    def stage_learned(self):
        g = self.single()
        if g is None:
            return
        have = self.list_for(g, "FJ_NET_ALLOW")
        add = [e for e in self._learn_entries if e not in have]
        if not add:
            return
        shown = "\n".join(add[:14]) + (f"\n… and {len(add) - 14} more" if len(add) > 14 else "")
        r = QMessageBox.question(
            self, "Stage learned destinations",
            f"Add these {len(add)} destination{'s' if len(add) != 1 else ''} to {g.name}'s whitelist?\n\n{shown}\n\n"
            "Only do this if you are happy for this game to talk to all of them. A game that was misbehaving while "
            "you recorded would have its destinations whitelisted too. Nothing is saved until you press Apply.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if r != QMessageBox.StandardButton.Yes:
            return
        self.stage_list(g, "FJ_NET_ALLOW", have + add)
        extra = " The game's network is still OFF; enable it in Protection." if g.net_mode(self.defaults) == "off" else ""
        self.statusBar().showMessage(f"Staged {len(add)} entries for {g.name}. Press Apply to save.{extra}", 9000)

    def clear_attempts(self):
        self.att_table.setRowCount(0)
        self.attempts.clear()
        self.attempt_proto.clear()
        self.tabs.tabBar().setTabText(2, "Network")

    # launching/monitor
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
            if r == QMessageBox.StandardButton.Yes and not self.apply_changes():
                return          # invalid or declined: do not launch with the old settings
        if len(games) > 1:
            r = QMessageBox.question(self, "Launch several?", f"Launch {len(games)} games at once?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                return
        for g in games:
            self.launch(g)
        self.tabs.setCurrentWidget(self.monitor_tab)

    def test_sandbox(self):
        """Run probe.sh inside a throwaway native game that has the selected game's profile."""
        games = self.loaded_games()
        if self.pending_count():
            r = QMessageBox.question(self, "Unapplied changes", "Apply pending changes before testing?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                                     | QMessageBox.StandardButton.Cancel)
            if r == QMessageBox.StandardButton.Cancel:
                return
            if r == QMessageBox.StandardButton.Yes and not self.apply_changes():
                return
        g = None
        if games:
            # read the files again: the test must see what a launch would see
            g = core.Game(games[0].name, games[0].path, core.parse_kv(games[0].path / "game.conf"),
                          games[0].has_launcher)
        defaults = core.parse_kv(self.qroot / core.DEFAULTS_NAME)
        dlg = wq_sandboxtest.SandboxTestDialog(self, self.qroot, g, defaults)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.show()

    def relax_selected(self):
        g = self.single()
        if g is None:
            QMessageBox.information(self, "Select a game", "Select exactly one game first.")
            return
        cur = getattr(self, "_relax_dlg", None)
        if cur is not None:
            cur.raise_()
            cur.activateWindow()
            return
        dlg = wq_relax_dialog.RelaxDialog(self, g)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._relax_dlg = dlg
        dlg.show()

    def launch(self, g: core.Game, run_exe: str = ""):
        """run_exe: a file in game/ to run once instead of EXE= (a setup file); game.conf is not changed."""
        if g.name in self.procs or g.name in self.baselining:
            return
        script = g.path / "launch-quarantine.sh"
        if not script.exists():
            QMessageBox.warning(self, "No launcher", f"{script} does not exist. Re-create the game with Add > New game.")
            return
        if not g.exe_ready and not run_exe:
            QMessageBox.warning(self, "Executable not set", f"Set EXE= in {g.path / 'game.conf'} first.")
            return
        if self.xray_tab.auto_baseline:
            # snapshot game/, prefix/, home/ and the whitelisted paths first so X-Ray can show what this run changed;
            # the game starts as soon as the snapshot is saved
            self.baselining.add(g.name)
            self.console.appendPlainText(f"[{g.name}] taking the X-Ray baseline…")
            self.xray_tab.baseline_for(g, lambda g=g, script=script, r=run_exe: self._start_game(g, script, r))
            return
        self._start_game(g, script, run_exe)

    def run_setup_selected(self):
        g = self.single()
        if g is None:
            QMessageBox.information(self, "Select a game", "Select exactly one game first.")
            return
        if g.name in self.procs:
            QMessageBox.information(self, "Already running", f"{g.name} is running. Stop it first.")
            return
        if not self.resolve_pending("Apply them before running the setup file?"):
            return
        found = core.find_setups(g.path, g.runner)
        rel = ""
        if found:
            items = found + ["Choose another file…"]
            pick, ok = QInputDialog.getItem(self, "Run setup file", "Run once inside the sandbox:", items, 0, False)
            if not ok:
                return
            rel = "" if pick == items[-1] else pick
        if not rel:
            start = str(g.path / "game")
            fn, _ = QFileDialog.getOpenFileName(self, "Choose the setup file (inside the game's game/ folder)", start)
            if not fn:
                return
            try:
                rel = os.path.relpath(os.path.realpath(fn), os.path.realpath(g.path / "game"))
            except ValueError:
                rel = ""
        if not rel or rel.startswith("..") or not core.exe_inside_game(g.path, rel):
            QMessageBox.warning(self, "Not usable",
                                "The setup file has to be a file inside this game's game/ folder. Copy it there first "
                                "(Open game folder).")
            return
        note = ("An installer writes into this game's Wine prefix, so it needs no network and no access to your files."
                if g.runner != "native" else
                "A native installer can only write to this game's game/ folder and private home: point it at the game folder.")
        r = QMessageBox.question(self, "Run setup file", f"Run {rel} once?\n\n{note}\n\nAfterwards use Set executable to pick "
                                 "the installed program.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if r == QMessageBox.StandardButton.Yes:
            self.launch(g, run_exe=rel)

    def _start_game(self, g: core.Game, script: Path, run_exe: str = ""):
        self.baselining.discard(g.name)
        if g.name in self.procs:
            return
        p = QProcess(self)
        p.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        p.setWorkingDirectory(str(g.path))
        p.setStandardInputFile(os.devnull)
        env = QProcessEnvironment.systemEnvironment()
        env.remove("WQ_RUN_EXE")                # only a deliberate "Run setup file" may set it
        if not self.xray_tab.auto_baseline:     # "Snapshot before each launch" is off: the launcher must not take one either
            env.insert("WQ_XRAY_BASELINE", "0")
        if run_exe:
            env.insert("WQ_RUN_EXE", run_exe)
        p.setProcessEnvironment(env)
        self.procs[g.name] = {"proc": p, "buf": ""}
        self.watch.start(g.name, g.path)
        self.runs_tab.begin_launch(g.name)
        p.readyReadStandardOutput.connect(lambda n=g.name: self.on_output(n))
        p.finished.connect(lambda code, _st, n=g.name: self.on_finished(n, code))
        p.errorOccurred.connect(lambda err, n=g.name: self._on_game_error(n, err))
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

    # kernel log tail
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
                self.record_attempt(gname, hit[1], hit[2], proto=core.parse_proto(line))

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
            self.runs_tab.feed_launch_line(name, line)
            hit = core.parse_connect(line)
            if hit:
                self.record_attempt(name, *hit, proto=core.parse_proto(line))

    def _on_game_error(self, name: str, err):
        """QProcess emits no finished() when the program never started, so without this the game would
        stay in self.procs: shown as running, and impossible to launch again."""
        if err != QProcess.ProcessError.FailedToStart:
            return
        self.console.appendPlainText(f"[{name}] failed to start")
        if name in self.procs:
            self.on_finished(name, 127)

    def on_finished(self, name: str, code: int):
        self.on_output(name)
        self.console.appendPlainText(f"[{name}] exited with code {code}")
        self.procs.pop(name, None)
        self.stopping.discard(name)
        self.refresh_rows()
        self.load_all()
        g = self.by_name.get(name)
        if g:
            self.xray_tab.run_finished(g)
            self.runs_tab.run_finished(g)
            self.findings_tab.refresh()
        verdict, vtext, _ = core.last_run(g.path) if g else ("never", "", 0.0)
        if g:
            self.watch.exited(name, g.path)               # what the exit summary covers is not repeated
        msg = wq_notify.finish_message(name, verdict, vtext, code, bool(self.settings.data.get("notify_clean")))
        if msg:
            self.notify(*msg)
        self.statusBar().showMessage(f"{name} exited" + ("" if code == 0 else f" with code {code}")
                                     + (f" — {vtext}" if verdict != "never" else ""), 10000)
        if verdict in ("alert", "blocked", "leak") and self.tabs.currentWidget() is not self.monitor_tab:
            self.tabs.tabBar().setTabText(self.tabs.indexOf(self.monitor_tab), "Monitor ●")
        if verdict in ("alert", "blocked", "leak") and self.tabs.currentWidget() is not self.runs_tab:
            self.tabs.tabBar().setTabText(self.tabs.indexOf(self.runs_tab), "Runs ●")

    # desktop notifications
    def notify(self, title: str, body: str, urgency: str = "normal", force: bool = False) -> bool:
        d = self.settings.data
        if not force:
            if not d.get("notify", True):
                return False
            # a game usually has the screen, so the default is to stay quiet while you are looking at wq-ui
            if d.get("notify_unfocused_only", True) and self.isActiveWindow():
                return False
        return self.notifier.send(title, body, urgency)

    def poll_notifications(self):
        for name in self.watch.watching():
            g = self.by_name.get(name)
            if g is None:
                self.watch.stop(name)
                continue
            msg = self.watch.poll(name, g.path)
            if msg:
                self.notify(*msg)

    def stop_selected(self):
        for g in self.loaded_games():
            d = self.procs.get(g.name)
            if d:
                # the sandbox and monitor stop at once; the launcher itself carries on to the
                # registry/home diff, the ClamAV scan and the verdict
                self.stopping.add(g.name)
                # kill_group ignores pid 0: os.killpg(0, ...) would signal wq-ui's own process group
                wq_dialogs.kill_group(d["proc"])
        self.refresh_rows()

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
                self.alert_badge.setVisible(False)
                self.alert_title.setText("Monitor alerts — select a single game")
                self._alert_sig = None
            return
        logs = sorted((g.path / "logs").glob("alerts-*.log")) if (g.path / "logs").is_dir() else []
        if not logs:
            if force or self._alert_sig != (g.name, None):
                self.alerts.setPlainText("")
                self.alert_badge.setVisible(False)
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
        self.refresh_rows()
        self.alerts.verticalScrollBar().setValue(self.alerts.verticalScrollBar().maximum())
        self.update_badge(text)
        self.alert_title.setText(f"Monitor alerts — {g.name} / {latest.name}")

    def update_badge(self, text: str):
        n_alert, n_warn = core.count_alerts(text)
        if n_alert:
            txt, st = f"{n_alert} alert{'s' if n_alert != 1 else ''}", "bad"
            if n_warn:
                txt += f", {n_warn} warning{'s' if n_warn != 1 else ''}"
        elif n_warn:
            txt, st = f"{n_warn} warning{'s' if n_warn != 1 else ''}", "warn"
        else:
            txt, st = "clean", "ok"
        self.alert_badge.setText(txt)
        set_prop(self.alert_badge, "status", st)
        self.alert_badge.setVisible(True)

    # add game / exe / folder
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

    def dragEnterEvent(self, e):
        if any(u.isLocalFile() for u in e.mimeData().urls()):
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if not paths:
            e.ignore()
            return
        e.acceptProposedAction()
        if len(paths) > 1:
            self.statusBar().showMessage(f"Dropped {len(paths)} items; adding the first ({paths[0]})", 10000)
        self.new_game(paths[0])

    def new_game(self, source=None):
        dlg = wq_dialogs.NewGameDialog(self.qroot, {g.name for g in self.games}, self)
        if isinstance(source, str) and source:         # a drop passes the path; a menu click passes a bool
            dlg._set_source(source)
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
                                f"{rel} is not a file inside {g.name}/game/ or its Wine prefix (symlinks out of those folders are refused).")
            return
        try:
            core.write_kv(g.path / "game.conf", {"EXE": rel})
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "Could not write game.conf", str(e))
            return
        self.reload_keep_selection()
        self.statusBar().showMessage(f"{g.name}: executable set to {rel}", 6000)

    def remove_game(self):
        """Move the selected game to the Trash. No Trash on this drive: move it into
        <quarantine>/.trash instead, so it can still be restored."""
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
            f"prefix, saves and logs. The folder goes to the system Trash, or to .trash inside the "
            f"quarantine folder when this drive has no Trash.")
        b_go = box.addButton("Move to Trash", QMessageBox.ButtonRole.DestructiveRole)
        b_cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(b_cancel)
        box.setEscapeButton(b_cancel)
        box.exec()
        if box.clickedButton() is not b_go:
            return
        res = QFile.moveToTrash(str(g.path))
        ok = res[0] if isinstance(res, tuple) else bool(res)        # PySide gives back (ok, trash path)
        moved_to = None
        if not ok:
            # no system Trash on this drive: move the folder into <qroot>/.trash instead. It is a rename
            # on the same drive, so nothing is copied, and it can be moved back by hand.
            if core.validate_removal(self.qroot, g.name):        # re-check right before moving
                return
            try:
                moved_to = core.stash_game(self.qroot, g.path)
            except OSError as e:
                QMessageBox.critical(self, "Could not move the game", f"{e}\n\nNothing was removed.")
                return
        self.staged.pop(g.name, None)
        self.dirty.clear()
        self.refresh_game_list()
        self.loaded = []
        self.on_selection_changed(force=True)
        self.statusBar().showMessage(
            f"Removed {g.name}" if moved_to is None else f"Moved {g.name} to {moved_to.parent}", 10000)

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
        m.addAction(self.act_test)
        m.addSeparator()
        m.addAction(self.act_setup)
        m.addAction(self.act_exe)
        m.addAction(self.act_folder)
        m.addSeparator()
        m.addAction("Remove game…", self.remove_game)
        m.exec(self.tree.viewport().mapToGlobal(pos))

    # /dev devices, scripts
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
            it = QListWidgetItem(path if exists else f"{path}   (not present, skipped)")
            it.setData(Qt.ItemDataRole.UserRole, path)
            lvl, note = core.device_risk(os.path.realpath(path)) if exists else ("ok", "")
            it.setToolTip(note or ("Hidden (--blacklist)." if exists else "Not present."))
            if not exists or lvl == "notable":
                it.setForeground(QBrush(self.theme.color("warn")))
            self.dev_list.addItem(it)
        self.dev_note.setText("" if self.dev_list.count() else "Nothing hidden beyond the boxes above.")
        for key, ed in self.hook_edits.items():
            vals = self.list_for(g, key)
            path = vals[0] if vals else ""
            ed.setText(path)
            if path and not os.path.isfile(path):
                ed.setToolTip("File not found, skipped at launch.")
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
            f"{f}\n\nThis runs on your machine, outside the sandbox, every time {g.name} "
            f"launches ({self.HOOK_TEXT[key]}). Only attach scripts you trust.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if r != QMessageBox.StandardButton.Yes:
            return
        self.stage_list(g, key, [f])
        self.tabs.setCurrentIndex(1)

    def clear_hook(self, key: str):
        g = self.single()
        if g is not None and self.list_for(g, key):
            self.stage_list(g, key, [])

    # misc
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

    def on_xray_changed(self, new: int, mod: int):
        if (new or mod) and self.tabs.currentWidget() is not self.xray_tab:
            self.tabs.tabBar().setTabText(self.tabs.indexOf(self.xray_tab), "X-Ray ●")

    def tabChanged(self, i):  # noqa: N802
        if i == 2:
            self.tabs.tabBar().setTabText(2, "Network")
        elif self.tabs.widget(i) is self.monitor_tab:
            self.tabs.tabBar().setTabText(i, "Monitor")
        elif self.tabs.widget(i) is self.xray_tab:
            self.tabs.tabBar().setTabText(i, "X-Ray")
        elif self.tabs.widget(i) is self.runs_tab:
            self.tabs.tabBar().setTabText(i, "Runs")

    def closeEvent(self, e):  # noqa: N802
        if self.procs:
            r = QMessageBox.question(self, "Games running",
                                     "Games are still running. Stop them and quit?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if r != QMessageBox.StandardButton.Yes:
                e.ignore()
                return
            for d in list(self.procs.values()):
                wq_dialogs.kill_group(d["proc"])
                d["proc"].waitForFinished(3000)
        self.xray_tab.shutdown()
        self.entropy_tab.shutdown()
        self.findings_tab.shutdown()
        self._save_session()
        k = getattr(self, "_klog", None)
        if k is not None:
            k.terminate()
            k.waitForFinished(1000)
        super().closeEvent(e)


# 
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
    app.setDesktopFileName(DESKTOP_ID)           # Wayland picks the taskbar icon from wine-quarantine.desktop
    app.setWindowIcon(app_icon())                # X11, and the fallback when the menu entry is not installed
    for font in sorted((wq_themes.ASSETS_DIR / "fonts").glob("*.ttf")):    # the Pixel theme's font
        QFontDatabase.addApplicationFont(str(font))
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

