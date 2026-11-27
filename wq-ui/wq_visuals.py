"""Qt widgets for wq-ui's visual security views.

  shield_icon / PostureCard   the sandbox "shield" ring: game list icon, Protection tab card
  HistoryStrip                one bar per recent run, coloured by verdict
  TimelineView                what happened during a run, in time order, by kind
  PreflightCard               the sandbox verifier's checks as a gate
  RunsTab                     the above plus "what changed since the last run"
  HostMapView                 the Network tab's destinations as bars

All numbers and parsing come from wq_posture and wq_runlog (Qt-free, covered by test_posture.py
and test_runlog.py). This file only draws. Colours are read from the theme at paint time, so a
theme change only needs update().
"""
from __future__ import annotations

import math
import time
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QIcon, QPainter, QPen, QPixmap, QTextOption
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFrame, QGroupBox, QHBoxLayout, QLabel, QListWidget,
                               QListWidgetItem, QPushButton, QScrollArea, QSizePolicy, QToolTip, QVBoxLayout,
                               QWidget)

import wq_core as core
import wq_posture as posture
import wq_runlog as runlog

# status words used across wq-ui -> theme token
TOKEN = {"ok": "ok", "warn": "warn", "bad": "error", "muted": "on_surface_variant"}
LEVEL_TOKEN = {"INFO": "on_surface_variant", "WARN": "warn", "ALERT": "error"}
RUN_TOKEN = {"clean": "ok", "notes": "warn", "alert": "error", "blocked": "error", "leak": "error",
             "never": "on_surface_variant"}


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _alpha(c: QColor, a: int) -> QColor:
    return QColor(c.red(), c.green(), c.blue(), a)


def _hex(theme, key: str) -> str:
    return theme.color(key).name()


def _muted(text: str = "", wrap: bool = True) -> QLabel:
    lb = QLabel(text)
    lb.setObjectName("hint")
    lb.setWordWrap(wrap)
    return lb


def _text(p: QPainter, rect: QRectF, text: str, align=Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
          wrap: bool = False) -> None:
    """drawText through QTextOption, the way wq_xray does it (flag enums of different kinds
    can't be OR-ed together in PySide6). One line, no wrapping, unless wrap is set."""
    opt = QTextOption(align)
    opt.setWrapMode(QTextOption.WrapMode.WordWrap if wrap else QTextOption.WrapMode.NoWrap)
    p.drawText(rect, text, opt)


# ---------------------------------------------------------------- shield

_PIX: dict[tuple, QPixmap] = {}


def shield_pixmap(score: int, grade: str, ring: QColor, ink: QColor, track: QColor,
                  size: int = 20, scale: int = 2) -> QPixmap:
    """A ring that fills clockwise from 12 o'clock in proportion to the score, with the grade
    letter inside. Cached: the game list asks for one per row on every refresh."""
    key = (score, grade, ring.rgba(), ink.rgba(), track.rgba(), size, scale)
    hit = _PIX.get(key)
    if hit is not None:
        return hit
    if len(_PIX) > 300:
        _PIX.clear()
    pm = QPixmap(size * scale, size * scale)
    pm.fill(Qt.GlobalColor.transparent)
    pm.setDevicePixelRatio(scale)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    w = max(2.0, size * 0.15)
    r = QRectF(w / 2, w / 2, size - w, size - w)
    pen = QPen(track, w)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(r)
    if score > 0:
        pen = QPen(ring, w)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap if score < 100 else Qt.PenCapStyle.FlatCap)
        p.setPen(pen)
        p.drawArc(r, 90 * 16, -int(round(score / 100.0 * 360 * 16)))
    font = QFont(p.font())
    font.setPixelSize(max(7, int(size * 0.46)))
    font.setBold(True)
    p.setFont(font)
    p.setPen(ink)
    _text(p, r, grade, Qt.AlignmentFlag.AlignCenter)
    p.end()
    _PIX[key] = pm
    return pm


def shield_icon(post: posture.Posture, theme, size: int = 20) -> QIcon:
    ring = theme.color(TOKEN[post.status])
    return QIcon(shield_pixmap(post.score, post.grade, ring, theme.color("on_surface"), theme.color("outline"), size))


class _Ring(QWidget):
    """The big version: score in the middle, grade under it."""

    def __init__(self, theme, size: int = 76):
        super().__init__()
        self.theme = theme
        self.post: posture.Posture | None = None
        self.setFixedSize(size, size)

    def set_posture(self, post: posture.Posture | None):
        self.post = post
        self.update()

    def paintEvent(self, _e):  # noqa: N802  (Qt override)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        th = self.theme.color
        w = 8.0
        r = QRectF(w / 2 + 1, w / 2 + 1, self.width() - w - 2, self.height() - w - 2)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(th("outline"), w))
        p.drawEllipse(r)
        if self.post is None:
            return
        if self.post.score > 0:
            pen = QPen(th(TOKEN[self.post.status]), w)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap if self.post.score < 100 else Qt.PenCapStyle.FlatCap)
            p.setPen(pen)
            p.drawArc(r, 90 * 16, -int(round(self.post.score / 100.0 * 360 * 16)))
        f = QFont(self.font())
        f.setBold(True)
        f.setPixelSize(int(self.height() * 0.30))
        p.setFont(f)
        p.setPen(th("on_surface"))
        _text(p, QRectF(0, self.height() * 0.22, self.width(), self.height() * 0.36), str(self.post.score), Qt.AlignmentFlag.AlignCenter)
        f.setBold(False)
        f.setPixelSize(int(self.height() * 0.17))
        p.setFont(f)
        p.setPen(th("on_surface_variant"))
        _text(p, QRectF(0, self.height() * 0.56, self.width(), self.height() * 0.2), f"grade {self.post.grade}", Qt.AlignmentFlag.AlignCenter)


class PostureCard(QWidget):
    """Shield ring, one-line verdict and the biggest weaknesses, for the game being edited."""

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.post: posture.Posture | None = None
        self.who = ""
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        self.ring = _Ring(theme)
        row.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignTop)
        self.text = QLabel()
        self.text.setWordWrap(True)
        self.text.setTextFormat(Qt.TextFormat.RichText)
        self.text.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        row.addWidget(self.text, 1)
        self.set_posture(None)

    def set_posture(self, post: posture.Posture | None, who: str = ""):
        self.post, self.who = post, who
        self.ring.set_posture(post)
        mut = _hex(self.theme, "on_surface_variant")
        if post is None:
            self.text.setText(f'<span style="color:{mut}">Select a game to see its shield.</span>')
            self.setToolTip("")
            return
        col = _hex(self.theme, TOKEN[post.status])
        head = f'<b style="color:{col}; font-size:larger">{_esc(post.headline())}</b>'
        if who:
            head += f' <span style="color:{mut}">· {_esc(who)}</span>'
        lines = [head]
        for f in post.findings[:4]:
            c = _hex(self.theme, {"bad": "error", "warn": "warn", "info": "on_surface_variant"}[f.severity])
            lines.append(f'<span style="color:{c}">&minus;{f.penalty}</span> &nbsp;{_esc(f.title)}')
        if len(post.findings) > 4:
            rest = sum(f.penalty for f in post.findings[4:])
            lines.append(f'<span style="color:{mut}">&minus;{rest} &nbsp;{len(post.findings) - 4} more (hover)</span>')
        lines.append(f'<span style="color:{mut}">A summary of the profile above, not a safety guarantee. '
                     f'Changes you have not applied yet are included.</span>')
        self.text.setText("<br>".join(lines))
        self.setToolTip("\n".join(f"-{f.penalty}  {f.title}: {f.detail}" for f in post.findings)
                        or "Every protection is on.")


# ---------------------------------------------------------------- run history

class HistoryStrip(QWidget):
    """One bar per recent run, oldest on the left. Colour is the verdict; a taller bar means more
    findings, so a bad run stands out from a tidy row."""
    picked = Signal(int)

    SLOT, PAD = 22, 6

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.items: list[runlog.RunSummary] = []
        self.cur = -1
        self._hover = -1
        self.setMouseTracking(True)
        self.setFixedHeight(46)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_history(self, items: list[runlog.RunSummary], cur: int = -1):
        self.items, self.cur, self._hover = items, cur, -1
        self.update()

    def set_current(self, cur: int):
        self.cur = cur
        self.update()

    def _slot_w(self) -> float:
        n = max(len(self.items), 1)
        return min(float(self.SLOT), (self.width() - 2 * self.PAD) / n)

    def _index_at(self, x: float) -> int:
        i = int((x - self.PAD) // max(self._slot_w(), 1.0))
        return i if 0 <= i < len(self.items) else -1

    def paintEvent(self, _e):  # noqa: N802  (Qt override)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        th = self.theme.color
        if not self.items:
            p.setPen(th("on_surface_variant"))
            _text(p, QRectF(self.rect()).adjusted(self.PAD, 0, 0, 0), "No runs recorded yet.")
            return
        sw = self._slot_w()
        base = self.height() - 8.0
        p.setPen(QPen(th("outline"), 1))
        p.drawLine(QPointF(self.PAD, base + 3), QPointF(self.width() - self.PAD, base + 3))
        for i, s in enumerate(self.items):
            findings = 4 * s.n_alert + s.n_warn + (6 if s.status in ("blocked", "leak") else 0)
            h = 8.0 + min(22.0, findings * 3.0)
            x = self.PAD + i * sw
            r = QRectF(x + 2, base - h, max(3.0, sw - 4), h)
            c = th(RUN_TOKEN.get(s.status, "on_surface_variant"))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(c if s.status != "clean" else _alpha(c, 170)))
            p.drawRoundedRect(r, 2.5, 2.5)
            if i == self.cur:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(th("on_surface"), 2))
                p.drawRoundedRect(r.adjusted(-1.5, -1.5, 1.5, 1.5), 3.5, 3.5)
            elif i == self._hover:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(th("on_surface_variant"), 1))
                p.drawRoundedRect(r.adjusted(-1, -1, 1, 1), 3, 3)

    def _tip(self, i: int) -> str:
        s = self.items[i]
        extra = ""
        if s.n_alert or s.n_warn:
            extra = f"\n{s.n_alert} alert(s), {s.n_warn} warning(s)"
        return f"{s.run.label}\n{s.text}{extra}\nClick to open this run."

    def mouseMoveEvent(self, e):  # noqa: N802
        i = self._index_at(e.position().x())
        if i != self._hover:
            self._hover = i
            self.setCursor(Qt.CursorShape.PointingHandCursor if i >= 0 else Qt.CursorShape.ArrowCursor)
            self.update()
        if i >= 0:
            QToolTip.showText(e.globalPosition().toPoint(), self._tip(i), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, _e):  # noqa: N802
        if self._hover != -1:
            self._hover = -1
            self.update()

    def mousePressEvent(self, e):  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            i = self._index_at(e.position().x())
            if i >= 0:
                self.picked.emit(i)


# ---------------------------------------------------------------- timeline

class TimelineView(QWidget):
    """A run as lanes: processes, files, ClamAV, network. Each marker is the events that fall in
    one column of the strip; its size is how many, its colour the worst of them."""
    hovered = Signal(object)         # list[runlog.Event] | None
    picked = Signal(object)          # list[runlog.Event]

    LABEL_W, ROW_H, AXIS_H, PAD = 138, 26, 30, 8

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.tl: runlog.Timeline | None = None
        self.empty_text = "Select a game."
        self._hits: list[tuple[QRectF, list[runlog.Event]]] = []
        self._hover: int = -1
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._fit()

    def set_timeline(self, tl: runlog.Timeline | None, empty_text: str = ""):
        self.tl = tl
        if empty_text:
            self.empty_text = empty_text
        self._hits, self._hover = [], -1
        self._fit()
        self.update()

    def _fit(self):
        lanes = len(self.tl.lanes()) if self.tl else 0
        self.setFixedHeight(max(70, 2 * self.PAD + lanes * self.ROW_H + self.AXIS_H))

    def _track(self) -> tuple[float, float]:
        return float(self.LABEL_W), float(self.width() - self.PAD - 4)

    def paintEvent(self, _e):  # noqa: N802  (Qt override)
        th = self.theme.color
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(th("surface_container")))
        p.setPen(QPen(th("outline"), 1))
        p.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 6, 6)
        tl = self.tl
        self._hits = []
        if tl is None:
            p.setPen(th("on_surface_variant"))
            _text(p, QRectF(self.rect()).adjusted(16, 0, -16, 0), self.empty_text, Qt.AlignmentFlag.AlignCenter, wrap=True)
            return
        x0, x1 = self._track()
        span = max(x1 - x0, 1.0)
        lanes = tl.lanes()
        top = float(self.PAD)
        bottom = top + len(lanes) * self.ROW_H
        fm = p.fontMetrics()
        ink, mut = th("on_surface"), th("on_surface_variant")

        if tl.has_after:                                    # the work after the game exited (diffs, ClamAV)
            gx = x0 + tl.frac(tl.t_game) * span
            p.fillRect(QRectF(gx, top, x1 - gx, bottom - top), _alpha(ink, 16))
            pen = QPen(mut, 1)
            pen.setStyle(Qt.PenStyle.DashLine)
            p.setPen(pen)
            p.drawLine(QPointF(gx, top), QPointF(gx, bottom + 4))

        for li, lane in enumerate(lanes):
            cy = top + li * self.ROW_H + self.ROW_H / 2
            p.setPen(mut)
            _text(p, QRectF(self.PAD + 2, cy - 10, self.LABEL_W - self.PAD - 8, 20),
                  fm.elidedText(runlog.LANE_TITLE[lane], Qt.TextElideMode.ElideRight, self.LABEL_W - self.PAD - 8))
            p.setPen(QPen(_alpha(th("outline"), 200), 1))
            p.drawLine(QPointF(x0, cy), QPointF(x1, cy))
            ncols = max(12, int(span // 13))
            for col, count, worst, evs in tl.bins(lane, ncols):
                cx = x0 + (col + 0.5) / ncols * span
                rad = 3.5 + min(5.0, math.log2(count) * 1.5) if count > 1 else 3.5
                if worst == "ALERT":
                    rad += 1.0
                c = th(LEVEL_TOKEN[worst])
                rect = QRectF(cx - rad, cy - rad, 2 * rad, 2 * rad)
                self._hits.append((rect.adjusted(-2, -3, 2, 3), evs))
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QBrush(c if worst != "INFO" else _alpha(c, 150)))
                p.drawEllipse(rect)
                if worst == "ALERT":
                    p.setBrush(Qt.BrushStyle.NoBrush)
                    p.setPen(QPen(c, 1.5))
                    p.drawEllipse(rect.adjusted(-3, -3, 3, 3))
                if len(self._hits) - 1 == self._hover:
                    p.setBrush(Qt.BrushStyle.NoBrush)
                    p.setPen(QPen(ink, 1.5))
                    p.drawEllipse(rect.adjusted(-2, -2, 2, 2))

        # axis: start, game exit, end
        ay = bottom + 8
        p.setPen(QPen(th("outline"), 1))
        p.drawLine(QPointF(x0, ay), QPointF(x1, ay))
        ticks = [(0.0, "+0:00", Qt.AlignmentFlag.AlignLeft)]
        if tl.has_after:
            ticks.append((tl.frac(tl.t_game), f"{runlog.fmt_offset(tl.t_game - tl.t0)} game exited", Qt.AlignmentFlag.AlignHCenter))
            ticks.append((1.0, runlog.fmt_offset(tl.t1 - tl.t0), Qt.AlignmentFlag.AlignRight))
        else:
            ticks.append((1.0, f"{runlog.fmt_offset(tl.t_game - tl.t0)} game exited", Qt.AlignmentFlag.AlignRight))
        p.setPen(mut)
        last_right = -1e9                                   # right edge of the last label drawn
        for f, text, al in ticks:
            x = x0 + f * span
            p.drawLine(QPointF(x, ay - 3), QPointF(x, ay + 3))
            w = fm.horizontalAdvance(text) + 6
            left = x if al == Qt.AlignmentFlag.AlignLeft else x - w if al == Qt.AlignmentFlag.AlignRight else x - w / 2
            left = min(max(left, x0 - 4), self.width() - w - 2)
            if left < last_right + 6:                       # would run into the previous label: keep the tick, skip the text
                continue
            _text(p, QRectF(left, ay + 3, w, 16), text)
            last_right = left + w

    # ---- mouse
    def _hit_at(self, pos: QPointF) -> int:
        best, dist = -1, 1e9
        for i, (r, _evs) in enumerate(self._hits):
            if r.contains(pos):
                d = abs(r.center().x() - pos.x()) + abs(r.center().y() - pos.y())
                if d < dist:
                    best, dist = i, d
        return best

    def tooltip_for(self, evs: list[runlog.Event], limit: int = 8) -> str:
        tl = self.tl
        lines = []
        for e in evs[:limit]:
            msg = e.msg if len(e.msg) <= 110 else e.msg[:107] + "..."
            lines.append(f"{tl.offset(e.t) if tl else ''}  {e.level:<5}  {msg}")
        if len(evs) > limit:
            lines.append(f"... and {len(evs) - limit} more here")
        return "\n".join(lines)

    def mouseMoveEvent(self, e):  # noqa: N802
        i = self._hit_at(e.position())
        if i != self._hover:
            self._hover = i
            self.setCursor(Qt.CursorShape.PointingHandCursor if i >= 0 else Qt.CursorShape.ArrowCursor)
            self.hovered.emit(self._hits[i][1] if i >= 0 else None)
            self.update()
        if i >= 0:
            QToolTip.showText(e.globalPosition().toPoint(), self.tooltip_for(self._hits[i][1]), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, _e):  # noqa: N802
        if self._hover != -1:
            self._hover = -1
            self.hovered.emit(None)
            self.update()

    def mousePressEvent(self, e):  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            i = self._hit_at(e.position())
            if i >= 0:
                self.picked.emit(self._hits[i][1])


# ---------------------------------------------------------------- pre-flight

class _GateBar(QWidget):
    """One segment per verifier check: green passed, red failed."""

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.checks: list[runlog.Check] = []
        self.aborted = False
        self.setFixedHeight(14)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_checks(self, checks: list[runlog.Check], aborted: bool = False):
        self.checks, self.aborted = checks, aborted
        self.update()

    def paintEvent(self, _e):  # noqa: N802  (Qt override)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        th = self.theme.color
        n = len(self.checks)
        if not n:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(_alpha(th("outline"), 160)))
            p.drawRoundedRect(QRectF(0, 3, self.width(), 8), 3, 3)
            return
        gap = 2.0
        w = (self.width() - gap * (n - 1)) / n
        p.setPen(Qt.PenStyle.NoPen)
        for i, c in enumerate(self.checks):
            p.setBrush(QBrush(th("ok") if c.ok else th("error")))
            p.drawRoundedRect(QRectF(i * (w + gap), 2, max(w, 1.0), 10), 2, 2)


class PreflightCard(QWidget):
    """The sandbox verifier's result for a launch, as a gate: a bar of checks and, below it, the
    checks grouped by what they protect. Collapsed while everything passed."""

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.pf: runlog.Preflight | None = None
        self.when = ""
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        head = QHBoxLayout()
        self.title = QLabel()
        self.title.setWordWrap(True)
        self.title.setTextFormat(Qt.TextFormat.RichText)
        head.addWidget(self.title, 1)
        self.toggle = QPushButton("Show checks")
        self.toggle.setCheckable(True)
        self.toggle.toggled.connect(self._toggled)
        head.addWidget(self.toggle, 0, Qt.AlignmentFlag.AlignTop)
        v.addLayout(head)
        self.bar = _GateBar(theme)
        v.addWidget(self.bar)
        self.detail = QLabel()
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.RichText)
        self.detail.setVisible(False)
        v.addWidget(self.detail)
        self.set_preflight(None)

    def set_preflight(self, pf: runlog.Preflight | None, when: str = "", empty: str = ""):
        self.pf, self.when = pf, when
        mut = _hex(self.theme, "on_surface_variant")
        self.toggle.setVisible(bool(pf and pf.checks))
        if pf is None or not pf.found:
            self.bar.set_checks([])
            self.title.setText(f'<span style="color:{mut}">{_esc(empty or "No sandbox check recorded for this run.")}</span>')
            self.detail.setVisible(False)
            return
        self.bar.set_checks(pf.checks, pf.aborted)
        total = pf.passed + pf.failed
        if pf.ok:
            col = _hex(self.theme, "ok")
            self.title.setText(f'<b style="color:{col}">✓ {pf.passed} of {total} checks passed</b>'
                               f'<span style="color:{mut}"> &nbsp;The sandbox verified itself before the game started'
                               f'{" · " + _esc(when) if when else ""}.</span>')
        else:
            col = _hex(self.theme, "error")
            what = "The launch was stopped. " if pf.aborted else ""
            self.title.setText(f'<b style="color:{col}">✗ {pf.failed} of {total} checks failed</b>'
                               f'<span style="color:{mut}"> &nbsp;{what}{"(" + _esc(when) + ")" if when else ""}</span>')
        self._fill_detail()
        # open by default only when something failed
        self.toggle.blockSignals(True)
        self.toggle.setChecked(not pf.ok)
        self.toggle.blockSignals(False)
        self._toggled(not pf.ok)

    def _fill_detail(self):
        pf = self.pf
        if pf is None:
            return
        ok, bad, mut = (_hex(self.theme, k) for k in ("ok", "error", "on_surface_variant"))
        rows = []
        for g in runlog.GROUPS:
            items = [c for c in pf.checks if c.group == g]
            if not items:
                continue
            items.sort(key=lambda c: c.ok)                      # failures first
            lis = "".join(f'<div><span style="color:{ok if c.ok else bad}">{"✓" if c.ok else "✗"}</span> '
                          f'{_esc(c.text)}</div>' for c in items)
            rows.append(f'<tr><td style="color:{mut}; padding-right:14px; vertical-align:top; white-space:nowrap">{_esc(g)}</td>'
                        f'<td style="padding-bottom:5px">{lis}</td></tr>')
        self.detail.setText("<table>" + "".join(rows) + "</table>")

    def _toggled(self, on: bool):
        self.toggle.setText("Hide checks" if on else "Show checks")
        self.detail.setVisible(bool(on and self.pf and self.pf.checks))

    def refresh_theme(self):
        self.set_preflight(self.pf, self.when)


# ---------------------------------------------------------------- runs tab

class RunsTab(QWidget):
    """Everything about how a game's runs went: history, the sandbox check, the timeline and
    what is different from the run before. Reads the logs the launcher already writes."""

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.game = None
        self.history: list[runlog.RunSummary] = []
        self.cur = -1
        self._dirty = False
        self._rows: dict[runlog.Event, int] = {}
        self._live: tuple[str, list[str]] | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        v = QVBoxLayout(body)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        head = QHBoxLayout()
        self.title = QLabel("Runs")
        head.addWidget(self.title, 1)
        head.addWidget(QLabel("Run"))
        self.combo = QComboBox()
        self.combo.setMinimumWidth(240)
        self.combo.currentIndexChanged.connect(self._combo_changed)
        head.addWidget(self.combo)
        v.addLayout(head)

        self.strip = HistoryStrip(theme)
        self.strip.picked.connect(self._pick_run)
        v.addWidget(self.strip)
        self.trend = QLabel()
        self.trend.setWordWrap(True)
        self.trend.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(self.trend)

        g = QGroupBox("Sandbox check before launch")
        gl = QVBoxLayout(g)
        self.preflight = PreflightCard(theme)
        gl.addWidget(self.preflight)
        v.addWidget(g)

        g = QGroupBox("Timeline")
        gl = QVBoxLayout(g)
        self.timeline = TimelineView(theme)
        self.timeline.picked.connect(self._timeline_picked)
        gl.addWidget(self.timeline)
        self.legend = _muted()
        self.legend.setTextFormat(Qt.TextFormat.RichText)
        gl.addWidget(self.legend)
        v.addWidget(g)

        g = QGroupBox("Since the run before")
        gl = QVBoxLayout(g)
        self.diff = QLabel()
        self.diff.setWordWrap(True)
        self.diff.setTextFormat(Qt.TextFormat.RichText)
        gl.addWidget(self.diff)
        v.addWidget(g)

        g = QGroupBox("Warnings and alerts in this run")
        gl = QVBoxLayout(g)
        self.events = QListWidget()
        self.events.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.events.setMinimumHeight(110)
        self.events.setMaximumHeight(220)
        gl.addWidget(self.events)
        v.addWidget(g)
        v.addStretch(1)
        self._refresh_legend()
        self._show_none("Select one game to see its runs.")

    # ---- game / refresh
    def set_game(self, g):
        if g is None and self.game is None:
            return
        if g is not None and self.game is not None and g.path == self.game.path and not self._dirty:
            return
        self.game = g
        self._live = None
        if g is None:
            self.history, self.cur = [], -1
            self._show_none("Select one game to see its runs.")
        elif self.isVisible():
            self.refresh()
        else:
            self._dirty = True

    def showEvent(self, e):  # noqa: N802
        super().showEvent(e)
        if self._dirty:
            self.refresh()

    def run_finished(self, g):
        if self.game is not None and g.path == self.game.path:
            self._live = None
            if self.isVisible():
                self.refresh()
            else:
                self._dirty = True

    def refresh(self, keep: bool = False):
        self._dirty = False
        g = self.game
        if g is None:
            self._show_none("Select one game to see its runs.")
            return
        keep_stamp = self.history[self.cur].run.stamp if keep and 0 <= self.cur < len(self.history) else None
        self.history = runlog.run_history(g.path, 20)
        self.title.setText(f"Runs of {g.name}")
        self.combo.blockSignals(True)
        self.combo.clear()
        for i in range(len(self.history) - 1, -1, -1):
            s = self.history[i]
            self.combo.addItem(f"{s.run.label}  ·  {s.text}", i)
        self.combo.blockSignals(False)
        if not self.history:
            self.cur = -1
            self.strip.set_history([], -1)
            self._show_none("This game has not been run yet.")
            if self._live:
                self._show_live()
            return
        idx = len(self.history) - 1
        if keep_stamp:
            idx = next((i for i, s in enumerate(self.history) if s.run.stamp == keep_stamp), idx)
        self.strip.set_history(self.history, idx)
        self._select(idx)

    def _show_none(self, text: str):
        self.combo.blockSignals(True)
        self.combo.clear()
        self.combo.blockSignals(False)
        self.strip.set_history([], -1)
        self.trend.setText("")
        self.timeline.set_timeline(None, text)
        self.preflight.set_preflight(None, empty=text)
        self.diff.setText("")
        self.events.clear()
        self._rows = {}
        if self.game is None:
            self.title.setText("Runs")

    # ---- selecting a run
    def _combo_changed(self, row: int):
        i = self.combo.itemData(row)
        if isinstance(i, int):
            self._select(i, from_combo=True)

    def _pick_run(self, i: int):
        self._select(i)

    def _select(self, i: int, from_combo: bool = False):
        if not 0 <= i < len(self.history):
            return
        self.cur = i
        self.strip.set_current(i)
        if not from_combo:
            self.combo.blockSignals(True)
            self.combo.setCurrentIndex(len(self.history) - 1 - i)
            self.combo.blockSignals(False)
        s = self.history[i]
        prev = self.history[i - 1] if i > 0 else None
        mut, bad, warn, ok = (_hex(self.theme, k) for k in ("on_surface_variant", "error", "warn", "ok"))

        note = runlog.trend_note(self.history) if i == len(self.history) - 1 else ""
        self.trend.setText(f'<b style="color:{warn}">⚠ {_esc(note)}</b>' if note else
                           f'<span style="color:{mut}">Last {len(self.history)} run{"s" if len(self.history) != 1 else ""}, '
                           f'oldest on the left. Taller bars have more findings. Click one to open it.</span>')

        tl = runlog.build_timeline(s.run, self.game.path if self.game else None)
        self.timeline.set_timeline(tl, "This run left no monitor log, so there is nothing to draw.")
        self._fill_events(tl)

        pf = runlog.parse_preflight(runlog.launch_text(s.run))
        if i == len(self.history) - 1 and self._live and self.game and self._live[0] == self.game.name:
            self._show_live()
        else:
            self.preflight.set_preflight(pf, s.run.label, empty="This run's launch log has no sandbox check in it.")

        new, gone = runlog.compare(prev, s)
        self.diff.setText(self._diff_html(prev, s, new, gone, mut, bad, ok))

    def _diff_html(self, prev, s, new, gone, mut, bad, ok) -> str:
        if prev is None:
            if not s.findings_raw:
                return f'<span style="color:{mut}">First recorded run, and it has no warnings or alerts.</span>'
            return f'<span style="color:{mut}">First recorded run: all {len(new)} finding(s) below are new.</span>' + self._bullets(new, bad)
        if not new and not gone:
            return f'<span style="color:{ok}">Same as the run before.</span><span style="color:{mut}"> No finding appeared or went away.</span>'
        out = []
        if new:
            out.append(f'<b style="color:{bad}">{len(new)} new</b>' + self._bullets(new, bad))
        if gone:
            out.append(f'<b style="color:{ok}">{len(gone)} gone</b>' + self._bullets(gone, mut))
        return "<br>".join(out)

    @staticmethod
    def _bullets(msgs: list[str], color: str, limit: int = 6) -> str:
        rows = [f'<div style="color:{color}">&nbsp;&nbsp;• {_esc(m if len(m) <= 140 else m[:137] + "...")}</div>' for m in msgs[:limit]]
        if len(msgs) > limit:
            rows.append(f'<div>&nbsp;&nbsp;… and {len(msgs) - limit} more</div>')
        return "".join(rows)

    def _fill_events(self, tl: runlog.Timeline | None):
        self.events.clear()
        self._rows = {}
        if tl is None:
            return
        notable = tl.notable()
        if not notable:
            it = QListWidgetItem("Nothing to report: no warnings or alerts in this run.")
            it.setForeground(QBrush(self.theme.color("on_surface_variant")))
            self.events.addItem(it)
            return
        for e in notable:
            lane = runlog.LANE_TITLE.get(e.kind, e.kind)
            it = QListWidgetItem(f"{tl.offset(e.t):>8}  {e.level:<5}  {lane}: {e.msg}")
            it.setForeground(QBrush(self.theme.color(LEVEL_TOKEN[e.level])))
            it.setToolTip(e.msg)
            self.events.addItem(it)
            self._rows[e] = self.events.count() - 1

    def _timeline_picked(self, evs):
        for e in sorted(evs, key=lambda e: -e.rank):
            row = self._rows.get(e)
            if row is not None:
                self.events.setCurrentRow(row)
                self.events.scrollToItem(self.events.item(row))
                return

    # ---- live pre-flight while a game launches
    def begin_launch(self, name: str):
        self._live = (name, [])

    def feed_launch_line(self, name: str, line: str):
        if self._live is None or self._live[0] != name:
            return
        if "[SANDBOX-VERIFY]" in line or "[LEAK]" in line:
            self._live[1].append(line)
            if self.game is not None and self.game.name == name:
                self._show_live()

    def _show_live(self):
        if not self._live:
            return
        pf = runlog.parse_preflight("\n".join(self._live[1]))
        self.preflight.set_preflight(pf, "this launch")

    # ---- theme
    def _refresh_legend(self):
        ink, warn, bad = (_hex(self.theme, k) for k in ("on_surface_variant", "warn", "error"))
        self.legend.setText(f'<span style="color:{ink}">● routine &nbsp; </span><span style="color:{warn}">● warning &nbsp; </span>'
                            f'<span style="color:{bad}">◉ alert &nbsp; </span>'
                            f'<span style="color:{ink}">Bigger dot = more events at that moment. Hover for details, click to find it in the list. '
                            f'The shaded part is what the monitor did after the game exited (file diffs, ClamAV).</span>')

    def refresh_theme(self):
        self._refresh_legend()
        self.preflight.refresh_theme()
        for w in (self.strip, self.timeline):
            w.update()
        if self.game is not None and 0 <= self.cur < len(self.history):
            self._select(self.cur)


# ---------------------------------------------------------------- network host map

class HostMapView(QWidget):
    """The destinations a game tried to reach, busiest first, as bars. Red: blocked. Amber: some
    blocked, or learn mode. Green: let through by a filtered allow-list. A pill marks a
    destination first seen in the latest run."""
    picked = Signal(str)

    ROW_H, LABEL_W, PAD, MAX_ROWS = 24, 190, 8, 10

    def __init__(self, theme):
        super().__init__()
        self.theme = theme
        self.hosts: list[runlog.Host] = []
        self.empty_text = "Select one game."
        self._rows: list[tuple[QRectF, runlog.Host]] = []
        self._hover = -1
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._fit()

    def set_hosts(self, hosts: list[runlog.Host], empty_text: str = ""):
        self.hosts = hosts[: self.MAX_ROWS]
        if empty_text:
            self.empty_text = empty_text
        self._hover = -1
        self._fit()
        self.update()

    def _fit(self):
        self.setFixedHeight(max(54, 2 * self.PAD + max(len(self.hosts), 1) * self.ROW_H))

    def paintEvent(self, _e):  # noqa: N802  (Qt override)
        th = self.theme.color
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(th("surface_container")))
        p.setPen(QPen(th("outline"), 1))
        p.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 6, 6)
        self._rows = []
        if not self.hosts:
            p.setPen(th("on_surface_variant"))
            _text(p, QRectF(self.rect()).adjusted(16, 0, -16, 0), self.empty_text, Qt.AlignmentFlag.AlignCenter, wrap=True)
            return
        fm = p.fontMetrics()
        x0 = float(self.LABEL_W)
        avail = max(40.0, self.width() - x0 - self.PAD - 120)
        biggest = math.sqrt(max(h.hits for h in self.hosts))
        for i, h in enumerate(self.hosts):
            y = self.PAD + i * self.ROW_H
            row = QRectF(self.PAD / 2, y, self.width() - self.PAD, self.ROW_H)
            self._rows.append((row, h))
            if i == self._hover:
                p.fillRect(row, _alpha(th("on_surface"), 14))
            ports = ",".join(str(x) for x in h.ports[:3]) + ("…" if len(h.ports) > 3 else "")
            p.setPen(th("on_surface"))
            _text(p, QRectF(self.PAD + 2, y, self.LABEL_W - self.PAD - 6, self.ROW_H),
                  fm.elidedText(f"{h.addr}:{ports}", Qt.TextElideMode.ElideRight, self.LABEL_W - self.PAD - 8))
            c = th(TOKEN[h.tone])
            w = max(4.0, avail * math.sqrt(h.hits) / biggest)
            bar = QRectF(x0, y + 5, w, self.ROW_H - 10)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(c))
            p.drawRoundedRect(bar, 3, 3)
            tx = x0 + w + 8
            p.setPen(th("on_surface_variant"))
            label = f"{h.hits}×" + (f"  {h.blocked} blocked" if h.blocked else "")
            _text(p, QRectF(tx, y, 130, self.ROW_H), label)
            if h.new:
                px = tx + fm.horizontalAdvance(label) + 10
                pill = QRectF(px, y + 4, fm.horizontalAdvance("new") + 12, self.ROW_H - 8)
                p.setBrush(QBrush(_alpha(th("primary"), 60)))
                p.setPen(QPen(th("primary"), 1))
                p.drawRoundedRect(pill, 8, 8)
                p.setPen(th("on_surface"))
                _text(p, pill, "new", Qt.AlignmentFlag.AlignCenter)

    def _tip(self, h: runlog.Host) -> str:
        first = time.strftime("%Y-%m-%d %H:%M", time.localtime(h.first))
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(h.last))
        ports = ", ".join(str(x) for x in h.ports[:12]) + (" ..." if len(h.ports) > 12 else "")
        bits = [f"{h.addr}", f"ports: {ports}"]
        if h.protos:
            bits.append("protocol: " + ", ".join(sorted(h.protos)))
        bits += [f"{h.hits} attempts ({h.blocked} blocked, {h.allowed} let through)",
                 f"first seen {first}, last {last}"]
        if h.new:
            bits.append("first seen in the latest run")
        bits.append("Attempts are logged at most once a second per destination.")
        return "\n".join(bits)

    def mouseMoveEvent(self, e):  # noqa: N802
        i = next((k for k, (r, _h) in enumerate(self._rows) if r.contains(e.position())), -1)
        if i != self._hover:
            self._hover = i
            self.setCursor(Qt.CursorShape.PointingHandCursor if i >= 0 else Qt.CursorShape.ArrowCursor)
            self.update()
        if i >= 0:
            QToolTip.showText(e.globalPosition().toPoint(), self._tip(self._rows[i][1]), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, _e):  # noqa: N802
        if self._hover != -1:
            self._hover = -1
            self.update()

    def mousePressEvent(self, e):  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton and 0 <= self._hover < len(self._rows):
            self.picked.emit(self._rows[self._hover][1].addr)
