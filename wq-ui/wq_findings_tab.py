"""Findings tab: what YARA, capa, ClamAV and the pre-launch checks (packing, big encrypted blocks) found.

Reads the game's alert logs (wq_findings does the parsing) and shows one row per finding. "Scan now" runs the
same pre-launch scan a launch would run (wq-prescan.sh) without starting the game, then shows the result."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QProcess, Qt, QUrl
from PySide6.QtGui import QBrush, QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QLabel, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

import wq_findings as F

LEVEL_TEXT = {"ALERT": "Alert", "WARN": "Warning", "INFO": "Info"}


class FindingsTab(QWidget):
    def __init__(self, theme, qroot, parent=None):
        super().__init__(parent)
        self.theme, self.qroot = theme, Path(qroot)
        self.game = None
        self.proc: QProcess | None = None
        self._log: Path | None = None

        top = QHBoxLayout()
        self.cmb_log = QComboBox()
        self.cmb_log.setMinimumWidth(260)
        self.cmb_log.currentIndexChanged.connect(self._load_selected)
        self.chk_info = QCheckBox("Show informational")
        self.chk_info.setChecked(True)
        self.chk_info.toggled.connect(self._load_selected)
        self.btn_scan = QPushButton("Scan now")
        self.btn_scan.setToolTip("Runs the pre-launch scan (YARA, capa, packing and encrypted-block checks, ClamAV) "
                                 "on this game without starting it.")
        self.btn_scan.clicked.connect(self.scan_now)
        self.btn_open = QPushButton("Open log")
        self.btn_open.clicked.connect(self._open_log)
        top.addWidget(QLabel("Run:"))
        top.addWidget(self.cmb_log)
        top.addWidget(self.chk_info)
        top.addStretch(1)
        top.addWidget(self.btn_scan)
        top.addWidget(self.btn_open)

        self.status = QLabel("Select a game.")
        self.status.setWordWrap(True)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Level", "Source", "Finding", "Details", "File"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setColumnWidth(0, 80)
        self.tree.setColumnWidth(1, 120)
        self.tree.setColumnWidth(2, 260)
        self.tree.setColumnWidth(3, 420)

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.status)
        lay.addWidget(self.tree, 1)
        self._enable(False)

    def _enable(self, on: bool):
        for w in (self.cmb_log, self.chk_info, self.btn_scan, self.btn_open):
            w.setEnabled(on)

    # ---------- game link
    def set_game(self, g):
        self.game = g
        self.tree.clear()
        self.cmb_log.blockSignals(True)
        self.cmb_log.clear()
        self.cmb_log.blockSignals(False)
        if g is None:
            self._enable(False)
            self.status.setText("Select a game.")
            return
        self.refresh()

    def refresh(self, pick: Path | None = None):
        """Reload the list of runs; show `pick`, else the newest."""
        if self.game is None:
            return
        logs = F.logs_for(Path(self.game.path))
        self._enable(True)
        self.btn_open.setEnabled(bool(logs))
        self.cmb_log.blockSignals(True)
        self.cmb_log.clear()
        for p in logs:
            self.cmb_log.addItem(p.name, str(p))
        idx = self.cmb_log.findData(str(pick)) if pick else 0
        self.cmb_log.setCurrentIndex(max(idx, 0))
        self.cmb_log.blockSignals(False)
        if not logs:
            self.tree.clear()
            self.status.setText("No scan has run for this game yet. Press Scan now, or launch it.")
            return
        self._load_selected()

    def refresh_theme(self):
        self._load_selected()

    # ---------- table
    def _load_selected(self, *_):
        path = self.cmb_log.currentData()
        self.tree.clear()
        self._log = Path(path) if path else None
        if self._log is None:
            return
        try:
            text = self._log.read_text(errors="replace")
        except OSError as e:
            self.status.setText(f"Cannot read {self._log.name}: {e}")
            return
        found = F.parse(text)
        self.status.setText(F.summary(found))
        t = self.theme.color
        colour = {"ALERT": t("error"), "WARN": t("warn"), "INFO": t("on_surface_variant")}
        for f in found:
            if f.level == "INFO" and not self.chk_info.isChecked():
                continue
            it = QTreeWidgetItem([LEVEL_TEXT[f.level], f.source, f.what, f.detail, f.file])
            it.setForeground(0, QBrush(colour[f.level]))
            it.setToolTip(3, f.detail)
            it.setToolTip(4, f.file)
            self.tree.addTopLevelItem(it)

    def _open_log(self):
        if self._log is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._log)))

    # ---------- scan without launching
    def scan_now(self):
        if self.game is None or self.proc is not None:
            return
        script = self.qroot / "wq-prescan.sh"
        if not script.is_file():
            self.status.setText(f"{script} is missing.")
            return
        from time import strftime
        self._scan_log = Path(self.game.path) / "logs" / f"alerts-{strftime('%Y%m%d-%H%M%S')}-scan.log"
        self._scan_log.parent.mkdir(parents=True, exist_ok=True)
        self.proc = QProcess(self)
        self.proc.setWorkingDirectory(str(self.qroot))
        self.proc.finished.connect(self._scan_done)
        self.proc.errorOccurred.connect(lambda *_: self._scan_done(-1, QProcess.ExitStatus.CrashExit))
        self.btn_scan.setEnabled(False)
        self.status.setText("Scanning (YARA, capa, packing and encrypted-block checks, ClamAV)... this can take a minute.")
        self.proc.start("bash", [str(script), self.game.name, "--alertlog", str(self._scan_log)])

    def _scan_done(self, *_):
        proc, self.proc = self.proc, None
        if proc is not None:
            proc.deleteLater()
        self.btn_scan.setEnabled(True)
        self.refresh(pick=self._scan_log if self._scan_log.exists() else None)

    def shutdown(self):
        if self.proc is not None:
            self.proc.kill()
            self.proc.waitForFinished(2000)
            self.proc = None
