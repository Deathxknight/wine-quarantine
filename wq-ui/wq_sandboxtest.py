"""'Test sandbox' dialog: runs probe.sh inside a throwaway native game that uses the selected game's
firejail profile and shows what the jail lets through, with a diff against the previous run."""
from __future__ import annotations

import os
import shutil
import signal
from pathlib import Path

from PySide6.QtCore import QProcess, QProcessEnvironment, Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFont, QGuiApplication, QTextCursor
from PySide6.QtWidgets import (QCheckBox, QDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton,
                               QTabWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

import wq_core as core
import wq_probe as probe

TIMEOUT_MS = 180_000
TAG_COLOR = {"LEAK": "#d64545", "ok": "#2e9e55", "info": None}
STATUS_TEXT = {
    "clean": ("No leaks found", "#2e9e55"),
    "leaks": ("Leaks found", "#d64545"),
    "blocked": ("The sandbox verifier stopped the launch", "#d64545"),
    "noprobe": ("The probe did not run (see Raw log)", "#d6a645"),
}


class SandboxTestDialog(QDialog):
    def __init__(self, parent: QWidget, qroot: Path, game: core.Game | None, defaults: dict[str, list[str]]):
        super().__init__(parent)
        self.qroot, self.game, self.defaults = qroot, game, defaults
        self.name = game.name if game else probe.DEFAULTS_KEY
        self.setWindowTitle(f"Test sandbox: {self.name}")
        self.resize(820, 620)
        self.proc: QProcess | None = None
        self.output = ""
        self.profile: dict[str, list[str]] = {}
        self.run_data: dict | None = None
        self.prev: dict | None = None

        v = QVBoxLayout(self)
        self.headline = QLabel("")
        f = self.headline.font(); f.setBold(True); f.setPointSize(f.pointSize() + 2)
        self.headline.setFont(f)
        v.addWidget(self.headline)
        self.sub = QLabel("")
        self.sub.setWordWrap(True)
        v.addWidget(self.sub)

        self.tabs = QTabWidget()
        v.addWidget(self.tabs, 1)

        res = QWidget()
        rl = QVBoxLayout(res)
        rl.setContentsMargins(0, 6, 0, 0)
        self.only_problems = QCheckBox("Only show leaks and things that changed")
        self.only_problems.toggled.connect(self._fill_tree)
        rl.addWidget(self.only_problems)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["", "Check"])
        self.tree.setRootIsDecorated(True)
        self.tree.setColumnWidth(0, 70)
        rl.addWidget(self.tree, 1)
        self.tabs.addTab(res, "Results")

        self.changes = QPlainTextEdit()
        self.changes.setReadOnly(True)
        self.tabs.addTab(self.changes, "Changes since last run")

        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setFont(QFont("monospace"))
        self.raw.setMaximumBlockCount(5000)
        self.tabs.addTab(self.raw, "Raw log")

        row = QHBoxLayout()
        self.btn_run = QPushButton("Run again")
        self.btn_run.clicked.connect(self.start)
        self.btn_copy = QPushButton("Copy report")
        self.btn_copy.clicked.connect(self.copy_report)
        self.btn_copy.setEnabled(False)
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.close)
        row.addWidget(self.btn_run)
        row.addWidget(self.btn_copy)
        row.addStretch(1)
        row.addWidget(self.btn_close)
        v.addLayout(row)

        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._timeout)
        QTimer.singleShot(0, self.start)

    # running
    def start(self):
        if self.proc is not None:
            return
        for tool in ("firejail", "inotifywait"):
            if not shutil.which(tool):
                QMessageBox.warning(self, "Missing tool", f"{tool} is not installed, the sandbox can't be tested.")
                return
        try:
            self.profile = probe.effective_profile(self.game, self.defaults)
            d = probe.prepare(self.qroot, self.profile)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Can't set up the test", str(e))
            return
        self.prev = (probe.load_runs(self.qroot, self.name) or [None])[-1]
        self.output = ""
        self.raw.clear()
        self.tree.clear()
        self.changes.clear()
        self.run_data = None
        self.btn_run.setEnabled(False)
        self.btn_copy.setEnabled(False)
        self.headline.setText("Testing…")
        self.headline.setStyleSheet("")
        src = f"the profile of '{self.game.name}'" if self.game else "the saved defaults"
        self.sub.setText(f"Running probe.sh inside the sandbox with {src}, as a native game. "
                         "It only looks at things and tries harmless calls.")
        p = QProcess(self)
        p.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        p.setWorkingDirectory(str(d))
        p.setStandardInputFile(os.devnull)
        env = QProcessEnvironment.systemEnvironment()
        env.insert("WQ_XRAY_BASELINE", "0")
        p.setProcessEnvironment(env)
        p.readyReadStandardOutput.connect(self._read)
        p.finished.connect(self._finished)
        p.errorOccurred.connect(lambda _e: self._append("[failed to start the launcher]\n"))
        self.proc = p
        script = str(d / "launch-quarantine.sh")
        if hasattr(p, "setChildProcessModifier"):
            p.setChildProcessModifier(lambda: os.setsid())
            p.start(script, [])
        else:
            p.start("setsid", [script])
        self.timer.start(TIMEOUT_MS)

    def _append(self, text: str):
        self.output += text
        self.raw.moveCursor(QTextCursor.MoveOperation.End)
        self.raw.insertPlainText(text)

    def _read(self):
        if self.proc is not None:
            self._append(bytes(self.proc.readAllStandardOutput()).decode(errors="replace"))

    def _kill_group(self, sig):
        if self.proc is not None and self.proc.processId():
            try:
                os.killpg(self.proc.processId(), sig)
            except (OSError, ProcessLookupError):
                pass

    def _timeout(self):
        self._append("\n[test timed out, stopping it]\n")
        self._kill_group(signal.SIGTERM)

    def _finished(self, *_):
        self.timer.stop()
        self._read()
        self.proc = None
        parsed = probe.parse_output(self.output)
        self.run_data = probe.make_run(parsed, self.profile)
        if self.run_data["status"] in ("clean", "leaks"):       # a run that never got going isn't worth keeping
            try:
                probe.save_run(self.qroot, self.name, self.run_data)
            except OSError as e:
                self._append(f"\n[could not save the result: {e}]\n")
        self.btn_run.setEnabled(True)
        self.btn_copy.setEnabled(True)
        self._show()

    # showing
    def _show(self):
        run = self.run_data
        if run is None:
            return
        text, color = STATUS_TEXT[run["status"]]
        c = probe.counts(run["rows"])
        self.headline.setText(text)
        self.headline.setStyleSheet(f"color: {color};")
        if run["status"] in ("clean", "leaks"):
            self.sub.setText(f"{c['LEAK']} leak(s), {c['ok']} ok, {c['info']} info. "
                             "'info' lines depend on your toggles: read them, they are not failures.")
        elif run["status"] == "blocked":
            self.sub.setText("Fix these first (the game would not have started either):\n  "
                             + "\n  ".join(run["verify_fail_lines"] or ["see the Raw log"]))
        else:
            self.sub.setText("Nothing was reported. Usually firejail or inotify-tools is missing, or the profile "
                             "is invalid (a cancelled launch prints why). Check the Raw log.")
        self._fill_tree()
        self._fill_changes()
        if run["status"] in ("noprobe", "blocked"):
            self.tabs.setCurrentIndex(2 if run["status"] == "noprobe" else 0)

    def _changed_keys(self) -> set[tuple[str, str]]:
        if not self.prev or not self.run_data:
            return set()
        return {(r["section"], probe.norm(r["text"])) for r in probe.diff_rows(self.prev["rows"], self.run_data["rows"])
                if r["new"] is not None}

    def _fill_tree(self, *_):
        self.tree.clear()
        if not self.run_data:
            return
        only = self.only_problems.isChecked()
        changed = self._changed_keys()
        sections: dict[str, QTreeWidgetItem] = {}
        for r in self.run_data["rows"]:
            is_changed = (r["section"], probe.norm(r["text"])) in changed
            if only and r["tag"] != "LEAK" and not is_changed:
                continue
            top = sections.get(r["section"])
            if top is None:
                top = QTreeWidgetItem(self.tree, ["", r["section"]])
                bf = top.font(1); bf.setBold(True); top.setFont(1, bf)
                sections[r["section"]] = top
            label = r["text"] + ("   (changed)" if is_changed else "")
            it = QTreeWidgetItem(top, [r["tag"], label])
            col = TAG_COLOR.get(r["tag"])
            if col:
                it.setForeground(0, QBrush(QColor(col)))
            if r["tag"] == "LEAK":
                bf = it.font(0); bf.setBold(True); it.setFont(0, bf); it.setFont(1, bf)
            it.setToolTip(1, r["text"])
        self.tree.expandAll()

    def _fill_changes(self):
        run = self.run_data
        if not run:
            return
        if not self.prev:
            self.changes.setPlainText("This is the first saved test for this game, so there is nothing to compare with yet.\n"
                                      "Change a setting on the Protection tab, apply it, and run the test again.")
            return
        lines = [f"Compared with the run from {self.prev['time']}:", ""]
        pd = probe.diff_profile(self.prev.get("profile", {}), run["profile"])
        lines.append("Settings that changed:")
        lines += [f"  {k}: {a} -> {b}" for k, a, b in pd] or ["  none"]
        lines += ["", "Results that changed:"]
        rd = probe.diff_rows(self.prev["rows"], run["rows"])
        for r in rd:
            lines.append(f"  [{r['old'] or '-'} -> {r['new'] or '-'}]  {r['section']}: {r['text']}")
        if not rd:
            lines.append("  none")
            if pd:
                lines.append("")
                lines.append("A setting changed but no result did. That usually means the toggle isn't covered by a probe check,")
                lines.append("or it only matters for something the probe doesn't try.")
        self.changes.setPlainText("\n".join(lines))

    def copy_report(self):
        if self.run_data:
            QGuiApplication.clipboard().setText(probe.format_report(self.name, self.run_data, self.prev))

    def closeEvent(self, e):
        if self.proc is not None:
            self.timer.stop()
            self._kill_group(signal.SIGTERM)
            self.proc.waitForFinished(3000)
            if self.proc.state() != QProcess.ProcessState.NotRunning:
                self._kill_group(signal.SIGKILL)
        super().closeEvent(e)
