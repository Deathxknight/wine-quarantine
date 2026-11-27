"""'Relax…' dialog: launches the selected game through wq-ui's normal launch path and, if the sandbox
ends inside the quick-launch window, switches off the next restriction on the ladder (wq_relax.LADDER)
and tries again, until one launch stays up.

The logic that decides what to relax and what a trial's result means is in wq_relax.py (Qt-free, tested by
test_relax.py). This file only drives it: it polls once every 250 ms and never blocks.
"""
from __future__ import annotations

import os
import time

from PySide6.QtCore import QProcess, Qt, QTimer
from PySide6.QtWidgets import (QCheckBox, QDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QSpinBox, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

import wq_core as core
import wq_dialogs
import wq_relax as relax

TICK_MS = 250
# Pre-launch scans and a first-run prefix setup can take a while before any sandbox exists. Stop is always
# there; this only stops a launch that never gets anywhere from waiting forever.
START_TIMEOUT_S = 900
NOT_STARTED_GRACE_S = 6          # no launcher process at all this long after asking: the launch was refused

IDLE, WATCH, PAUSED, DONE = "idle", "watch", "paused", "done"
COL_STEP, COL_COST, COL_STATE = 0, 1, 2


class RelaxDialog(QDialog):
    def __init__(self, win, game: core.Game):
        super().__init__(win)
        self.win = win
        self.name = game.name
        self.conf = game.path / "game.conf"
        self.state = IDLE
        self.snap: dict[str, list[str] | None] | None = None
        self.relaxed: list[relax.Step] = []
        self.remaining: list[relax.Step] = []
        self.proposal: tuple[relax.Step, str] | None = None
        self.success = False
        self.trial_no = 0
        self.window_s = 20
        self._reset_trial()

        self.setWindowTitle(f"Relax until it launches: {self.name}")
        self.resize(640, 640)
        v = QVBoxLayout(self)

        intro = QLabel(
            "Launches the game with its current settings. If the sandbox ends within the quick-launch window, "
            "the next restriction is switched off for this game and it launches again, until one launch stays up. "
            "Monitoring, scanning and network settings are never touched, and nothing is relaxed to get past a "
            "pre-launch refusal or a monitor alert.")
        intro.setWordWrap(True)
        v.addWidget(intro)

        # a session that was cut short earlier left a backup: settle that before starting a new one
        self.stale = QWidget()
        sl = QVBoxLayout(self.stale)
        sl.setContentsMargins(0, 0, 0, 0)
        self.stale_label = QLabel("")
        self.stale_label.setWordWrap(True)
        sl.addWidget(self.stale_label)
        sb = QHBoxLayout()
        self.btn_stale_restore = QPushButton("Restore the settings from before")
        self.btn_stale_restore.clicked.connect(self._stale_restore)
        self.btn_stale_keep = QPushButton("Keep what is there now")
        self.btn_stale_keep.clicked.connect(self._stale_keep)
        sb.addWidget(self.btn_stale_restore)
        sb.addWidget(self.btn_stale_keep)
        sb.addStretch(1)
        sl.addLayout(sb)
        v.addWidget(self.stale)
        self.stale.setVisible(False)

        opts = QHBoxLayout()
        opts.addWidget(QLabel("Quick-launch window"))
        self.spin = QSpinBox()
        self.spin.setRange(5, 180)
        self.spin.setValue(20)
        self.spin.setSuffix(" s")
        self.spin.setToolTip("How long the sandbox has to stay up for a launch to count as working. It starts when "
                             "the sandbox itself starts, so pre-launch scans and prefix setup do not use it up.")
        opts.addWidget(self.spin)
        opts.addSpacing(16)
        self.step_by_step = QCheckBox("Ask before each step")
        self.step_by_step.setToolTip("Pause after every failed launch and show what would be relaxed next. "
                                     "Steps with a large security cost always ask.")
        opts.addWidget(self.step_by_step)
        opts.addStretch(1)
        v.addLayout(opts)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Restriction (tried in this order)", "Cost", "Now"])
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        v.addWidget(self.tree, 1)
        self.items: dict[str, QTreeWidgetItem] = {}
        self.steps_all = relax.plan(game, win.defaults, include_opt_in=True)
        for s in self.steps_all:
            it = QTreeWidgetItem([s.label, relax.RISK_TEXT[s.risk].split(":")[0], "on"])
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(COL_STEP, Qt.CheckState.Unchecked if s.opt_in else Qt.CheckState.Checked)
            it.setToolTip(COL_STEP, s.why + ("\n\nOff until you tick it: the sandbox leans on this." if s.opt_in else ""))
            it.setToolTip(COL_COST, relax.RISK_TEXT[s.risk])
            self.tree.addTopLevelItem(it)
            self.items[s.key] = it
        for c in (COL_COST, COL_STATE):
            self.tree.resizeColumnToContents(c)
        self.tree.setColumnWidth(COL_STEP, 340)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        f = self.status.font()
        f.setBold(True)
        self.status.setFont(f)
        v.addWidget(self.status)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(8)
        v.addWidget(self.bar)

        # shown only while paused on a proposal
        self.ask = QWidget()
        al = QHBoxLayout(self.ask)
        al.setContentsMargins(0, 0, 0, 0)
        self.btn_relax = QPushButton("Relax it and retry")
        self.btn_relax.clicked.connect(self._ask_relax)
        self.btn_skip = QPushButton("Skip this one")
        self.btn_skip.clicked.connect(self._ask_skip)
        self.btn_fine = QPushButton("That launch was fine, stop here")
        self.btn_fine.setToolTip("For a game whose launcher starts something else and exits by design.")
        self.btn_fine.clicked.connect(self._ask_fine)
        for b in (self.btn_relax, self.btn_skip, self.btn_fine):
            al.addWidget(b)
        al.addStretch(1)
        v.addWidget(self.ask)
        self.ask.setVisible(False)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(120)
        v.addWidget(self.log)

        row = QHBoxLayout()
        self.btn_start = QPushButton("Start")
        self.btn_start.setDefault(True)
        self.btn_start.clicked.connect(self.on_start)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_keep = QPushButton("Keep changes")
        self.btn_keep.clicked.connect(self.on_keep)
        self.btn_undo = QPushButton("Undo all")
        self.btn_undo.setToolTip("Put game.conf back exactly as it was before this session.")
        self.btn_undo.clicked.connect(self.on_undo)
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.close)
        for b in (self.btn_start, self.btn_stop, self.btn_keep, self.btn_undo):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.btn_close)
        v.addLayout(row)

        self.timer = QTimer(self)
        self.timer.setInterval(TICK_MS)
        self.timer.timeout.connect(self._tick)

        if not self.steps_all:
            self._say("Nothing to relax: every compatibility switch is already off for this game, so a crash is not "
                      "caused by a restriction this can change.")
        else:
            self._say("Ready. Untick anything you never want switched off, then Start.")
        self._check_stale()
        self._set_state(IDLE)

    # ---------------------------------------------------------------- small helpers

    def _reset_trial(self):
        self.t0 = 0.0
        self.t_up: float | None = None        # when the sandbox (firejail) first appeared
        self.t_down: float | None = None      # when it went away again
        self.seen = False                     # the launcher process has been seen in wq-ui's process table
        self.exit_code: int | None = None
        self.user_stopped = False
        self.last_log = ""

    def _say(self, text: str):
        self.status.setText(text)

    def _note(self, text: str):
        self.log.appendPlainText(text)

    def _game(self) -> core.Game | None:
        return self.win.by_name.get(self.name)

    def _set_item(self, step: relax.Step, text: str):
        it = self.items.get(step.key)
        if it is not None:
            it.setText(COL_STATE, text)

    def _ticked(self) -> list[relax.Step]:
        return [s for s in self.steps_all if self.items[s.key].checkState(COL_STEP) == Qt.CheckState.Checked]

    def _set_state(self, state: str):
        self.state = state
        idle, watch, paused, done = (state == k for k in (IDLE, WATCH, PAUSED, DONE))
        stale = self.stale.isVisible()
        self.btn_start.setEnabled(idle and bool(self.steps_all) and not stale)
        self.btn_stop.setEnabled(watch)
        self.btn_keep.setEnabled((paused or done) and bool(self.relaxed))
        self.btn_undo.setEnabled((paused or done) and bool(self.relaxed))
        self.spin.setEnabled(idle)
        self.step_by_step.setEnabled(idle)
        self.tree.setEnabled(idle)
        self.ask.setVisible(paused)
        self.bar.setVisible(watch)

    # ---------------------------------------------------------------- an unfinished earlier session

    def _check_stale(self):
        b = relax.load_backup(self.name)
        if not b:
            return
        diff = relax.describe_changes(b["snapshot"], self.conf)
        if not diff:
            relax.clear_backup(self.name)
            return
        self.stale_label.setText("An earlier session was cut short and left this game relaxed:\n  • " + "\n  • ".join(diff))
        self.stale.setVisible(True)

    def _stale_restore(self):
        b = relax.load_backup(self.name)
        if b and self._write(lambda: relax.restore(self.conf, b["snapshot"])):
            relax.clear_backup(self.name)
            self._reload()
            self.stale.setVisible(False)
            self._say("Restored the settings from before the earlier session.")
            self._set_state(self.state)

    def _stale_keep(self):
        relax.clear_backup(self.name)
        self.stale.setVisible(False)
        self._set_state(self.state)

    # ---------------------------------------------------------------- driving the trials

    def _write(self, fn) -> bool:
        try:
            fn()
            return True
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "Could not write game.conf", str(e))
            return False

    def _reload(self):
        self.win.reload_keep_selection()

    def on_start(self):
        g = self._game()
        if g is None:
            return
        if self.name in self.win.procs:
            QMessageBox.information(self, "Already running", f"{self.name} is running. Stop it first.")
            return
        if not g.exe_ready:
            QMessageBox.warning(self, "Executable not set", f"Set EXE= in {self.conf} first.")
            return
        if not self.win.resolve_pending("Apply them before relaxing, or the reload after each step would drop them."):
            return
        g = self._game()
        self.remaining = [s for s in self._ticked() if relax.is_on(g, self.win.defaults, s)]
        if not self.remaining:
            self._say("Nothing is ticked that is still on for this game.")
            return
        self.window_s = self.spin.value()
        # remember every key this dialog could change, so Undo puts game.conf back exactly
        self.snap = relax.snapshot(self.conf, [s.key for s in self.steps_all])
        if not self._write(lambda: relax.save_backup(self.name, self.conf, self.snap, [])):
            return
        self.relaxed, self.success, self.trial_no = [], False, 0
        self.log.clear()
        self._begin_trial("with the current settings")

    def _begin_trial(self, what: str):
        g = self._game()
        if g is None:
            self._end("The game is gone from the list.")
            return
        self.trial_no += 1
        self._reset_trial()
        self.t0 = time.time()
        self.bar.setRange(0, self.window_s * 10)
        self.bar.setValue(0)
        self._note(f"Trial {self.trial_no}: launching {what}.")
        self._set_state(WATCH)
        self._say(f"Trial {self.trial_no}: launching…")
        self.win.launch(g)
        if self.name not in self.win.procs and self.name not in self.win.baselining:
            # launch() refused before starting anything (it has already told the person why)
            self._finish(exited=True)
            return
        self.timer.start()

    def _launcher_finished(self, code: int, status):
        self.exit_code = code if status == QProcess.ExitStatus.NormalExit else None

    def _pgid(self, d) -> int:
        pid = int(d["proc"].processId())
        if pid <= 1:
            return 0
        try:
            return os.getpgid(pid)
        except OSError:
            return pid

    def _tick(self):
        if self.state != WATCH:
            self.timer.stop()
            return
        now = time.time()
        d = self.win.procs.get(self.name)
        if d is None:
            if self.seen:
                self._finish(exited=True)                      # the launcher has finished, post-run checks included
            elif self.name not in self.win.baselining and now - self.t0 > NOT_STARTED_GRACE_S:
                self._finish(exited=True)
            return
        if not self.seen:
            self.seen = True
            d["proc"].finished.connect(self._launcher_finished)
        up = relax.sandbox_up(self._pgid(d))
        if up and self.t_up is None:
            self.t_up = now
        if self.t_up is None:
            if now - self.t0 > START_TIMEOUT_S:
                self._note("The sandbox never started. Stopping this launch.")
                self.on_stop()
                return
            self._say(f"Trial {self.trial_no}: preparing ({now - self.t0:.0f} s): pre-launch scans and prefix setup "
                      "run before the sandbox starts.")
            return
        if up:
            el = now - self.t_up
            self.bar.setValue(min(int(el * 10), self.window_s * 10))
            self._say(f"Trial {self.trial_no}: sandbox up for {el:.0f} of {self.window_s} s…")
            if el >= self.window_s:
                self._finish(exited=False)
        elif self.t_down is None:
            self.t_down = now
            self._say(f"Trial {self.trial_no}: the sandbox ended after {self.t_down - self.t_up:.0f} s. "
                      "Waiting for the post-run checks to finish…")

    def _finish(self, exited: bool):
        self.timer.stop()
        g = self._game()
        now = time.time()
        ran = ((self.t_down or now) - self.t_up) if self.t_up else 0.0
        launch_txt, alert_txt = relax.read_trial_logs(g.path, self.t0) if g else ("", "")
        self.last_log = launch_txt
        outcome, msg = relax.classify(exited, self.exit_code, ran, self.window_s, launch_txt, alert_txt,
                                      self.user_stopped, sandbox_started=self.t_up is not None)
        self._note(f"Trial {self.trial_no}: {msg}")
        if outcome == relax.SURVIVED:
            self.success = True
            self._end(f"It launched and stayed up. {len(self.relaxed)} restriction(s) relaxed. "
                      "Keep the changes or undo them below. The game is still running.", success=True)
        elif outcome == relax.CRASHED:
            self._next_step()
        else:
            self._end(msg)

    def _next_step(self):
        g = self._game()
        self.remaining = [s for s in self.remaining if g and relax.is_on(g, self.win.defaults, s)]
        if not self.remaining:
            self._end("Every ticked restriction is relaxed and it still does not stay up, so the cause is something "
                      "else. Undo all puts the settings back. The launch log has the details.")
            return
        step, why = relax.pick_next(self.remaining, self.last_log)
        self.proposal = (step, why)
        if self.step_by_step.isChecked() or step.risk == relax.HIGH:
            self._set_item(step, "next")
            self.btn_relax.setText(f"Relax “{step.label}” and retry")
            self._say(f"Next: {step.label} ({why}). {step.why}"
                      + (f" Cost: {relax.RISK_TEXT[step.risk]}." if step.risk != relax.LOW else ""))
            self._set_state(PAUSED)
        else:
            self._relax(step, why)

    def _relax(self, step: relax.Step, why: str):
        if self.snap is None or not self._write(lambda: relax.apply_step(self.conf, step)):
            self._end("Could not change game.conf, so nothing more was relaxed.")
            return
        self.relaxed.append(step)
        self.remaining = [s for s in self.remaining if s.key != step.key]
        self._set_item(step, "relaxed")
        self._write(lambda: relax.save_backup(self.name, self.conf, self.snap, [s.key for s in self.relaxed]))
        self._reload()
        self._note(f"Relaxed “{step.label}” ({why}).")
        self._begin_trial(f"with “{step.label}” off")

    # ---------------------------------------------------------------- the paused prompt

    def _ask_relax(self):
        if self.proposal:
            step, why = self.proposal
            self.proposal = None
            self._relax(step, why)

    def _ask_skip(self):
        if self.proposal:
            step, _ = self.proposal
            self.proposal = None
            self.remaining = [s for s in self.remaining if s.key != step.key]
            self._set_item(step, "skipped")
            self._note(f"Skipped “{step.label}”.")
            self._next_step()

    def _ask_fine(self):
        self.proposal = None
        self.success = True
        self._end("Stopped here at your word that the last launch was fine.", success=True)

    # ---------------------------------------------------------------- ending

    def _end(self, text: str, success: bool = False):
        self.timer.stop()
        self.proposal = None
        self._say(text)
        self._set_state(DONE)

    def on_stop(self):
        d = self.win.procs.get(self.name)
        self.user_stopped = True
        if d is not None:
            self.win.stopping.add(self.name)
            wq_dialogs.kill_group(d["proc"])
            self.win.refresh_rows()
        # the launcher finishes its post-run checks first; _tick sees it go and _finish reports "stopped"
        self._say("Stopping… the launcher finishes its post-run checks first.")
        self.btn_stop.setEnabled(False)

    def on_keep(self):
        relax.clear_backup(self.name)
        self._note("Kept the changes: " + ", ".join(s.label for s in self.relaxed) + ".")
        self.relaxed = []
        self._say("Kept. These settings are now this game's own, visible on the Protection tab.")
        self._set_state(DONE)

    def on_undo(self):
        if self.snap is None or not self._write(lambda: relax.restore(self.conf, self.snap)):
            return
        relax.clear_backup(self.name)
        for s in self.relaxed:
            self._set_item(s, "on")
        self._note("Undid every change from this session.")
        self.relaxed, self.success = [], False
        self._reload()
        self._say("Undone. game.conf is back to how it was before this session.")
        self._set_state(DONE)

    # ---------------------------------------------------------------- closing

    def reject(self):
        self.close()

    def closeEvent(self, e):
        # no super().closeEvent(): QDialog's would call reject() again
        if self.state == WATCH:
            self.on_stop()
            self.timer.stop()
        if self.relaxed and self.snap is not None:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Question)
            box.setWindowTitle("Relaxed settings")
            box.setText(f"{len(self.relaxed)} restriction(s) are switched off for {self.name}.")
            box.setInformativeText("Keep them, or put game.conf back as it was?")
            b_keep = box.addButton("Keep", QMessageBox.ButtonRole.AcceptRole)
            b_undo = box.addButton("Undo", QMessageBox.ButtonRole.DestructiveRole)
            b_cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
            box.setEscapeButton(b_cancel)
            box.exec()
            c = box.clickedButton()
            if c is b_cancel or c is None:
                e.ignore()
                return
            if c is b_undo:
                self.on_undo()
                if self.relaxed:             # the restore failed: stay open rather than lose the way back
                    e.ignore()
                    return
            else:
                relax.clear_backup(self.name)
        self.timer.stop()
        if getattr(self.win, "_relax_dlg", None) is self:
            self.win._relax_dlg = None
        e.accept()
