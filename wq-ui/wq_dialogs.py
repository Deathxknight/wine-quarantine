"""Dialogs for wq-ui: add a game, pick /dev nodes to hide, pick the exe.
The checks behind them (name rules, exe discovery, /dev) are in wq_core."""
from __future__ import annotations

import os
import shutil
import signal
from pathlib import Path

from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit, QProgressBar,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

import wq_core as core

ARCHIVE_TOOLS = {".zip": "unzip", ".rar": "unrar", ".7z": "7z", ".tar": "tar", ".gz": "tar", ".tgz": "tar",
                 ".xz": "tar", ".txz": "tar", ".bz2": "tar", ".tbz2": "tar"}


def _note(text: str = "", status: str | None = None, hint: bool = False) -> QLabel:
    lab = QLabel(text)
    lab.setWordWrap(True)
    if hint:
        lab.setObjectName("hint")
    if status:
        lab.setProperty("status", status)
    return lab


def _repolish(w: QWidget):
    w.style().unpolish(w)
    w.style().polish(w)


def start_in_own_group(p: QProcess, program: str, args: list[str]):
    """Start `program` in its own session so we can signal the whole tree."""
    if hasattr(p, "setChildProcessModifier"):
        p.setChildProcessModifier(lambda: os.setsid())
        p.start(program, args)
    else:                                   # older Qt, let setsid(1) do it
        p.start("setsid", [program, *args])


def kill_group(p: QProcess, sig=signal.SIGTERM):
    pid = int(p.processId())
    if pid <= 0:
        return
    try:
        os.killpg(pid, sig)
    except OSError:
        p.terminate()


# ---------------------------------------------------------------------------
# add a game
# ---------------------------------------------------------------------------
class NewGameDialog(QDialog):
    """Runs new-quarantine.sh or new-native.sh. With several candidate files the
    script would ask which one, so stdin is closed (it takes the first) and the
    main window offers the exe picker afterwards."""

    def __init__(self, qroot: Path, existing: set[str], parent=None):
        super().__init__(parent)
        self.qroot = Path(qroot)
        self.existing = set(existing)
        self.created_name: str | None = None
        self.proc: QProcess | None = None
        self._cancelled = False
        self.setWindowTitle("Add a quarantined game")
        self.setMinimumSize(660, 520)

        v = QVBoxLayout(self)
        form = QFormLayout()

        self.kind = QComboBox()
        self.kind.addItem("Windows game (Wine / Proton)", "wine")
        self.kind.addItem("Native Linux game (shell script or binary)", "native")
        self.kind.currentIndexChanged.connect(self._validate)
        form.addRow("Type", self.kind)

        self.name = QLineEdit()
        self.name.setPlaceholderText("e.g. My Game")
        self.name.textChanged.connect(self._validate)
        form.addRow("Name", self.name)

        src_row = QWidget()
        h = QHBoxLayout(src_row)
        h.setContentsMargins(0, 0, 0, 0)
        self.source = QLineEdit()
        self.source.setPlaceholderText("Optional - a folder, an archive (.zip .rar .7z .tar.gz …), or a single file")
        self.source.textChanged.connect(self._validate)
        self.b_file = QPushButton("File…")
        self.b_dir = QPushButton("Folder…")
        self.b_file.clicked.connect(self._pick_file)
        self.b_dir.clicked.connect(self._pick_dir)
        h.addWidget(self.source, 1)
        h.addWidget(self.b_file)
        h.addWidget(self.b_dir)
        form.addRow("Source", src_row)
        v.addLayout(form)

        self.note = _note("", "warn")
        v.addWidget(self.note)
        v.addWidget(_note(
            "The source is copied or unpacked into <name>/game/ inside your wine-quarantine folder; the original is "
            "left alone. With no source you get an empty quarantine to drop files into yourself. If several .exe "
            "files are found you can pick the right one afterwards.", hint=True))

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(6)
        self.progress.hide()
        v.addWidget(self.progress)

        self.log = QPlainTextEdit()
        self.log.setObjectName("console")
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(5000)
        self.log.setPlaceholderText("new-quarantine.sh output appears here")
        v.addWidget(self.log, 1)

        bar = QHBoxLayout()
        bar.addStretch(1)
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self._close_clicked)
        self.btn_create = QPushButton("Create")
        self.btn_create.setProperty("accent", True)
        self.btn_create.setDefault(True)
        self.btn_create.clicked.connect(self._create)
        bar.addWidget(self.btn_close)
        bar.addWidget(self.btn_create)
        v.addLayout(bar)

        self._validate()

    # -- input
    def _pick_file(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Game executable or archive", str(Path.home()),
            "Games and archives (*.exe *.sh *.AppImage *.zip *.rar *.7z *.tar *.tar.gz *.tgz *.tar.xz *.tar.bz2);;"
            "All files (*)")
        if f:
            self._set_source(f)

    def _pick_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Game folder", str(Path.home()))
        if d:
            self._set_source(d)

    def _set_source(self, path: str):
        self.source.setText(path)
        if not self.name.text().strip():
            stem = Path(path).stem if Path(path).is_file() else Path(path).name
            self.name.setText(stem.replace("_", " ").strip())

    def _validate(self) -> bool:
        err = core.validate_game_name(self.name.text(), self.existing, self.qroot)
        src = self.source.text().strip()
        if not err and src:
            sp = Path(src).expanduser()
            if not sp.exists():
                err = f"Source not found: {src}"
            elif sp.is_file():
                tool = ARCHIVE_TOOLS.get(sp.suffix.lower())
                if tool and not shutil.which(tool):
                    err = f"{sp.suffix} archives need “{tool}”, which is not installed."
        if self.name.text() == "":
            err = ""               # don't nag before the first keystroke
        self.note.setText(err)
        self.note.setVisible(bool(err))
        ok = not err and bool(self.name.text().strip())
        self.btn_create.setEnabled(ok and self.proc is None)
        return ok

    # -- run
    def _set_busy(self, busy: bool):
        for w in (self.kind, self.name, self.source, self.b_file, self.b_dir):
            w.setEnabled(not busy)
        self.progress.setVisible(busy)
        self.btn_create.setEnabled(not busy and self._validate())
        self.btn_close.setText("Cancel" if busy else "Close")

    def _create(self):
        if not self._validate():
            return
        script = (self.qroot / "wq-ui" / "new-native.sh" if self.kind.currentData() == "native"
                  else self.qroot / "new-quarantine.sh")
        if not script.is_file():
            QMessageBox.critical(self, "Missing script", f"{script} not found.")
            return
        name = self.name.text()
        args = [name]
        src = self.source.text().strip()
        if src:
            args.append(str(Path(src).expanduser()))
        self.log.clear()
        self.log.appendPlainText(f"$ {script.name} {' '.join(repr(a) for a in args)}")
        p = QProcess(self)
        p.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        p.setWorkingDirectory(str(self.qroot))
        p.setStandardInputFile(os.devnull)
        p.readyReadStandardOutput.connect(self._read)
        p.finished.connect(lambda code, st, n=name: self._finished(n, code, st))
        p.errorOccurred.connect(self._error)
        self.proc = p
        self._cancelled = False
        self._set_busy(True)
        start_in_own_group(p, str(script), args)

    def _read(self):
        if self.proc is None:
            return
        text = bytes(self.proc.readAllStandardOutput()).decode("utf-8", "replace")
        for line in core.strip_ansi(text).replace("\r", "\n").split("\n"):
            if line.strip():
                self.log.appendPlainText(line)

    def _error(self, err):
        if err == QProcess.ProcessError.FailedToStart:
            self.log.appendPlainText("could not start new-quarantine.sh (is it executable?)")
            self.proc = None
            self._set_busy(False)

    def _finished(self, name: str, code: int, status):
        self._read()
        self.proc = None
        if getattr(self, "_cancelled", False):
            self.log.appendPlainText("\nCancelled. new-quarantine.sh removes the partly created folder itself.")
            self._set_busy(False)
            return
        if status == QProcess.ExitStatus.NormalExit and code == 0:
            self.created_name = name
            self.log.appendPlainText(f"\n✓ Created “{name}”.")
            self.btn_create.hide()
            self.btn_close.setText("Done")
            for w in (self.kind, self.name, self.source, self.b_file, self.b_dir):
                w.setEnabled(False)
            self.progress.hide()
        else:
            self.log.appendPlainText(f"\n✗ Setup failed (exit code {code}). Nothing was kept.")
            self._set_busy(False)

    def _close_clicked(self):
        if self.proc is not None:
            self._cancelled = True
            kill_group(self.proc)
            return
        if self.created_name:
            self.accept()
        else:
            self.reject()

    def reject(self):                     # Esc / window close button
        if self.proc is not None:
            self._cancelled = True
            kill_group(self.proc)
            self.proc.waitForFinished(3000)
        super().reject()


# ---------------------------------------------------------------------------
# /dev picker
# ---------------------------------------------------------------------------
class DevicePickerDialog(QDialog):
    """Pick /dev nodes to hide. Essential ones aren't listed, risky ones get a note."""

    def __init__(self, already: set[str], parent=None):
        super().__init__(parent)
        self.already = set(already)
        self.setWindowTitle("Block /dev devices")
        self.setMinimumSize(640, 480)
        v = QVBoxLayout(self)
        v.addWidget(_note(
            "Hidden devices disappear from /dev inside the sandbox (firejail --blacklist). Everything else under /dev "
            "stays visible, so this is for hardening beyond the Block audio / webcam / U2F… boxes. "
            "Take care with GPU and input nodes: the game stops seeing them.", hint=True))

        top = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter, e.g. input, sd, hidraw…")
        self.search.textChanged.connect(self._filter)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._fill)
        top.addWidget(self.search, 1)
        top.addWidget(refresh)
        v.addLayout(top)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Device", "Kind", "Note"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.itemDoubleClicked.connect(lambda *_: self.accept())
        v.addWidget(self.table, 1)

        row = QHBoxLayout()
        row.addWidget(QLabel("Or a path"))
        self.custom = QLineEdit()
        self.custom.setPlaceholderText("/dev/…")
        row.addWidget(self.custom, 1)
        v.addLayout(row)

        bar = QHBoxLayout()
        bar.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        self.ok = QPushButton("Block selected")
        self.ok.setProperty("accent", True)
        self.ok.clicked.connect(self.accept)
        bar.addWidget(cancel)
        bar.addWidget(self.ok)
        v.addLayout(bar)
        self._fill()

    def _fill(self):
        self.table.setRowCount(0)
        for path, kind, note in core.list_devices():
            r = self.table.rowCount()
            self.table.insertRow(r)
            blocked = path in self.already
            cells = [path, kind, "already blocked" if blocked else note]
            for c, text in enumerate(cells):
                it = QTableWidgetItem(text)
                if blocked:
                    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsSelectable & ~Qt.ItemFlag.ItemIsEnabled)
                self.table.setItem(r, c, it)
        self._filter()

    def _filter(self):
        q = self.search.text().strip().lower()
        for r in range(self.table.rowCount()):
            hay = " ".join(self.table.item(r, c).text().lower() for c in range(3))
            self.table.setRowHidden(r, bool(q) and q not in hay)

    def chosen(self) -> list[str]:
        out: list[str] = []
        for r in sorted({i.row() for i in self.table.selectedItems()}):
            out.append(self.table.item(r, 0).text())
        c = self.custom.text().strip()
        if c and c not in out:
            out.append(c)
        return out


# ---------------------------------------------------------------------------
# executable picker
# ---------------------------------------------------------------------------
class ExePickerDialog(QDialog):
    def __init__(self, gamedir: Path, current: str = "", parent=None, note: str = "", runner: str = "wine"):
        super().__init__(parent)
        self.gamedir = Path(gamedir)
        self.runner = runner
        self.setWindowTitle(f"Executable for {self.gamedir.name}")
        self.setMinimumSize(520, 380)
        v = QVBoxLayout(self)
        v.addWidget(_note(note or "Choose the file that starts the game. Paths are relative to the game/ folder.",
                          hint=True))
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(lambda *_: self.accept())
        v.addWidget(self.list, 1)
        what = "start script or binary" if runner == "native" else ".exe"
        self.empty = _note(f"No {what} found in game/. Copy the game files into that folder, then use "
                           "“Other file…”.", "warn")
        v.addWidget(self.empty)

        bar = QHBoxLayout()
        other = QPushButton("Other file…")
        other.clicked.connect(self._other)
        bar.addWidget(other)
        bar.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        self.ok = QPushButton("Use this")
        self.ok.setProperty("accent", True)
        self.ok.clicked.connect(self.accept)
        bar.addWidget(cancel)
        bar.addWidget(self.ok)
        v.addLayout(bar)

        exes = core.find_exes(self.gamedir, runner)
        if current and current not in ("CHANGE_ME.exe", "CHANGE_ME.sh") and current not in exes:
            exes.insert(0, current)
        for e in exes:
            self.list.addItem(QListWidgetItem(e))
        for i in range(self.list.count()):
            if self.list.item(i).text() == current:
                self.list.setCurrentRow(i)
                break
        else:
            if self.list.count():
                self.list.setCurrentRow(0)
        self._sync()

    def _sync(self):
        self.empty.setVisible(self.list.count() == 0)
        self.ok.setEnabled(self.list.count() > 0)
        _repolish(self.empty)

    def _other(self):
        base = self.gamedir / "game"
        f, _ = QFileDialog.getOpenFileName(self, "Executable inside game/", str(base),
                                           "Start scripts and binaries (*.sh *.AppImage);;All files (*)"
                                           if self.runner == "native" else
                                           "Windows programs (*.exe);;All files (*)")
        if not f:
            return
        real_base = os.path.realpath(base)
        real_f = os.path.realpath(f)
        if not real_f.startswith(real_base + os.sep):
            QMessageBox.warning(self, "Outside game/",
                                "The executable has to be inside this game's game/ folder.")
            return
        rel = os.path.relpath(real_f, real_base)
        if not core.valid_exe_rel(rel):
            QMessageBox.warning(self, "Unsafe path", "That path is not allowed.")
            return
        for i in range(self.list.count()):
            if self.list.item(i).text() == rel:
                self.list.setCurrentRow(i)
                return
        self.list.insertItem(0, QListWidgetItem(rel))
        self.list.setCurrentRow(0)
        self._sync()

    def chosen(self) -> str | None:
        it = self.list.currentItem()
        return it.text() if it else None
