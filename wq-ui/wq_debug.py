#!/usr/bin/env python3
"""wq_debug - Debug dialog for wq-ui.

Checks dependencies and paths (the way config.sh resolves them), and builds a
redacted, copy-pasteable report for GitHub issues.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QPlainTextEdit, QPushButton, QVBoxLayout,
)

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
ICON = {OK: "✓", WARN: "⚠", FAIL: "✗", INFO: "•"}
COLOR = {OK: "#3fb950", WARN: "#d29922", FAIL: "#f85149", INFO: None}
OLD_FIREJAIL = (0, 9, 80)   # <= this: --private hides whitelisted paths under $HOME

RESOLVE = r'''
cd "$1" || exit 1
source ./config.sh >/dev/null 2>&1
for v in QROOT STEAM_ROOT LUTRIS_UMU UMU_DATA UMU_RO_PATH PROTON_PREFERRED ALERT_TERMINAL; do
  printf '%s=%s\n' "$v" "${!v}"
done
for p in "${QUARANTINE_RO_PATHS[@]}"; do printf 'RO=%s\n' "$p"; done
for p in "${PROTON_SEARCH_DIRS[@]}"; do printf 'SEARCH=%s\n' "$p"; done
printf 'PROTON_FOUND=%s\n' "$(find_proton "${2:-}" 2>/dev/null || true)"
printf 'TERMINAL=%s\n' "$(detect_terminal 2>/dev/null || true)"
'''


def sh(cmd: list[str], timeout: int = 6) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:  # noqa: BLE001
        return f"<{type(e).__name__}: {e}>"


def resolve(qroot: Path, gamedir: Path | None) -> dict:
    R: dict = {"RO": [], "SEARCH": [], "_error": ""}
    try:
        r = subprocess.run(["bash", "-c", RESOLVE, "bash", str(qroot), str(gamedir or "")],
                           capture_output=True, text=True, timeout=15)
    except Exception as e:  # noqa: BLE001
        R["_error"] = f"{type(e).__name__}: {e}"
        return R
    for line in r.stdout.splitlines():
        k, _, v = line.partition("=")
        if k in ("RO", "SEARCH"):
            R[k].append(v)
        else:
            R[k] = v
    if r.returncode != 0:
        R["_error"] = (r.stderr or "bash exited non-zero").strip()
    return R


def real(p: str | Path) -> str:
    return os.path.realpath(str(p))


def under(p: str | Path, base: str | Path) -> bool:
    a, b = real(p), real(base)
    return a == b or a.startswith(b.rstrip("/") + os.sep)


def parse_ver(text: str) -> tuple[int, ...] | None:
    m = re.search(r"(\d+(?:\.\d+)+)", text)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def tail(path: Path, n: int = 50) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 65536))
            data = f.read().decode("utf-8", "replace")
        lines = data.splitlines()[-n:]
        return "\n".join(l if len(l) <= 300 else l[:300] + f" …[+{len(l) - 300} chars]" for l in lines)
    except OSError as e:
        return f"<cannot read {path.name}: {e}>"


def list_games(qroot: Path) -> list[str]:
    try:
        return sorted(d.name for d in qroot.iterdir() if (d / "game").is_dir())
    except OSError:
        return []


def cut(l: str, n: int = 300) -> str:
    return l if len(l) <= n else l[:n] + f" …[+{len(l) - n} chars]"


def alert_tail(path: Path, n: int = 50) -> str:
    """first/last line, plus the last n lines that are not 'New process' noise"""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as e:
        return f"<cannot read {path.name}: {e}>"
    keep = [l for l in lines if "New process:" not in l]
    out = []
    if lines:
        out.append("first: " + cut(lines[0]))
    out.append(f"({len(lines)} lines, {len(lines) - len(keep)} 'New process' lines hidden)")
    out += [cut(l) for l in keep[-n:]]
    if lines:
        out.append("last: " + cut(lines[-1]))
    return "\n".join(out)


def newest_launch_log(qroot: Path, game: str | None) -> Path | None:
    if not game:
        return None
    logs = list((qroot / game / "logs").glob("launch-*.log"))
    return max(logs, key=lambda p: p.stat().st_mtime, default=None)


def newest_log(qroot: Path, game: str | None) -> Path | None:
    dirs = [qroot / game] if game else [qroot / g for g in list_games(qroot)]
    logs: list[Path] = []
    for d in dirs:
        logs += list((d / "logs").glob("alerts-*.log"))
    return max(logs, key=lambda p: p.stat().st_mtime, default=None)


def collect(qroot: Path, game: str | None) -> dict:
    home = real(Path.home())
    gamedir = (qroot / game) if game else None
    R = resolve(qroot, gamedir)
    checks: list[tuple[str, str, str, str]] = []

    def add(status: str, label: str, detail: str = "", hint: str = ""):
        checks.append((status, label, detail, hint))

    # ---- versions
    fj_path = shutil.which("firejail")
    fj_txt = sh(["firejail", "--version"]).splitlines()[0] if fj_path else ""
    fjv = parse_ver(fj_txt) if fj_txt else None
    old_fj = bool(fjv and fjv <= OLD_FIREJAIL)
    umu = R.get("LUTRIS_UMU", "")
    umu_ver = ""
    if umu and os.access(umu, os.X_OK):
        out = sh([umu, "--version"], timeout=8).splitlines()
        umu_ver = out[0].replace("INFO: ", "") if out else ""

    # ---- dependencies
    if fj_path:
        add(OK, "firejail", fj_txt)
        if old_fj:
            _any_home = any(x and os.path.exists(x) and under(x, home)
                            for x in (R.get("PROTON_FOUND", ""), R.get("STEAM_ROOT", ""), R.get("LUTRIS_UMU", "")))
            add(WARN if _any_home else INFO, "firejail version quirk",
                f"{fj_txt}: --private hides whitelisted paths under $HOME"
                + ("" if _any_home else " (not affecting you: nothing important is under $HOME)"),
                "Keep Proton, Steam and umu outside your home folder (e.g. /opt/proton or /mnt/...).")
    else:
        add(FAIL, "firejail", "not found in PATH", "Install it with your package manager.")
    for b, hint in (("inotifywait", "package: inotify-tools"), ("python3", "")):
        p = shutil.which(b)
        add(OK if p else FAIL, b, p or "not found in PATH", "" if p else hint)

    if umu and os.access(umu, os.X_OK):
        add(OK, "umu-run", f"{umu}  {umu_ver}".strip())
    elif umu:
        add(FAIL, "umu-run", f"{umu} is not executable", "Check LUTRIS_UMU in config.local.sh.")
    else:
        add(FAIL, "umu-run", "not found", "Install umu-launcher, or set LUTRIS_UMU in config.local.sh.")

    proton = R.get("PROTON_FOUND", "")
    if proton and (Path(proton) / "toolmanifest.vdf").is_file():
        add(OK, "Proton build", proton)
    else:
        searched = ", ".join(R["SEARCH"]) or "(nothing)"
        add(FAIL, "Proton build", f"none with toolmanifest.vdf found. Searched: {searched}",
            "Install GE-Proton, or set PROTON_PREFERRED in config.local.sh.")

    for b in ("unzip", "unrar", "Xephyr"):
        p = shutil.which(b)
        add(OK if p else WARN, f"{b} (optional)", p or "not found")
    sz = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    add(OK if sz else WARN, "7z (optional)", sz or "not found")

    # ClamAV scanning (wq-scan.sh --check reports the binary and database state)
    try:
        chk = subprocess.run([str(qroot / "wq-scan.sh"), "--check"], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:                                  # noqa: BLE001
        chk = f"wq-scan.sh --check failed: {e}"
    clam_ok = bool(chk) and "not found" not in chk.splitlines()[0] and "database: none" not in chk and "failed" not in chk
    add(OK if clam_ok else WARN, "ClamAV scan (optional)", chk.replace("\n", "; ") or "no output",
        "" if clam_ok else "Install clamav and run: sudo freshclam")

    term = R.get("TERMINAL", "")
    add(OK if term else WARN, "terminal for alert window", term or "none detected",
        "" if term else "Set ALERT_TERMINAL in config.local.sh.")

    # ---- paths
    if under(qroot, home):
        add(FAIL, "quarantine folder outside $HOME", f"{real(qroot)} is inside $HOME",
            "Move it out of home, e.g.\n  sudo mkdir /mnt/wine-quarantine && sudo chown $USER /mnt/wine-quarantine")
    else:
        add(OK, "quarantine folder outside $HOME", real(qroot))

    sev = FAIL if old_fj else WARN
    ro = [r for r in R["RO"] if r]
    ro_real = [real(r) for r in ro]

    def covered(p: str) -> bool:
        rp = real(p)
        return rp.startswith(("/usr/", "/bin/", "/lib/", "/lib64/", "/sbin/")) or \
            any(rp == r or rp.startswith(r + os.sep) for r in ro_real)

    targets = [("Proton", proton), ("Steam root", R.get("STEAM_ROOT", "")),
               ("umu-run", umu)]
    for name, p in targets:
        if not p or not os.path.exists(p):
            continue
        if under(p, home):
            hint = ""
            if name == "Proton":
                base = Path(real(p)).name
                hint = (f"sudo mkdir -p /opt/proton\n  sudo cp -a \"{p}\" /opt/proton/\n"
                        f"  # then in config.local.sh:\n  PROTON_PREFERRED=/opt/proton/{base}\n"
                        "  QUARANTINE_EXTRA_RO_PATHS=(\"/opt/proton\")")
            add(sev, f"{name} outside $HOME", f"{real(p)} is inside $HOME; firejail --private may hide it", hint)
        elif not covered(p):
            add(WARN, f"{name} visible in sandbox", f"{real(p)} is not under any QUARANTINE_RO_PATHS entry",
                "Add its folder to QUARANTINE_RO_PATHS in config.local.sh.")
        else:
            add(OK, f"{name} outside $HOME", real(p))

    for r in ro:
        add(OK if os.path.exists(r) else WARN, "QUARANTINE_RO_PATHS entry",
            r if os.path.exists(r) else f"{r} does not exist")

    pp = R.get("PROTON_PREFERRED", "")
    if pp:
        ok = (Path(pp) / "toolmanifest.vdf").is_file()
        add(OK if ok else FAIL, "PROTON_PREFERRED", pp if ok else f"{pp}: toolmanifest.vdf not found")
    else:
        add(INFO, "PROTON_PREFERRED", "not set (first Proton in the search dirs is used)")

    add(INFO, "config.local.sh", "present" if (qroot / "config.local.sh").is_file() else "absent")

    hf, vs = qroot / "verify-sandbox.sha256", qroot / "verify-sandbox.sh"
    if vs.is_file() and hf.is_file():
        exp = hf.read_text().split()[0] if hf.read_text().split() else ""
        act = hashlib.sha256(vs.read_bytes()).hexdigest()
        if exp == act:
            add(OK, "verify-sandbox.sh hash", "matches verify-sandbox.sha256")
        else:
            add(FAIL, "verify-sandbox.sh hash", "does not match verify-sandbox.sha256",
                f"If you edited it on purpose: {vs} --update-hash")
    else:
        add(FAIL, "verify-sandbox.sh / .sha256", "missing", "Re-clone or restore both files.")

    lc = qroot / "_launch-core.sh"
    if lc.is_file():
        patched = "wq-ui integration" in lc.read_text(errors="replace")
        add(OK if patched else WARN, "wq-ui integration applied",
            "_launch-core.sh is patched" if patched else "_launch-core.sh is not patched",
            "" if patched else "Run: python3 wq-ui/integrate.py")

    if (Path.home() / ".Xauthority").exists():
        add(INFO, "~/.Xauthority on host", "exists; verify-sandbox expects it NOT to be visible inside")

    return {"R": R, "checks": checks, "fj": fj_txt or "not installed", "umu_ver": umu_ver,
            "game": game, "home": home}


def redact(text: str) -> str:
    home = real(Path.home())
    text = text.replace(home, "$HOME").replace(str(Path.home()), "$HOME")
    user = os.environ.get("USER") or Path.home().name
    if len(user) >= 3:
        text = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(user)}(?![A-Za-z0-9_])", "$USER", text)
    return text


def git_state(qroot: Path) -> str:
    try:
        r = subprocess.run(["git", "-C", str(qroot), "status", "--short", "-uno"],
                           capture_output=True, text=True, timeout=5)
    except Exception:  # noqa: BLE001
        return "git: unavailable"
    if r.returncode != 0:
        return "git: not a checkout"
    out = r.stdout.strip()
    return "git: tracked files unmodified" if not out else "git: modified tracked files:\n" + out


def build_report(qroot: Path, data: dict, include_game: bool) -> str:
    R, L = data["R"], []
    L.append("## wine-quarantine debug report")
    L.append(f"generated: {datetime.now():%Y-%m-%d %H:%M}")
    try:
        c = subprocess.run(["git", "-C", str(qroot), "log", "-1", "--format=%h %ad %s", "--date=short"],
                           capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:  # noqa: BLE001
        c = ""
    L.append(f"repo commit: {c or 'unknown (not a git checkout?)'}")
    L.append("")
    L.append("### System")
    osr = {}
    try:
        for ln in Path("/etc/os-release").read_text().splitlines():
            k, _, v = ln.partition("=")
            osr[k] = v.strip('"')
    except OSError:
        pass
    L.append(f"distro: {osr.get('PRETTY_NAME', platform.platform())}")
    L.append(f"kernel: {platform.release()}")
    L.append(f"python: {platform.python_version()}")
    try:
        import PySide6
        L.append(f"PySide6: {PySide6.__version__}")
    except Exception:  # noqa: BLE001
        pass
    L.append(f"firejail: {data['fj']}")
    L.append(f"umu: {data['umu_ver'] or 'unknown'}")
    L.append(f"session: {os.environ.get('XDG_SESSION_TYPE', '?')}  "
             f"DISPLAY={os.environ.get('DISPLAY', '')}  WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY', '')}")
    L.append("")
    L.append("### Checks")
    for status, label, detail, hint in data["checks"]:
        L.append(f"[{ICON[status]}] {label}" + (f": {detail}" if detail else ""))
        if hint and status in (WARN, FAIL):
            L.append("      fix: " + hint.replace("\n", "\n      "))
    L.append("")
    L.append("### Resolved by config.sh")
    if R.get("_error"):
        L.append(f"(resolver problem: {R['_error']})")
    for k in ("QROOT", "STEAM_ROOT", "LUTRIS_UMU", "UMU_DATA", "UMU_RO_PATH", "PROTON_PREFERRED",
              "PROTON_FOUND", "ALERT_TERMINAL", "TERMINAL"):
        L.append(f"{k}={R.get(k, '')}")
    L.append("PROTON_SEARCH_DIRS=" + " ".join(R["SEARCH"]))
    L.append("QUARANTINE_RO_PATHS=" + " ".join(R["RO"]))
    L.append("")
    L.append("### config.sh")
    p = qroot / "config.sh"
    L.append(("sha256 " + hashlib.sha256(p.read_bytes()).hexdigest()[:12]) if p.is_file() else "missing")
    L.append(git_state(qroot))
    L.append("")
    L.append("### config.local.sh")
    p = qroot / "config.local.sh"
    L.append(p.read_text().rstrip() if p.is_file() else "(absent)")
    if include_game and data["game"]:
        g = qroot / data["game"]
        L.append("")
        L.append(f"### game.conf ({data['game']})")
        gc = g / "game.conf"
        L.append(gc.read_text().rstrip() if gc.is_file() else "(absent)")
        lg = newest_log(qroot, data["game"])
        L.append("")
        L.append(f"### {lg.name if lg else 'alert log'} (process noise hidden)")
        L.append(alert_tail(lg) if lg else "(no logs)")
        if lg:
            pat = re.compile(r"\[(WARN|WARNING|ALERT|ERROR|BLOCK\w*)\]|FAIL|FATAL|denied|not found|Traceback", re.I)
            try:
                bad = [l for l in lg.read_text(errors="replace").splitlines() if pat.search(l)]
            except OSError:
                bad = []
            L.append("")
            L.append(f"### problem lines in {lg.name} (last 30)")
            L.append("\n".join(l if len(l) <= 300 else l[:300] + " …" for l in bad[-30:]) or "(none)")
        ll = newest_launch_log(qroot, data["game"])
        L.append("")
        if ll:
            L.append(f"### last 60 lines of {ll.name} (launcher output: sandbox verify, umu, wine)")
            L.append(re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", tail(ll, 60)))
        else:
            L.append("### launcher output")
            L.append("(no launch-*.log yet: launch the game once with the updated _launch-core.sh)")
    return redact("\n".join(L))


class DebugDialog(QDialog):
    def __init__(self, qroot: Path, parent=None):
        super().__init__(parent)
        self.qroot = Path(qroot)
        self.setWindowTitle("Debug")
        self.resize(780, 740)
        v = QVBoxLayout(self)

        v.addWidget(QLabel("<b>Dependencies and paths</b>"))
        self.list = QListWidget()
        v.addWidget(self.list, 3)

        row = QHBoxLayout()
        self.inc = QCheckBox("Include a game's game.conf and latest log "
                             "(may contain game names / paths)")
        self.game = QComboBox()
        self.game.addItems(list_games(self.qroot))
        self.game.setEnabled(False)
        row.addWidget(self.inc)
        row.addWidget(self.game, 1)
        v.addLayout(row)

        v.addWidget(QLabel("<b>Report</b> — paste this into a GitHub issue "
                           "(your username and home path are replaced with $USER / $HOME)"))
        self.report = QPlainTextEdit()
        self.report.setReadOnly(True)
        self.report.setFont(QFont("monospace"))
        self.report.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        v.addWidget(self.report, 4)

        btns = QHBoxLayout()
        btns.addStretch(1)
        self.b_refresh = QPushButton("Refresh")
        self.b_copy = QPushButton("Copy report")
        b_close = QPushButton("Close")
        for b in (self.b_refresh, self.b_copy, b_close):
            btns.addWidget(b)
        v.addLayout(btns)

        self.b_refresh.clicked.connect(self.refresh)
        self.b_copy.clicked.connect(self.copy)
        b_close.clicked.connect(self.accept)
        self.inc.toggled.connect(lambda on: (self.game.setEnabled(on), self.refresh()))
        self.game.currentIndexChanged.connect(lambda *_: self.refresh())
        self.refresh()

    def refresh(self):
        inc = self.inc.isChecked() and self.game.count() > 0
        data = collect(self.qroot, self.game.currentText() if inc else None)
        self.list.clear()
        for status, label, detail, hint in data["checks"]:
            text = f"{ICON[status]}  {label}" + (f" — {detail}" if detail else "")
            if hint and status in (WARN, FAIL):
                text += "\n      fix: " + hint.replace("\n", "\n      ")
            it = QListWidgetItem(redact(text))
            if COLOR[status]:
                it.setForeground(QBrush(QColor(COLOR[status])))
            self.list.addItem(it)
        self.report.setPlainText(build_report(self.qroot, data, inc))

    def copy(self):
        text = "```\n" + self.report.toPlainText() + "\n```"
        QGuiApplication.clipboard().setText(text)
        self.b_copy.setText("Copied ✓")
        QTimer.singleShot(1500, lambda: self.b_copy.setText("Copy report"))
