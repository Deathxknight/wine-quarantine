"""Desktop notifications for wq-ui. Qt-free, like wq_core.

Two jobs:

  Notifier     sends a notification with notify-send (no shell, arguments as a list,
               text stripped of control characters and cut short). Does nothing if
               notify-send is not installed.
  AlertWatch   watches the monitor's alerts-*.log of games that are running (and for a
               while after they exit, because the monitor still scans then) and says
               when new [ALERT] / [WARN] findings show up. Findings that were already
               in the log when the run started are never reported.

The rules for what is worth a notification live here so test_notify.py can check them
without a desktop.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import wq_core as core

APP = "wine-quarantine"
MIN_GAP = 10.0            # seconds between live notifications for one game; findings are batched
POST_EXIT_WATCH = 300.0   # keep watching this long after the game exits (file diffs, ClamAV)
TAIL = 1 << 20            # read at most the last 1 MiB of a log

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_STAMP = re.compile(r"^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\]\s*")
_TAG = re.compile(r"^\[(ALERT|WARN|INFO|LEAK)\]\s*")


def clean(text: str, limit: int = 160) -> str:
    """One line, no control characters, at most `limit` characters."""
    t = " ".join(_CTRL.sub(" ", text).split())
    return t if len(t) <= limit else t[:limit - 1].rstrip() + "…"


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def notify_args(title: str, body: str, urgency: str = "normal") -> list[str]:
    """The notify-send command line. "--" keeps a title that starts with "-" from being an option."""
    urgency = urgency if urgency in ("low", "normal", "critical") else "normal"
    icon = {"critical": "dialog-error", "normal": "dialog-warning"}.get(urgency, "dialog-information")
    ms = {"critical": 20000, "normal": 10000}.get(urgency, 6000)
    return ["notify-send", "-a", APP, "-u", urgency, "-i", icon, "-t", str(ms), "--",
            clean(title, 80), clean(body, 240)]


class Notifier:
    def __init__(self):
        self.exe = shutil.which("notify-send")

    @property
    def available(self) -> bool:
        return self.exe is not None

    def send(self, title: str, body: str, urgency: str = "normal") -> bool:
        if not self.exe:
            return False
        args = notify_args(title, body, urgency)
        args[0] = self.exe
        try:
            p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            return False
        threading.Thread(target=p.wait, daemon=True).start()      # reap it, no zombie
        return True


# ---- what the log says ------------------------------------------------------------------------
def latest_alert_log(game_path: Path | str) -> Path | None:
    logs = Path(game_path) / "logs"
    try:
        found = sorted(logs.glob("alerts-*.log"))
    except OSError:
        return None
    return found[-1] if found else None


def read_tail(path: Path) -> str:
    try:
        with path.open("rb") as f:
            size = path.stat().st_size
            f.seek(max(0, size - TAIL))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def last_finding(text: str) -> str:
    """The most recent real alert line (else warning) as plain text, without timestamp or tag."""
    alert = warn = ""
    for ln in text.splitlines():
        if "[ALERT]" in ln and not core._ALERT_META.search(ln):
            alert = ln
        elif "[WARN]" in ln:
            warn = ln
    ln = alert or warn
    return clean(_TAG.sub("", _STAMP.sub("", ln)), 200) if ln else ""


class AlertWatch:
    """Per-game record of what has already been reported."""

    def __init__(self):
        self.state: dict[str, dict] = {}

    def watching(self) -> list[str]:
        return list(self.state)

    def start(self, name: str, game_path) -> None:
        """Call when a run starts: whatever is in the newest log now is old news."""
        self.state[name] = {"log": None, "alert": 0, "warn": 0, "sent": 0.0,
                            "new_a": 0, "new_w": 0, "until": None}
        self._baseline(name, game_path)

    def _baseline(self, name: str, game_path) -> None:
        st = self.state[name]
        log = latest_alert_log(game_path)
        st["log"] = log.name if log else None
        st["alert"], st["warn"] = core.count_alerts(read_tail(log)) if log else (0, 0)
        st["new_a"] = st["new_w"] = 0

    def exited(self, name: str, game_path, now: float | None = None) -> None:
        """The game exited and its summary is being reported separately: mark everything seen so far
        as covered, and keep watching for what the post-exit scans add."""
        if name not in self.state:
            return
        self._baseline(name, game_path)
        self.state[name]["until"] = (time.monotonic() if now is None else now) + POST_EXIT_WATCH

    def stop(self, name: str) -> None:
        self.state.pop(name, None)

    def poll(self, name: str, game_path, now: float | None = None) -> tuple[str, str, str] | None:
        """(title, body, urgency) when there is something new to report, else None."""
        st = self.state.get(name)
        if st is None:
            return None
        now = time.monotonic() if now is None else now
        if st["until"] is not None and now > st["until"]:
            self.stop(name)
            return None
        log = latest_alert_log(game_path)
        if log is None:
            return None
        text = read_tail(log)
        a, w = core.count_alerts(text)
        if log.name != st["log"]:                 # the new run's log: it starts from nothing
            st["log"], st["alert"], st["warn"] = log.name, 0, 0
        st["new_a"] += max(0, a - st["alert"])
        st["new_w"] += max(0, w - st["warn"])
        st["alert"], st["warn"] = a, w
        if not (st["new_a"] or st["new_w"]) or now - st["sent"] < MIN_GAP:
            return None
        na, nw = st["new_a"], st["new_w"]
        st["new_a"] = st["new_w"] = 0
        st["sent"] = now
        bits = ([plural(na, "alert")] if na else []) + ([plural(nw, "warning")] if nw else [])
        title = f"{name}: {', '.join(bits)}"
        body = last_finding(text) or "See the Monitor tab."
        return title, body, "critical" if na else "normal"


def finish_message(name: str, verdict: str, vtext: str, code: int, notify_clean: bool = False
                   ) -> tuple[str, str, str] | None:
    """What to say when a game exits, from core.last_run's verdict. None for nothing."""
    if verdict in ("alert", "blocked", "leak"):
        head = {"alert": "alerts", "blocked": "launch blocked", "leak": "possible leak"}[verdict]
        return f"{name} ended: {head}", clean(vtext) or "See the Runs tab.", "critical"
    if verdict == "notes":
        return f"{name} ended with warnings", clean(vtext) or "See the Runs tab.", "normal"
    if notify_clean and verdict == "clean":
        return f"{name} ended: clean", clean(vtext) or "No findings.", "low"
    if code not in (0, None) and verdict == "never":
        return f"{name} exited with code {code}", "No monitor log was written.", "normal"
    return None
