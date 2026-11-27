"""Qt-free reading of a game's run logs, for the Runs tab and the Network host map.

Everything here is read from files the launcher and monitor already write:

  logs/alerts-YYYYMMDD-HHMMSS.log   monitor output, one "[time] [LEVEL] message" per line
  logs/launch-YYYYMMDD-HHMMSS.log   launcher + sandbox verifier output
  logs/net-attempts.jsonl           connection attempts, appended by wq-ui while it is open

The two timestamps in a pair of file names are the same run, which is how a run's monitor log
and launch log are matched up. Nothing in here changes a log, and a missing or half-written
file is never an error: it just gives fewer events.

The monitor logs process starts ("New process: pid=... cmd=...") without the parent pid, so
this module shows process starts as a lane of events, not as a tree.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import wq_core as core

LEVELS = {"INFO": 0, "WARN": 1, "ALERT": 2}
NET_LOG = "net-attempts.jsonl"
NET_LOG_MAX = 512 * 1024                     # bytes; older half is dropped when it grows past this
NET_THROTTLE = 1.0                           # seconds: the same destination is logged at most this often
NET_KEEP_DAYS = 30                           # same window the launcher keeps run logs for
READ_MAX = 2 * 1024 * 1024                   # never read more than this of one log

_STAMP_FILE = re.compile(r"^(alerts|launch)-(\d{8}-\d{6})\.log$")     # the "-scan" log is not a run
_LINE = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\] \[(INFO|WARN|ALERT)\] (.*)$")


# runs

@dataclass(frozen=True)
class Run:
    stamp: str                   # 20261121-175649
    start: float                 # unix time parsed from the stamp (local time, like the logs)
    alerts: Path | None
    launch: Path | None

    @property
    def label(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start))


def _stamp_time(stamp: str) -> float:
    try:
        return time.mktime(time.strptime(stamp, "%Y%m%d-%H%M%S"))
    except (ValueError, OverflowError):
        return 0.0


def list_runs(game_path: Path | str, limit: int = 30) -> list[Run]:
    """The newest `limit` runs of a game, oldest first."""
    logs = Path(game_path) / "logs"
    found: dict[str, dict[str, Path]] = {}
    try:
        names = list(logs.iterdir())
    except OSError:
        return []
    for p in names:
        m = _STAMP_FILE.match(p.name)
        if m:
            found.setdefault(m.group(2), {})[m.group(1)] = p
    stamps = sorted(found)[-limit:] if limit else sorted(found)
    return [Run(s, _stamp_time(s), found[s].get("alerts"), found[s].get("launch")) for s in stamps]


def _read(path: Path | None, tail: bool = False, limit: int = READ_MAX) -> str:
    if path is None:
        return ""
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            if tail and size > limit:
                f.seek(size - limit)
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


# events

@dataclass(frozen=True)
class Event:
    t: float
    level: str           # INFO | WARN | ALERT
    kind: str            # process | file | scan | net | system
    msg: str

    @property
    def rank(self) -> int:
        return LEVELS.get(self.level, 0)


LANES = ("process", "file", "scan", "net", "system")
LANE_TITLE = {"process": "Processes", "file": "Files and persistence", "scan": "Scans (ClamAV, YARA, capa)",
              "net": "Network", "system": "Monitor"}

_SYSTEM = re.compile(r"^(Monitor started|Game process ended|Native mode|Wine INIT|Kill switch|No terminal emulator"
                     r"|Home directory is NOT hidden|nothing to watch|no watch paths|The filesystem watcher)")
_PROCESS = re.compile(r"\bpid=\d+|^New process|^Suspicious process|^System process|rundll32|^reg\.exe|^cmd\.exe")
_FILE = re.compile(r"Home diff|Registry|Startup|system32|windows/|[Ww]ritten|[Dd]ropped|[Aa]utostart|systemd user"
                   r"|SSH directory|\.local/bin|[Ss]uspicious file|[Nn]ew (executable|file|script)|Persistence key"
                   r"|Session environment|Desktop launcher|Launcher/unit|Shell/session")


def classify(msg: str) -> str:
    if msg.startswith(("ClamAV", "YARA", "Pre-launch", "capa")):
        return "scan"
    if _SYSTEM.search(msg):
        return "system"
    if _FILE.search(msg) and "pid=" not in msg:
        return "file"
    if _PROCESS.search(msg):
        return "process"
    return "system"


def parse_alert_log(text: str) -> list[Event]:
    out: list[Event] = []
    for line in text.splitlines():
        m = _LINE.match(core.strip_ansi(line))
        if not m:
            continue
        try:
            t = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"))
        except (ValueError, OverflowError):
            continue
        out.append(Event(t, m.group(2), classify(m.group(3)), m.group(3)))
    return out


# connection attempts

@dataclass(frozen=True)
class Attempt:
    t: float
    addr: str
    port: int
    blocked: bool
    mode: str = ""
    proto: str = ""


_last_logged: dict[tuple, float] = {}


def append_attempt(game_path: Path | str, addr: str, port: int, blocked: bool, mode: str = "",
                   proto: str = "", now: float | None = None) -> bool:
    """Remember one connection attempt for the Runs tab and the host map. Returns False when
    it was skipped (the same destination was logged less than NET_THROTTLE seconds ago, or the
    log can't be written). Failing to write must never get in the way of the Network tab."""
    now = time.time() if now is None else now
    key = (str(game_path), addr, port)
    if now - _last_logged.get(key, 0.0) < NET_THROTTLE:
        return False
    if len(_last_logged) > 5000:             # a port scan must not grow this without limit
        _last_logged.clear()
    path = Path(game_path) / "logs" / NET_LOG
    rec = {"t": round(now, 3), "a": addr, "p": int(port), "b": bool(blocked)}
    if mode:
        rec["m"] = mode
    if proto:
        rec["pr"] = proto
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            big = path.stat().st_size > NET_LOG_MAX
        except OSError:
            big = False
        if big:
            lines = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[len(lines) // 2:]))
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError:
        return False
    _last_logged[key] = now
    return True


def read_attempts(game_path: Path | str, since: float = 0.0, until: float | None = None) -> list[Attempt]:
    out: list[Attempt] = []
    for line in _read(Path(game_path) / "logs" / NET_LOG, tail=True).splitlines():
        try:
            r = json.loads(line)
            a = Attempt(float(r["t"]), str(r["a"]), int(r["p"]), bool(r.get("b", False)),
                        str(r.get("m", "")), str(r.get("pr", "")))
        except (ValueError, KeyError, TypeError):
            continue
        if a.t >= since and (until is None or a.t <= until):
            out.append(a)
    return out


# timeline

@dataclass
class Timeline:
    events: list[Event]
    t0: float                   # run start (the monitor's first line)
    t_game: float               # game process ended
    t1: float                   # last event (ClamAV and diffs run after the game ends)
    truncated: bool = False

    @property
    def has_after(self) -> bool:
        return self.t1 - self.t_game >= 1 and any(e.t > self.t_game for e in self.events)

    @property
    def duration(self) -> float:
        return max(0.0, self.t_game - self.t0)

    def frac(self, t: float) -> float:
        """Where t sits on the strip, 0..1. The time the game ran takes 80% of the width and the
        work after it ended (diffs, ClamAV) the rest, so a 3-hour game and a 10-second scan both
        stay readable."""
        run_w = 0.8 if self.has_after else 1.0
        span = max(self.t_game - self.t0, 1.0)
        if t <= self.t_game:
            return max(0.0, (t - self.t0) / span) * run_w
        post = max(self.t1 - self.t_game, 1.0)
        return run_w + min(1.0, (t - self.t_game) / post) * (1.0 - run_w)

    def lanes(self) -> list[str]:
        """Lanes to draw: processes and files always, the others only when something happened there."""
        have = {e.kind for e in self.events}
        return [k for k in LANES if k in ("process", "file") or k in have]

    def bins(self, lane: str, n: int) -> list[tuple[int, int, str, list[Event]]]:
        """Events of one lane grouped into n columns: (column, count, worst level, events)."""
        cols: dict[int, list[Event]] = {}
        for e in self.events:
            if e.kind == lane:
                cols.setdefault(min(n - 1, int(self.frac(e.t) * n)), []).append(e)
        res = []
        for c in sorted(cols):
            evs = cols[c]
            worst = max(evs, key=lambda e: e.rank).level
            res.append((c, len(evs), worst, evs))
        return res

    def notable(self) -> list[Event]:
        """Warnings and alerts in time order. Routine events stay on the strip only."""
        return [e for e in self.events if e.rank >= 1]

    def offset(self, t: float) -> str:
        return fmt_offset(t - self.t0)


def fmt_offset(sec: float) -> str:
    s = int(round(sec))
    sign = "-" if s < 0 else "+"
    s = abs(s)
    h, rem = divmod(s, 3600)
    m, sec_ = divmod(rem, 60)
    return f"{sign}{h}:{m:02d}:{sec_:02d}" if h else f"{sign}{m}:{sec_:02d}"


def build_timeline(run: Run, game_path: Path | str | None = None) -> Timeline | None:
    """The run's events in time order, or None if it left no readable monitor log."""
    text = _read(run.alerts, tail=True)
    events = parse_alert_log(text)
    if not events:
        return None
    t0 = next((e.t for e in events if e.msg.startswith("Monitor started")), events[0].t)
    ended = [e.t for e in events if e.msg.startswith("Game process ended")]
    t_end = max(e.t for e in events)
    t_game = ended[0] if ended else t_end
    if game_path is not None:
        for a in read_attempts(game_path, since=t0 - 1, until=t_game + 5):
            lvl = "WARN" if a.blocked else "INFO"
            where = f"{a.addr}:{a.port}" + (f" ({a.proto})" if a.proto else "")
            events.append(Event(a.t, lvl, "net", f"{'Blocked' if a.blocked else 'Allowed'} connection to {where}"))
    events.sort(key=lambda e: e.t)
    return Timeline(events, t0, max(t_game, t0), max(e.t for e in events),
                    truncated=run.alerts is not None and _size(run.alerts) > READ_MAX)


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


# history

_NORM_NUM = re.compile(r"\d+")


def _norm(msg: str) -> str:
    """A finding with the parts that change every run (pids, times, counts, run folders)
    flattened, so the same finding in two runs compares equal."""
    return _NORM_NUM.sub("N", msg).strip()


@dataclass
class RunSummary:
    run: Run
    status: str                          # clean | notes | alert | blocked | leak
    text: str
    n_alert: int
    n_warn: int
    findings: frozenset[str] = field(default_factory=frozenset)
    findings_raw: tuple[str, ...] = ()

    @property
    def start(self) -> float:
        return self.run.start


_SUM_CACHE: dict[tuple, RunSummary] = {}


def _sig(p: Path | None) -> tuple:
    try:
        st = p.stat() if p else None
    except OSError:
        st = None
    return (str(p), st.st_mtime_ns, st.st_size) if st else (str(p), 0, 0)


def launch_text(run: Run) -> str:
    """The run's launch log with colour codes removed (empty if it has none)."""
    return core.strip_ansi(_read(run.launch))


def summarize_run(run: Run) -> RunSummary:
    """Verdict and findings of one run. Cached until either of its logs changes, so the Runs
    tab can refresh often without reading twenty logs each time."""
    key = (run.stamp, _sig(run.alerts), _sig(run.launch))
    hit = _SUM_CACHE.get(key)
    if hit is not None:
        return hit
    if len(_SUM_CACHE) > 400:
        _SUM_CACHE.clear()
    launch = core.strip_ansi(_read(run.launch))
    alerts = _read(run.alerts, tail=True)
    status, text = core.run_verdict(launch, alerts)
    n_alert, n_warn = core.count_alerts(alerts)
    raw = []
    for ev in parse_alert_log(alerts):
        if ev.rank >= 1 and not core._ALERT_META.search(ev.msg):
            raw.append(ev.msg)
    res = RunSummary(run, status, text, n_alert, n_warn, frozenset(_norm(m) for m in raw), tuple(raw))
    _SUM_CACHE[key] = res
    return res


def run_history(game_path: Path | str, limit: int = 20) -> list[RunSummary]:
    """Verdicts of the last `limit` runs, oldest first."""
    return [summarize_run(r) for r in list_runs(game_path, limit)]


def compare(prev: RunSummary | None, cur: RunSummary) -> tuple[list[str], list[str]]:
    """(findings that are new in cur, findings that were in prev and are gone). With no earlier
    run everything is new. Each finding is listed once, in the order it appeared."""
    before = prev.findings if prev else frozenset()

    def pick(msgs: tuple[str, ...], skip: frozenset[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for m in msgs:
            n = _norm(m)
            if n not in skip and n not in seen:
                seen.add(n)
                out.append(m)
        return out

    return pick(cur.findings_raw, before), (pick(prev.findings_raw, cur.findings) if prev else [])


def trend_note(history: list[RunSummary], min_clean: int = 3) -> str:
    """A sentence when the latest run is worse than a streak of clean ones before it (the
    pattern of a game that behaves until it has been trusted for a while), else ''."""
    if len(history) < min_clean + 1:
        return ""
    *before, last = history
    if last.status in ("clean", "never"):
        return ""
    streak = 0
    for s in reversed(before):
        if s.status != "clean":
            break
        streak += 1
    if streak < min_clean:
        return ""
    what = {"notes": "new notes", "alert": "alerts", "blocked": "a blocked launch",
            "leak": "a sandbox leak"}.get(last.status, "findings")
    return f"The latest run has {what} after {streak} clean runs in a row. Worth a closer look."


# pre-flight card

@dataclass(frozen=True)
class Check:
    ok: bool
    text: str
    group: str


@dataclass
class Preflight:
    checks: list[Check] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    aborted: bool = False

    @property
    def found(self) -> bool:
        return bool(self.checks) or self.aborted

    @property
    def ok(self) -> bool:
        return self.found and not self.failed and not self.aborted


GROUPS = ("Privileges", "Network", "Files", "Display and IPC", "Other")
_G_RULES = (
    ("Privileges", re.compile(r"Cap(Eff|Prm|Bnd|Amb)|NoNewPrivs|Seccomp|capabilit|namespace(?! contains)", re.I)),
    ("Network", re.compile(r"network|DNS|resolver|interface|loopback", re.I)),
    ("Files", re.compile(r"\$HOME|home|drives|/media|game/|game\.conf|prefix|umu|snapshot|read-only|mount", re.I)),
    ("Display and IPC", re.compile(r"D-?Bus|SSH_AUTH|socket|input|X11|display|Wayland|agent", re.I)),
)
_V_OK = re.compile(r"\[SANDBOX-VERIFY\] ok:\s+(.*)")
_V_FAIL = re.compile(r"\[SANDBOX-VERIFY\] FAIL:\s+(.*)")
_V_SUM = re.compile(r"\[SANDBOX-VERIFY\] (\d+) passed, (\d+) failed")
_V_ABORT = re.compile(r"\[SANDBOX-VERIFY\] ABORT")
_V_LEAK = re.compile(r"\[LEAK\]\s*(.*)")


def group_of(text: str) -> str:
    for name, rx in _G_RULES:
        if rx.search(text):
            return name
    return "Other"


def parse_preflight(text: str) -> Preflight:
    """The verifier's checks from a launch log (or the live launcher output)."""
    pf = Preflight()
    for raw in text.splitlines():
        line = core.strip_ansi(raw)
        if (m := _V_OK.search(line)):
            pf.checks.append(Check(True, m.group(1).strip(), group_of(m.group(1))))
        elif (m := _V_FAIL.search(line)):
            pf.checks.append(Check(False, m.group(1).strip(), group_of(m.group(1))))
        elif (m := _V_LEAK.search(line)):
            pf.checks.append(Check(False, "Leak: " + m.group(1).strip(), group_of(m.group(1))))
        elif (m := _V_SUM.search(line)):
            pf.passed, pf.failed = int(m.group(1)), int(m.group(2))
        elif _V_ABORT.search(line):
            pf.aborted = True
    if not (pf.passed or pf.failed):
        pf.passed = sum(c.ok for c in pf.checks)
        pf.failed = sum(not c.ok for c in pf.checks)
    return pf


# network hosts

@dataclass
class Host:
    addr: str
    ports: list[int]
    hits: int
    blocked: int
    allowed: int
    first: float
    last: float
    new: bool = False            # first seen in the latest run
    protos: set[str] = field(default_factory=set)
    modes: set[str] = field(default_factory=set)

    @property
    def status(self) -> str:
        if self.blocked and not self.allowed:
            return "blocked"
        return "mixed" if self.blocked else "allowed"

    @property
    def tone(self) -> str:
        """ok | warn | bad, with the same meaning as the Status column of the attempts table:
        blocked is red (the game tried something), allowed is green only when a filtered
        allow-list let it through, amber for learn mode and red for an unrestricted network."""
        if self.status == "blocked":
            return "bad"
        if self.status == "mixed":
            return "warn"
        if "open" in self.modes:
            return "bad"
        return "warn" if "learn" in self.modes else "ok"


def host_stats(attempts: list[Attempt], latest_start: float | None = None,
               now: float | None = None) -> list[Host]:
    """Attempts grouped by destination address, busiest first. `new` marks a destination whose
    first attempt in the window falls in the latest run (at or after latest_start)."""
    now = time.time() if now is None else now
    cutoff = now - NET_KEEP_DAYS * 86400
    by: dict[str, Host] = {}
    for a in sorted(attempts, key=lambda a: a.t):
        if a.t < cutoff:
            continue
        h = by.get(a.addr)
        if h is None:
            h = by[a.addr] = Host(a.addr, [], 0, 0, 0, a.t, a.t)
        h.hits += 1
        h.last = a.t
        h.blocked += int(a.blocked)
        h.allowed += int(not a.blocked)
        if a.port not in h.ports:
            h.ports.append(a.port)
        if a.proto:
            h.protos.add(a.proto)
        if a.mode:
            h.modes.add(a.mode)
    for h in by.values():
        h.ports.sort()
        h.new = latest_start is not None and h.first >= latest_start
    return sorted(by.values(), key=lambda h: (-h.hits, h.addr))


def learn_preview(attempts: list[Attempt], existing: list[str]) -> dict:
    """What turning a learn-mode recording into an allow-list would do. Destinations already
    covered by `existing` stay as they are; loopback, IPv6 and multicast/broadcast can't be
    whitelisted, so they are counted separately. `entries` is what would be added; the
    protocol is only known when the kernel log said so, otherwise a destination is listed in
    `unknown_proto` for the user to answer."""
    covered, add, skip = set(), {}, set()
    unknown: set[tuple[str, int]] = set()
    for a in attempts:
        key = (a.addr, a.port)
        if ":" in a.addr or core.is_special_addr(a.addr):
            skip.add(key)
        elif core.allow_matches(existing, a.addr, a.port):
            covered.add(key)
        elif a.proto in ("tcp", "udp"):
            add[(a.proto, a.addr, a.port)] = None
        else:
            unknown.add(key)
    entries = sorted(f"{p}:{ad}:{po}" for p, ad, po in add)
    unknown -= {(ad, po) for _p, ad, po in add}
    return {"covered": len(covered), "entries": entries, "unknown_proto": sorted(unknown),
            "not_whitelistable": len(skip)}
