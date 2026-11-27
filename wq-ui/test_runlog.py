"""Tests for wq_runlog (timeline, history, pre-flight, network hosts). No Qt, no firejail."""
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_core as core  # noqa: E402
import wq_runlog as R  # noqa: E402


def ts(stamp: str) -> float:
    return time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))


def game_dir() -> Path:
    d = Path(tempfile.mkdtemp()) / "G"
    (d / "logs").mkdir(parents=True)
    return d


def write_run(d: Path, stamp: str, alerts: str, launch: str = "wq: native launch\n[SANDBOX-VERIFY] 1 passed, 0 failed\n"):
    (d / "logs" / f"alerts-{stamp}.log").write_text(alerts)
    (d / "logs" / f"launch-{stamp}.log").write_text(launch)


def lines(*rows) -> str:
    return "".join(f"[{t}] [{lvl}] {msg}\n" for t, lvl, msg in rows)


# ---- classification, against the messages the monitor really emits
CASES = {
    "Monitor started for /x (firejail pid 5, mode: native)": "system",
    "Game process ended. Full log: /x/logs/alerts-1.log": "system",
    "Native mode: watching private home /x/home and the game folder": "system",
    "Kill switch triggered - terminating sandbox.": "system",
    "New process: pid=123 cmd=/usr/bin/python3 game.py": "process",
    "Suspicious process: nc pid=44 cmd=nc -l 9": "process",
    "Suspicious process running: pid=7 cmd=powershell.exe -enc x": "process",
    "reg.exe modifying persistence key: pid=9 cmd=reg add": "process",
    "Shell/session startup file written: ~/.bashrc (CREATE)": "file",
    "File dropped into ~/.local/bin (on PATH): ~/.local/bin/x (CREATE)": "file",
    "New executable (ELF) written in home: bin/x (CLOSE_WRITE)": "file",
    "Executable dropped into Startup: C:/Startup/a.exe (CREATE)": "file",
    "Unexpected write to system32: /x/system32/y.dll (CREATE)": "file",
    "Registry hive modified at runtime: user.reg (MODIFY)": "file",
    "Persistence key written in user.reg: [Run] foo": "file",
    "Home unchanged vs pre-run snapshot (startup files, autostart, units, ~/.local/bin, ~/.ssh)": "file",
    "Home diff: removed ~/.zshrc": "file",
    "ClamAV: 1 file(s) scanned, none flagged (changed since last scan)": "scan",
    "ClamAV database is 21 day(s) old (limit 7). Run: sudo freshclam": "scan",
    "ClamAV: game/x.exe: Win.Trojan.Agent": "scan",
    "something nobody planned for": "system",
}
for msg, want in CASES.items():
    got = R.classify(msg)
    assert got == want, (msg, got, want)

# ---- parsing the real sample logs shipped in the project folder
here = Path(__file__).resolve().parent.parent
sample = here / "probe" / "logs" / "alerts-20261121-175649.log"
if sample.exists():
    evs = R.parse_alert_log(sample.read_text())
    assert len(evs) == 7 and evs[0].msg.startswith("Monitor started")
    assert [e.level for e in evs].count("WARN") == 1 and evs[-1].kind == "scan"
    pf = R.parse_preflight((here / "probe" / "logs" / "launch-20261121-175649.log").read_text())
    print("sample preflight:", pf.passed, pf.failed, len(pf.checks))
    assert pf.passed == 18 and pf.failed == 0 and len(pf.checks) == 18 and pf.ok
    assert {c.group for c in pf.checks} <= set(R.GROUPS)

# garbage lines are skipped, never raise
assert R.parse_alert_log("not a log line\n[bad] [INFO] x\n\x1b[31m[2026-11-21 10:00:00] [ALERT] red\x1b[0m\n")[0].level == "ALERT"
assert R.parse_alert_log("[2026-13-45 99:99:99] [INFO] impossible date\n") == []

# ---- runs: pairing, ordering, the -scan log is not a run
d = game_dir()
write_run(d, "20261121-100000", lines(("2026-11-21 10:00:00", "INFO", "Monitor started for /x (firejail pid 1, mode: native)")))
write_run(d, "20261121-110000", lines(("2026-11-21 11:00:00", "INFO", "Monitor started for /x (firejail pid 1, mode: native)")))
(d / "logs" / "alerts-20261121-110000-scan.log").write_text("[2026-11-21 11:00:00] [INFO] scan only\n")
(d / "logs" / "clamscan-20261121-100000.log").write_text("x")
(d / "logs" / "launch-20261120-090000.log").write_text("launch with no alert log\n")
runs = R.list_runs(d)
assert [r.stamp for r in runs] == ["20261120-090000", "20261121-100000", "20261121-110000"]
assert runs[0].alerts is None and runs[1].alerts and runs[1].launch
assert [r.stamp for r in R.list_runs(d, limit=2)] == ["20261121-100000", "20261121-110000"]
assert R.list_runs(d / "nope") == []

# ---- timeline: positions, lanes, bins, notable
d = game_dir()
write_run(d, "20261121-120000", lines(
    ("2026-11-21 12:00:00", "INFO", "Monitor started for /x (firejail pid 1, mode: native)"),
    ("2026-11-21 12:00:10", "INFO", "New process: pid=10 cmd=/bin/game"),
    ("2026-11-21 12:00:11", "INFO", "New process: pid=11 cmd=/bin/helper"),
    ("2026-11-21 12:01:00", "WARN", "New executable (ELF) written in game/: bin/dropped (CLOSE_WRITE)"),
    ("2026-11-21 12:01:30", "ALERT", "Suspicious process: curl pid=12 cmd=curl http://x"),
    ("2026-11-21 12:01:31", "ALERT", "Kill switch triggered - terminating sandbox."),
    ("2026-11-21 12:01:40", "INFO", "Game process ended. Full log: /x"),
    ("2026-11-21 12:01:45", "INFO", "ClamAV: 3 file(s) scanned, none flagged (changed since last scan)"),
    ("2026-11-21 12:01:50", "WARN", "ClamAV database is 21 day(s) old (limit 7). Run: sudo freshclam"),
))
run = R.list_runs(d)[0]
R.append_attempt(d, "93.184.216.34", 443, True, "filtered", "tcp", now=ts("2026-11-21 12:00:30"))
R.append_attempt(d, "10.0.0.5", 80, False, "learn", now=ts("2026-11-21 12:00:31"))
R.append_attempt(d, "1.1.1.1", 53, True, "filtered", now=ts("2026-11-21 14:00:00"))    # a different run: not in this one
tl = R.build_timeline(run, d)
assert tl is not None and tl.duration == 100 and tl.has_after
assert R.build_timeline(R.Run("x", 0, None, None)) is None
assert tl.lanes() == ["process", "file", "scan", "net", "system"]
assert tl.frac(tl.t0) == 0 and abs(tl.frac(tl.t_game) - 0.8) < 1e-9 and abs(tl.frac(tl.t1) - 1.0) < 1e-9
assert all(0 <= tl.frac(e.t) <= 1 for e in tl.events)
assert [e.t for e in tl.events] == sorted(e.t for e in tl.events)
net = [e for e in tl.events if e.kind == "net"]
assert len(net) == 2 and net[0].level == "WARN" and "Blocked connection to 93.184.216.34:443 (tcp)" in net[0].msg
assert net[1].level == "INFO" and net[1].msg.startswith("Allowed")
b = tl.bins("process", 100)
assert sum(n for _c, n, _l, _e in b) == len([e for e in tl.events if e.kind == "process"])
worst = tl.bins("process", 1)[0][2]
assert worst == "ALERT"                                       # one column holds INFO and ALERT: worst wins
assert [e.level for e in tl.notable()].count("ALERT") == 2 and all(e.rank >= 1 for e in tl.notable())
assert tl.offset(tl.t0 + 62) == "+1:02" and R.fmt_offset(3725) == "+1:02:05" and R.fmt_offset(-3) == "-0:03"

# no events after the game ends: the strip uses the full width
d = game_dir()
write_run(d, "20261121-130000", lines(
    ("2026-11-21 13:00:00", "INFO", "Monitor started for /x (firejail pid 1, mode: native)"),
    ("2026-11-21 13:00:05", "INFO", "Game process ended. Full log: /x")))
tl2 = R.build_timeline(R.list_runs(d)[0])
assert not tl2.has_after and abs(tl2.frac(tl2.t_game) - 1.0) < 1e-9

# a run with no "Game process ended" (monitor killed): the last event stands in
d = game_dir()
write_run(d, "20261121-140000", lines(
    ("2026-11-21 14:00:00", "INFO", "Monitor started for /x (firejail pid 1, mode: native)"),
    ("2026-11-21 14:00:20", "INFO", "New process: pid=3 cmd=/bin/x")))
tl3 = R.build_timeline(R.list_runs(d)[0])
assert tl3.duration == 20 and not tl3.has_after

# ---- history, verdicts, compare, trend
d = game_dir()
clean = lines(("2026-11-21 10:00:00", "INFO", "Monitor started for /x (firejail pid 1, mode: native)"),
              ("2026-11-21 10:00:05", "WARN", "ClamAV database is 21 day(s) old (limit 7). Run: sudo freshclam"))
for i in range(4):
    write_run(d, f"20261121-10000{i}", clean.replace("21 day", f"{21 + i} day"))
write_run(d, "20261121-100004", clean + lines(
    ("2026-11-21 10:00:06", "ALERT", "Suspicious process: curl pid=99 cmd=curl x"),
    ("2026-11-21 10:00:07", "ALERT", "Kill switch triggered - terminating sandbox.")))
h = R.run_history(d)
print("history:", [(s.status, s.n_alert, s.n_warn) for s in h])
assert [s.status for s in h] == ["notes", "notes", "notes", "notes", "alert"]
assert h[-1].n_alert == 1 and h[-1].text == "✗ 1 alert"
# the stale-database warning is the same finding every run even though the day count changes
new, gone = R.compare(h[-2], h[-1])
assert new == ["Suspicious process: curl pid=99 cmd=curl x"] and gone == []
assert R.compare(h[-3], h[-2]) == ([], [])
new, gone = R.compare(h[-1], h[-2])
assert new == [] and gone == ["Suspicious process: curl pid=99 cmd=curl x"]
assert R.compare(None, h[0])[0] == [h[0].findings_raw[0]]
assert R.trend_note(h) == ""                                  # earlier runs had notes, not a clean streak
assert R.trend_note(h[:2]) == ""                              # too short

d = game_dir()
quiet = lines(("2026-11-21 10:00:00", "INFO", "Monitor started for /x (firejail pid 1, mode: native)"))
for i in range(4):
    write_run(d, f"20261121-10000{i}", quiet)
write_run(d, "20261121-100004", quiet + lines(("2026-11-21 10:00:05", "ALERT", "Autostart entry written: ~/.config/autostart/a.desktop (CREATE)")))
h = R.run_history(d)
assert [s.status for s in h] == ["clean"] * 4 + ["alert"]
note = R.trend_note(h)
assert "4 clean runs" in note and "alerts" in note
write_run(d, "20261121-100005", quiet)                         # back to clean: no note
assert R.trend_note(R.run_history(d)) == ""

# launch-log verdicts: leak beats blocked beats alert
d = game_dir()
write_run(d, "20261121-150000", quiet, "wq: x\n[SANDBOX-VERIFY] FAIL: CapEff is not zero\nwq: aborting launch\n")
write_run(d, "20261121-150100", quiet + lines(("2026-11-21 15:01:00", "ALERT", "x pid=1")), "SANDBOX LEAK\n")
assert [s.status for s in R.run_history(d)] == ["blocked", "leak"]

# ---- the history agrees with the Last run column for the newest run
d = game_dir()
write_run(d, "20261121-160000", quiet + lines(("2026-11-21 16:00:02", "WARN", "New file in windows/: a (CREATE)")))
assert core.last_run(d)[0] == R.run_history(d)[-1].status == "notes"

# ---- pre-flight parsing
launch = """wq: starting
[SANDBOX-VERIFY] ok:   CapEff is all-zero
[SANDBOX-VERIFY] ok:   network namespace contains only lo
[SANDBOX-VERIFY] ok:   no DNS resolver socket visible
[SANDBOX-VERIFY] FAIL: $HOME is not hidden
[SANDBOX-VERIFY] ok:   no raw input devices visible
[SANDBOX-VERIFY] ok:   DBUS_SESSION_BUS_ADDRESS points at firejail proxy
[SANDBOX-VERIFY] 4 passed, 1 failed
[SANDBOX-VERIFY] ABORT: sandbox not enforced
"""
pf = R.parse_preflight(launch)
assert (pf.passed, pf.failed, pf.aborted, pf.found, pf.ok) == (4, 1, True, True, False)
assert [(c.ok, c.group) for c in pf.checks] == [(True, "Privileges"), (True, "Network"), (True, "Network"),
                                                  (False, "Files"), (True, "Display and IPC"), (True, "Display and IPC")]
assert not R.parse_preflight("nothing here").found
live = R.parse_preflight("\x1b[32m[SANDBOX-VERIFY] ok:   NoNewPrivs=1\x1b[0m\n[LEAK] resolver socket reachable\n")
assert (live.passed, live.failed) == (1, 1) and live.checks[1].text.startswith("Leak:")     # no summary line yet: counted

# ---- connection attempts: persistence, throttle, rotation, bad lines
d = game_dir()
assert R.append_attempt(d, "1.2.3.4", 443, True, "filtered", "tcp", now=1000.0)
assert not R.append_attempt(d, "1.2.3.4", 443, True, now=1000.5)            # same destination within 1s: skipped
assert R.append_attempt(d, "1.2.3.4", 80, False, now=1000.5)                # other port: fine
assert R.append_attempt(d, "1.2.3.4", 443, False, now=1002.0)               # a second later: logged again
got = R.read_attempts(d)
assert [(a.addr, a.port, a.blocked) for a in got] == [("1.2.3.4", 443, True), ("1.2.3.4", 80, False), ("1.2.3.4", 443, False)]
assert got[0].proto == "tcp" and got[0].mode == "filtered" and got[1].proto == ""
assert len(R.read_attempts(d, since=1001)) == 1 and len(R.read_attempts(d, until=1001)) == 2
with (d / "logs" / R.NET_LOG).open("a") as f:
    f.write("garbage\n{\"t\": 1}\n")
assert len(R.read_attempts(d)) == 3
assert R.read_attempts(d / "missing") == []
big = game_dir()
R._last_logged.clear()
for i in range(12000):
    R.append_attempt(big, f"10.{i // 256 % 256}.{i % 256}.1", 80, True, now=2000.0 + i)
assert (big / "logs" / R.NET_LOG).stat().st_size <= R.NET_LOG_MAX + 200
last = R.read_attempts(big)[-1]
assert last.addr == f"10.{11999 // 256 % 256}.{11999 % 256}.1"               # newest entries survive rotation
assert not R.append_attempt(Path("/proc/nope"), "1.1.1.1", 1, True, now=1.0)    # unwritable: False, no exception

# ---- host stats
now = 10 * 86400.0
atts = [R.Attempt(now - 3 * 86400, "8.8.8.8", 53, True), R.Attempt(now - 3 * 86400 + 1, "8.8.8.8", 53, True),
        R.Attempt(now - 100, "8.8.8.8", 443, False), R.Attempt(now - 90, "9.9.9.9", 443, True, "", "tcp"),
        R.Attempt(now - 40 * 86400, "7.7.7.7", 1, True)]
hs = R.host_stats(atts, latest_start=now - 200, now=now)
assert [h.addr for h in hs] == ["8.8.8.8", "9.9.9.9"]                          # 7.7.7.7 is older than the window
a, b = hs
assert (a.hits, a.blocked, a.allowed, a.ports, a.status, a.new) == (3, 2, 1, [53, 443], "mixed", False)
assert (b.status, b.new, b.protos) == ("blocked", True, {"tcp"})
assert R.host_stats(atts, latest_start=None, now=now)[1].new is False

# ---- learn-mode preview
at = [R.Attempt(1, "5.5.5.5", 443, False, "learn", "tcp"), R.Attempt(2, "5.5.5.5", 443, False, "learn", "tcp"),
      R.Attempt(3, "6.6.6.6", 80, False, "learn"), R.Attempt(4, "7.7.7.7", 53, False, "learn", "udp"),
      R.Attempt(5, "239.1.1.1", 5353, False, "learn", "udp"), R.Attempt(6, "fe80::1", 80, False),
      R.Attempt(7, "127.0.0.1", 9, False), R.Attempt(8, "7.7.7.7", 123, False, "learn")]
pv = R.learn_preview(at, ["udp:7.7.7.7:53"])
assert pv["entries"] == ["tcp:5.5.5.5:443"]
assert pv["unknown_proto"] == [("6.6.6.6", 80), ("7.7.7.7", 123)]
assert pv["covered"] == 2 and pv["not_whitelistable"] == 2                     # 7.7.7.7:53 and 127.0.0.1 covered; multicast + v6 not whitelistable
assert R.learn_preview([], [])["entries"] == []

# host tone follows the attempts table: blocked red, allowed by a filter green, learn amber, open red
tn = R.host_stats([R.Attempt(now - 5, "1.1.1.1", 1, True, "filtered"), R.Attempt(now - 5, "2.2.2.2", 1, False, "filtered"),
                   R.Attempt(now - 5, "3.3.3.3", 1, False, "learn"), R.Attempt(now - 5, "4.4.4.4", 1, False, "open"),
                   R.Attempt(now - 5, "5.5.5.5", 1, True), R.Attempt(now - 4, "5.5.5.5", 1, False)], now=now)
assert {h.addr: h.tone for h in tn} == {"1.1.1.1": "bad", "2.2.2.2": "ok", "3.3.3.3": "warn", "4.4.4.4": "bad", "5.5.5.5": "warn"}
assert next(h for h in tn if h.addr == "3.3.3.3").modes == {"learn"}

# run summaries are cached until a log changes
d = game_dir()
write_run(d, "20261121-170000", quiet)
r0 = R.list_runs(d)[0]
s1 = R.summarize_run(r0)
assert R.summarize_run(r0) is s1
time.sleep(0.01)
(d / "logs" / "alerts-20261121-170000.log").write_text(quiet + lines(("2026-11-21 17:00:01", "WARN", "New file in windows/: a (CREATE)")))
s2 = R.summarize_run(R.list_runs(d)[0])
assert s2 is not s1 and s2.status == "notes"

print("runlog: ok")
