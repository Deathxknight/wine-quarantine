"""Tests for wq_notify: what gets reported, when, and how notify-send is called. No Qt, no desktop."""
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_notify as N  # noqa: E402

fails = 0


def check(cond, msg):
    global fails
    print(("ok   - " if cond else "FAIL - ") + msg)
    if not cond:
        fails += 1


def game():
    d = Path(tempfile.mkdtemp()) / "G"
    (d / "logs").mkdir(parents=True)
    return d


def log(d, stamp, *rows):
    p = d / "logs" / f"alerts-{stamp}.log"
    with p.open("a") as f:
        for lvl, msg in rows:
            f.write(f"[2026-11-22 12:00:00] [{lvl}] {msg}\n")
    return p


# --- clean / args
check(N.clean("a\x1b[31m b\n\tc") == "a [31m b c", "control characters and newlines are flattened")
check(len(N.clean("x" * 500, 50)) == 50 and N.clean("x" * 500, 50).endswith("…"), "long text is cut")
a = N.notify_args("-rf", "$(touch /tmp/x) `id`", "bogus")
check(a[a.index("--") + 1] == "-rf" and "-u" in a and a[a.index("-u") + 1] == "normal",
      "title after --, unknown urgency falls back to normal")
check(a[-1] == "$(touch /tmp/x) `id`", "body passed as one literal argument (no shell involved)")

# --- AlertWatch
w = N.AlertWatch()
d = game()
old = log(d, "20261122-100000", ("ALERT", "old run finding"), ("WARN", "old warn"))
w.start("G", d)
check(w.poll("G", d, now=100.0) is None, "findings already in the log at launch are not reported")

new = log(d, "20261122-110000", ("WARN", "monitor started"))
r = w.poll("G", d, now=101.0)
check(r is not None and r[0] == "G: 1 warning" and r[2] == "normal", f"new run's first warning reported: {r}")
check(w.poll("G", d, now=102.0) is None, "same content is not reported twice")

log(d, "20261122-110000", ("ALERT", "Unexpected outbound connection to 1.2.3.4:443"))
check(w.poll("G", d, now=103.0) is None, "throttled inside MIN_GAP (batched, not lost)")
log(d, "20261122-110000", ("ALERT", "New autostart entry written"))
r = w.poll("G", d, now=112.0)
check(r is not None and r[0] == "G: 2 alerts" and r[2] == "critical", f"batched alerts reported together: {r}")
check("autostart" in r[1] and "[ALERT]" not in r[1] and "2026-11-22" not in r[1],
      "body is the latest finding without tag or timestamp")

log(d, "20261122-110000", ("ALERT", "Kill switch triggered"))
check(w.poll("G", d, now=130.0) is None, "meta lines (kill switch) are not extra alerts")

# exit: covered by the exit summary, only later additions notify, and watching ends
w.exited("G", d, now=200.0)
check(w.poll("G", d, now=205.0) is None, "after exit, the summary already covered what was there")
log(d, "20261122-110000", ("ALERT", "ClamAV flagged file foo.dll"))
r = w.poll("G", d, now=220.0)
check(r is not None and "1 alert" in r[0], f"post-exit scan finding still reported: {r}")
check(w.poll("G", d, now=200.0 + N.POST_EXIT_WATCH + 1) is None and "G" not in w.state, "watch ends after the grace period")
check(w.poll("nope", d) is None, "unknown game is ignored")

# no log at all
w2 = N.AlertWatch()
d2 = game()
w2.start("H", d2)
check(w2.poll("H", d2, now=1.0) is None, "no alert log yet: nothing, no crash")

# --- finish_message
fm = N.finish_message
check(fm("G", "alert", "2 alerts", 0)[2] == "critical", "alert verdict is critical")
check(fm("G", "blocked", "", 0)[0].endswith("launch blocked"), "blocked launch named")
check(fm("G", "leak", "x", 0)[0].endswith("possible leak"), "leak named")
check(fm("G", "notes", "1 warning", 0)[2] == "normal", "warnings are normal urgency")
check(fm("G", "clean", "clean", 0) is None, "clean run is silent by default")
check(fm("G", "clean", "clean", 0, notify_clean=True)[2] == "low", "clean run notifies when asked")
check(fm("G", "never", "", 1) is not None and fm("G", "never", "", 0) is None, "crash with no logs is reported, clean exit is not")

# --- Notifier against a fake notify-send
bindir = Path(tempfile.mkdtemp())
out = bindir / "out.txt"
fake = bindir / "notify-send"
fake.write_text(f'#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done > {out}\n')
fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
os.environ["PATH"] = f"{bindir}:{os.environ['PATH']}"
n = N.Notifier()
check(n.available, "fake notify-send found on PATH")
check(n.send("T itle", "Body $(x)", "critical"), "send returns True")
for _ in range(50):
    if out.exists() and out.read_text():
        break
    time.sleep(0.05)
got = out.read_text().splitlines()
check(got[:2] == ["-a", "wine-quarantine"] and "critical" in got and got[-2:] == ["T itle", "Body $(x)"],
      f"notify-send received the expected arguments: {got}")
os.environ["PATH"] = "/nonexistent"
check(not N.Notifier().available and not N.Notifier().send("a", "b"), "no notify-send: quietly does nothing")

print("\nNOTIFY TESTS PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
