"""Offscreen smoke test for the 'Test sandbox' dialog and its toolbar action (skipped without PySide6)."""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    from PySide6.QtWidgets import QApplication
except ImportError:
    print("PySide6 not installed, skipping"); sys.exit(0)
import wq_core as core  # noqa: E402
import wq_probe as probe  # noqa: E402
import wq_sandboxtest as st  # noqa: E402

SAMPLE = """wq: native launch of probe (probe.sh).
\x1b[0m[SANDBOX-VERIFY] ok:   CapEff is all-zero
[SANDBOX-VERIFY] 18 passed, 0 failed
wq probe  2026-11-02 09:08:55  user=x host=archlinux arch=x86_64
cwd=/mnt/wine-quarantine/probev2/game  HOME=/home/x

== identity and privileges
  info  groups: deathxknight
  ok    CapEff empty
  LEAK  NoNewPrivs=0

== syscalls (python3 + ctypes, x86_64 only)
  ok    add_key            blocked (EPERM)
  info  kcmp               reached the kernel (errno 3 ESRCH)

== host sockets and environment
  info  X11 socket(s): X405  DISPLAY=:405  (host X11 shared unless this is Xephyr)
  ok    /run/systemd/private is a placeholder, not a socket

== summary: 1 leak(s), 3 ok, 3 info
"""

app = QApplication([])
fail = 0
def check(c, m):
    global fail
    print(("ok   - " if c else "FAIL - ") + m)
    if not c: fail = 1

q = Path(tempfile.mkdtemp())
g = core.Game("G", q / "G", {"EXE": ["a.exe"]}, True)
dlg = st.SandboxTestDialog(None, q, g, {})
dlg.timer.stop()                       # no firejail here: don't let start() run, feed the output by hand
dlg.profile = probe.effective_profile(g, {})
dlg.output = SAMPLE
dlg.proc = None
dlg._finished()
check(dlg.headline.text() == "Leaks found", "headline shows 'Leaks found'")
check(dlg.tree.topLevelItemCount() == 3 and dlg.tree.topLevelItem(0).childCount() == 3, "tree has 3 sections, 3 rows in the first")
check(dlg.btn_copy.isEnabled() and dlg.btn_run.isEnabled(), "buttons enabled after a run")
check(len(probe.load_runs(q, "G")) == 1, "the run was saved")
check("first saved test" in dlg.changes.toPlainText(), "first run: nothing to compare with")
dlg.only_problems.setChecked(True)
check(dlg.tree.topLevelItemCount() == 1 and dlg.tree.topLevelItem(0).child(0).text(0) == "LEAK", "filter keeps only the LEAK")

# second run with one thing fixed -> the Changes tab says so
dlg.prev = probe.load_runs(q, "G")[-1]
dlg.profile["FJ_NOINPUT"] = ["0"]
dlg.output = SAMPLE.replace("  LEAK  NoNewPrivs=0", "  ok    NoNewPrivs=1")
dlg._finished()
txt = dlg.changes.toPlainText()
check(dlg.headline.text() == "No leaks found", "second run is clean")
check("FJ_NOINPUT: 1 -> 0" in txt and "[LEAK -> ok]" in txt, "Changes tab lists the toggled setting and the flipped result")

# a run that never got going is shown but not stored
n = len(probe.load_runs(q, "G"))
dlg.output = "FATAL: firejail is not installed\n"
dlg._finished()
check(dlg.headline.text().startswith("The probe did not run") and len(probe.load_runs(q, "G")) == n, "failed start is reported and not saved")
dlg.output = "[SANDBOX-VERIFY] FAIL: /dev/input is readable\n[SANDBOX-VERIFY] 2 passed, 1 failed\n"
dlg._finished()
check("verifier" in dlg.headline.text() and "/dev/input" in dlg.sub.text(), "verifier failure is explained")

# defaults-only dialog
d2 = st.SandboxTestDialog(None, q, None, {}); d2.timer.stop()
check(d2.name == probe.DEFAULTS_KEY, "no game selected tests the defaults")

# the main window gets the action
try:
    import wq_ui
    from wq_ui import MainWindow
    check(hasattr(MainWindow, "test_sandbox"), "MainWindow.test_sandbox exists")
except Exception as e:
    check(False, f"wq_ui import: {e!r}")
sys.exit(fail)
