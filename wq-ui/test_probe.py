"""Tests for wq_probe.py (the Qt-free half of 'Test sandbox'). Run: python3 wq-ui/test_probe.py"""
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import wq_core as core  # noqa: E402
import wq_probe as p  # noqa: E402

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

fail = 0
def check(cond, msg):
    global fail
    print(("ok   - " if cond else "FAIL - ") + msg)
    if not cond:
        fail = 1

# parsing
r = p.parse_output(SAMPLE)
check(len(r["rows"]) == 7, f"7 rows parsed ({len(r['rows'])})")
check(r["rows"][0] == {"section": "identity and privileges", "tag": "info", "text": "groups: deathxknight"}, "first row, section and ANSI handled")
check(r["summary_seen"] and r["verify_passed"] == 18 and r["verify_failed"] == 0, "verifier totals and summary seen")
check(p.counts(r["rows"]) == {"LEAK": 1, "ok": 3, "info": 3}, "counts")
check(p.status(r) == "leaks", "status leaks")
check(p.status(p.parse_output(SAMPLE.replace("  LEAK  NoNewPrivs=0\n", ""))) == "clean", "status clean")
blocked = p.parse_output("[SANDBOX-VERIFY] FAIL: $HOME/x present - real home leaked\n[SANDBOX-VERIFY] 3 passed, 1 failed\n")
check(p.status(blocked) == "blocked" and blocked["verify_fail_lines"] == ["$HOME/x present - real home leaked"], "verifier failure is 'blocked'")
check(p.status(p.parse_output("FATAL: firejail is not installed\n")) == "noprobe", "no output at all is 'noprobe'")
check(len(p.parse_output("  ok    stray line before any section\n")["rows"]) == 0, "rows outside a section are ignored")

# normalising and diffing
check(p.norm("X11 socket(s): X405 DISPLAY=:405") == p.norm("X11 socket(s): X12 DISPLAY=:12"), "display numbers fold together")
new = p.parse_output(SAMPLE.replace("  LEAK  NoNewPrivs=0", "  ok    NoNewPrivs=1").replace("X405", "X777").replace(":405", ":777"))
d = p.diff_rows(r["rows"], new["rows"])
check(len(d) == 1 and d[0]["kind"] == "changed" and (d[0]["old"], d[0]["new"]) == ("LEAK", "ok"), "only the real change shows up in a diff")
gone = p.parse_output(SAMPLE.replace("  ok    CapEff empty\n", ""))
dg = p.diff_rows(r["rows"], gone["rows"])
check(len(dg) == 1 and dg[0]["kind"] == "gone", "a vanished check is reported")
check(p.diff_profile({"A": ["1"], "CLAM_SCAN": ["0"]}, {"A": ["0"], "CLAM_SCAN": ["1"]}) == [("A", "1", "0")], "profile diff ignores forced keys")

# effective profile
tmp = Path(tempfile.mkdtemp())
try:
    gconf = {"EXE": ["a.exe"], "FJ_NOINPUT": ["0"], "FJ_HOOK_PRE": ["/x/pre.sh"], "FJ_WL_RO": ["/opt/x"], "FJ_NET_ALLOW": ["tcp:1.1.1.1:443"]}
    defaults = {"FJ_NOSOUND": ["1"], "FJ_NET_ALLOW": ["tcp:2.2.2.2:443"], "FJ_DEV_BLOCK": ["/dev/foo"]}
    wine = core.Game("W", tmp, dict(gconf), True)
    prof = p.effective_profile(wine, defaults)
    check(prof["FJ_NOINPUT"] == ["0"] and prof["FJ_NOSOUND"] == ["1"] and prof["FJ_NOGROUPS"] == ["1"], "game.conf > defaults > builtin")
    check(prof["FJ_RESTRICT_NS"] == ["0"], "a Wine game keeps its Wine default for FJ_RESTRICT_NS")
    nat = core.Game("N", tmp, {"EXE": ["s.sh"], "RUNNER": ["native"]}, True)
    check(p.effective_profile(nat, {})["FJ_RESTRICT_NS"] == ["1"], "a native game gets the native default")
    check("FJ_HOOK_PRE" not in prof and "FJ_HOOK_POST" not in prof, "hooks are never copied into a test")
    check(sorted(prof["FJ_NET_ALLOW"]) == ["tcp:1.1.1.1:443", "tcp:2.2.2.2:443"], "FJ_NET_ALLOW merges game and defaults like profile.sh")
    check(prof["FJ_WL_RO"] == ["/opt/x"] and prof["FJ_DEV_BLOCK"] == ["/dev/foo"], "list keys carried over")
    check(prof["CLAM_SCAN"] == ["0"] and prof["MONITOR_KILL"] == ["0"], "scan and monitor-kill forced off")
    check(p.effective_profile(None, defaults)["FJ_NOSOUND"] == ["1"], "no game = defaults only")

    # the written game.conf is read back the same way the launcher reads it
    text = p.conf_text(prof)
    cf = tmp / "c.conf"; cf.write_text(text)
    back = core.parse_kv(cf)
    check(back["EXE"] == ["probe.sh"] and back["RUNNER"] == ["native"] and back["FJ_NOINPUT"] == ["0"], "conf round trip")
    check(back["FJ_EXTRA_ARGS"] == [""], "an empty list is written as 'KEY=' so defaults are not consulted")
    check("FJ_HOOK" not in text, "no hooks in the test conf")

    # prepare()
    q = tmp / "q"; q.mkdir()
    d1 = p.prepare(q, prof)
    check((d1 / "game" / "probe.sh").is_file() and (d1 / "launch-quarantine.sh").stat().st_mode & 0o100, "test game created")
    (d1 / "game" / "junk").write_text("x"); (d1 / "home").mkdir()
    d2 = p.prepare(q, prof)
    check(not (d2 / "game" / "junk").exists() and not (d2 / "home").exists(), "a second run starts from scratch")
    check(core.scan_games(q) == [], "scan_games does not list the test game")
    (q / "_sandbox-test").rename(q / "moved")
    (q / "_sandbox-test").symlink_to(tmp)
    try:
        p.prepare(q, prof); check(False, "a symlinked test dir is refused")
    except OSError:
        check((tmp / "c.conf").exists(), "a symlinked test dir is refused (and nothing was deleted)")

    # launcher text equals what config.sh generates
    root = HERE.parent
    sh = subprocess.run(["bash", "-c", '. "$1/config.sh" >/dev/null 2>&1; wq_launcher_text native', "_", str(root)],
                        capture_output=True, text=True).stdout
    check(sh == p.LAUNCHER_TEXT, "launcher text matches wq_launcher_text native")

    # stored runs
    for i in range(7):
        run = p.make_run(new, prof); run["time"] = f"t{i}"
        p.save_run(q, "My Game/x", run)
    runs = p.load_runs(q, "My Game/x")
    check(len(runs) == p.KEEP_RUNS and runs[-1]["time"] == "t6", "only the last runs are kept")
    check(p.results_path(q, "My Game/x").parent == q / ".sandbox-tests" and "/" not in p.results_path(q, "My Game/x").name, "result file name is sanitised")
    check(p.load_runs(q, "nope") == [], "no stored runs = empty list")
    p.results_path(q, "bad").write_text("{not json") if p.results_path(q, "bad").parent.exists() else None
    check(p.load_runs(q, "bad") == [], "a corrupt results file is ignored")
    rep = p.format_report("G", runs[-1], runs[-2])
    check("settings: unchanged" in rep and "results: unchanged" in rep and "== identity and privileges" in rep, "report text")
finally:
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

sys.exit(fail)
