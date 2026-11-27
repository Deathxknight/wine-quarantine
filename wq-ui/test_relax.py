"""Tests for wq_relax (the "Relax until it launches" ladder and its undo). No Qt, no firejail."""
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_core as core  # noqa: E402
import wq_relax as R  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="wq-relax-test-"))
os.environ["XDG_CACHE_HOME"] = str(tmp / "cache")


def game(conf=None, runner="wine", path=None):
    g = core.Game("T", path or tmp / "T", {k: list(v) for k, v in (conf or {}).items()})
    if runner == "native":
        g.conf["RUNNER"] = ["native"]
    return g


def keys(steps):
    return [s.key for s in steps]


# the profile.defaults.conf this project ships with: strict-ish, with a seccomp extra list
DEFAULTS = {k: [v] for k, v in (ln.split("=", 1) for ln in """
FJ_PRIVATE_HOME=1
FJ_PRIVATE_TMP=1
FJ_NONEWPRIVS=1
FJ_CAPS_DROP=1
FJ_NODBUS=1
FJ_SECCOMP=1
FJ_NOROOT=1
FJ_NOGROUPS=1
FJ_PRIVATE_DEV=1
FJ_NOINPUT=1
FJ_BLOCK_SOCKETS=1
FJ_RESTRICT_NS=1
FJ_GAME_RO=1
PRESCAN=1
YARA_SCAN=1
FJ_NOSOUND=1
FJ_NET=0
FJ_XEPHYR=1
FJ_SECCOMP_EXTRA=ptrace,process_vm_readv,process_vm_writev
FJ_IPC_NS=1
FJ_PROTOCOL=1
""".split())}

# --- plan -------------------------------------------------------------------------------------------
p = R.plan(game(), DEFAULTS)
print("plan:", keys(p))
assert keys(p)[0] == "FJ_RESTRICT_NS"                       # most common Proton culprit goes first
assert "FJ_SECCOMP_EXTRA" in keys(p) and "FJ_GAME_RO" in keys(p) and "FJ_XEPHYR" in keys(p)
assert "FJ_MDWX" not in keys(p) and "FJ_MEMFD" not in keys(p)      # already off by default: nothing to relax
assert not set(keys(p)) & R.NEVER                           # monitoring / network are never offered
assert not any(s.opt_in for s in p)                         # the always-on floor is opt-in only
assert {"FJ_NONEWPRIVS", "FJ_CAPS_DROP", "FJ_PRIVATE_HOME"} <= set(keys(R.plan(game(), DEFAULTS, include_opt_in=True)))

# a game that already has something off is not asked about it again
p = R.plan(game({"FJ_GAME_RO": ["0"], "FJ_SECCOMP_EXTRA": [""]}), DEFAULTS)
assert "FJ_GAME_RO" not in keys(p) and "FJ_SECCOMP_EXTRA" not in keys(p)
# a game that switched something on shows up
assert "FJ_MDWX" in keys(R.plan(game({"FJ_MDWX": ["1"]}), DEFAULTS))
# native games default FJ_RESTRICT_NS to on even with nothing set
assert "FJ_RESTRICT_NS" in keys(R.plan(game(runner="native"), {}))
assert "FJ_RESTRICT_NS" not in keys(R.plan(game(), {}))     # wine default is off
# every ladder key is something wq_core really knows
for s in R.LADDER:
    assert (s.key in core.ALL_BOOLS) if s.kind == R.BOOL else (s.key in core.TEXT_KEYS), s.key
assert len(set(keys(R.LADDER))) == len(R.LADDER)

# --- game_side_text: banner and verifier lines must not drive the choice -----------------------------
real_log = """wq: native launch of x (x).
Warning: NVIDIA card detected, nogroups command ignored
firejail version 0.9.82.2
Seccomp list in: add_key,ptrace,process_vm_readv,process_vm_writev, check list: @default-keep
Child process initialized in 27.03 ms
\x1b[0;32m[SANDBOX-VERIFY] ok:   creating new namespaces is refused\x1b[0m
[SANDBOX-VERIFY] ok:   no raw input devices visible
X Error of failed request:  BadAccess (attempt to access private resource denied)
"""
gs = R.game_side_text(real_log)
assert "ptrace" not in gs and "SANDBOX-VERIFY" not in gs and "BadAccess" in gs, gs
assert R.game_side_text("") == ""
# no verifier line (firejail itself failed): the rest of the log is used, minus the lines every run prints
gs2 = R.game_side_text("Seccomp list in: ptrace\nError: cannot open display\n")
assert "ptrace" not in gs2 and "cannot open display" in gs2

# --- pick_next --------------------------------------------------------------------------------------
plan_ = R.plan(game(), DEFAULTS)
step, why = R.pick_next(plan_, "")
assert step.key == plan_[0].key and why == "next on the list"
# the banner's seccomp list mentions ptrace and process_vm_readv on every run: that must not pick SECCOMP_EXTRA
banner_only = "\n".join(ln for ln in real_log.splitlines() if "X Error" not in ln)
step, why = R.pick_next(plan_, banner_only)
assert step.key == plan_[0].key, (step.key, why)
# a real hint from the game's side wins over ladder order
step, why = R.pick_next(plan_, real_log)
assert step.key == "FJ_IPC_NS" and "BadAccess" in why, (step.key, why)
step, why = R.pick_next(plan_, "[SANDBOX-VERIFY] ok: x\nXOpenDisplay failed: Cannot open display :0\n")
assert step.key == "FJ_XEPHYR", step.key
step, why = R.pick_next(plan_, "[SANDBOX-VERIFY] ok: x\nBad system call (core dumped)\n")
assert step.key == "FJ_SECCOMP_EXTRA", step.key         # SIGSYS is a seccomp kill
# a hint for a step that is not in the remaining list is ignored
rest = [s for s in plan_ if s.key != "FJ_IPC_NS"]
assert R.pick_next(rest, real_log)[0].key == rest[0].key
try:
    R.pick_next([], "")
    raise AssertionError("pick_next([]) should raise")
except ValueError:
    pass

# --- classify ---------------------------------------------------------------------------------------
ok_log = "[SANDBOX-VERIFY] ok: x\nwine: Unhandled exception\n"
o, msg = R.classify(True, 1, 4.0, 20, ok_log, "")
assert o == R.CRASHED and "code 1" in msg, (o, msg)
o, _ = R.classify(False, None, 20.0, 20, ok_log, "")
assert o == R.SURVIVED
o, msg = R.classify(True, 1, 1.0, 20, "[SANDBOX-VERIFY] FAIL: x\n", "")
assert o == R.REFUSED and "Relaxing the sandbox would not help" in msg
o, _ = R.classify(True, 0, 1.0, 20, "wq: aborting launch\n", "")
assert o == R.REFUSED                                         # a pre-launch refusal is not a crash
o, _ = R.classify(True, 97, 1.0, 20, "", "")
assert o == R.REFUSED                                         # preflight exit code, even with no log
o, msg = R.classify(True, 1, 5.0, 20, ok_log, "[ALERT] system32 write: foo.dll\n")
assert o == R.ALERT and "nothing was relaxed" in msg
# an alert while the game is still running does not count as "it launched fine"
o, _ = R.classify(False, None, 20.0, 20, ok_log, "[ALERT] something\n")
assert o == R.ALERT
o, _ = R.classify(True, 1, 3.0, 20, ok_log, "", stopped_by_user=True)
assert o == R.STOPPED
# the sandbox never came up: a setup problem or a silent exit is not something relaxing can fix
o, msg = R.classify(True, 1, 0, 20, "FATAL: no Proton build found. See config.sh.\n", "", sandbox_started=False)
assert o == R.REFUSED and "no Proton build" in msg
o, msg = R.classify(True, 1, 0, 20, "wq: pre-launch scan of x ...\n", "", sandbox_started=False)
assert o == R.NEVER_STARTED and "Nothing was relaxed" in msg
o, _ = R.classify(True, 1, 0, 20, "FATAL: firejail failed to start (or sandbox verification aborted), exit code 1\n",
                  "", sandbox_started=False)
assert o == R.CRASHED                                         # firejail itself failing can be a restriction
# a game's own "Error:" line after the sandbox started is not mistaken for a launcher setup problem
o, _ = R.classify(True, 1, 4, 20, "[SANDBOX-VERIFY] 30 passed, 0 failed\nError: bad thing\n", "")
assert o == R.CRASHED

# --- group_comms / sandbox_up against a fake /proc --------------------------------------------------
fake = tmp / "proc"
def fake_proc(pid, comm, pgrp):
    d = fake / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "stat").write_text(f"{pid} ({comm}) S 1 {pgrp} {pgrp} 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 1 1 1")
fake_proc(500, "bash", 500)
fake_proc(501, "firejail", 500)
fake_proc(502, "weird) name (x", 500)          # parentheses and spaces in comm
fake_proc(900, "firejail", 900)                # somebody else's sandbox: another group
(fake / "self").mkdir(exist_ok=True)           # non-numeric entries are skipped
assert R.group_comms(500, str(fake)) == {"bash", "firejail", "weird) name (x"}, R.group_comms(500, str(fake))
assert R.sandbox_up(500, str(fake)) and R.sandbox_up(900, str(fake))
assert not R.sandbox_up(501, str(fake))        # nothing has that group id
assert not R.sandbox_up(1, str(fake)) and not R.sandbox_up(0, str(fake))   # never look at init's group
(fake / "501" / "stat").unlink()                # firejail exits: the sandbox is gone, the launcher is still there
assert not R.sandbox_up(500, str(fake)) and R.group_comms(500, str(fake)) == {"bash", "weird) name (x"}
assert R.group_comms(500, str(tmp / "no-such-proc")) == set()

# --- read_trial_logs: an older run's logs are not this trial's -------------------------------------
gp = tmp / "G"
(gp / "logs").mkdir(parents=True)
old = gp / "logs" / "launch-20200101-000000.log"
old.write_text("[SANDBOX-VERIFY] FAIL: old run\n")
os.utime(old, (time.time() - 3600, time.time() - 3600))
t0 = time.time()
assert R.read_trial_logs(gp, t0) == ("", "")                 # nothing written since t0
new = gp / "logs" / "launch-20261126-000000.log"
new.write_text("wine: crash\n")
al = gp / "logs" / "alerts-20261126-000000.log"
al.write_text("[WARN] x\n")
lt, at = R.read_trial_logs(gp, t0)
assert lt == "wine: crash\n" and at == "[WARN] x\n"
assert R.read_trial_logs(tmp / "missing", t0) == ("", "")

# --- game.conf: relax and undo ----------------------------------------------------------------------
conf = tmp / "game.conf"
conf.write_text("# my game\nEXE=Game.exe\nFJ_GAME_RO=1\nFJ_SECCOMP_EXTRA=ptrace\nFJ_NOSOUND=1\n")
steps = [R.LADDER_BY_KEY[k] for k in ("FJ_GAME_RO", "FJ_SECCOMP_EXTRA", "FJ_RESTRICT_NS")]
snap = R.snapshot(conf, [s.key for s in steps])
assert snap == {"FJ_GAME_RO": ["1"], "FJ_SECCOMP_EXTRA": ["ptrace"], "FJ_RESTRICT_NS": None}, snap
for s in steps:
    R.apply_step(conf, s)
cur = core.parse_kv(conf)
assert cur["FJ_GAME_RO"] == ["0"] and cur["FJ_SECCOMP_EXTRA"] == [""] and cur["FJ_RESTRICT_NS"] == ["0"], cur
assert cur["EXE"] == ["Game.exe"] and cur["FJ_NOSOUND"] == ["1"]          # nothing else touched
assert "# my game" in conf.read_text()
# effective values now seen by the same logic the launcher mirrors
g = core.Game("T", tmp, core.parse_kv(conf))
assert not g.flag("FJ_GAME_RO", DEFAULTS) and not g.flag("FJ_RESTRICT_NS", DEFAULTS)
assert not R.is_on(g, DEFAULTS, R.LADDER_BY_KEY["FJ_SECCOMP_EXTRA"])      # empty override wins over the defaults
assert len(R.describe_changes(snap, conf)) == 3
R.restore(conf, snap)
back = core.parse_kv(conf)
assert back["FJ_GAME_RO"] == ["1"] and back["FJ_SECCOMP_EXTRA"] == ["ptrace"] and "FJ_RESTRICT_NS" not in back, back
assert back["EXE"] == ["Game.exe"] and R.describe_changes(snap, conf) == []

# --- backup file ------------------------------------------------------------------------------------
assert R.load_backup("T") is None
R.save_backup("T", conf, snap, ["FJ_GAME_RO"])
b = R.load_backup("T")
assert b and b["snapshot"] == snap and b["relaxed"] == ["FJ_GAME_RO"]
R.clear_backup("T")
assert R.load_backup("T") is None
R.clear_backup("T")                                           # clearing twice is fine
# a backup that names a key this feature never touches is not acted on
bp = R._backup_path("T")
bp.parent.mkdir(parents=True, exist_ok=True)
bp.write_text('{"snapshot": {"PRESCAN": ["0"]}}')
assert R.load_backup("T") is None
bp.write_text("not json")
assert R.load_backup("T") is None
# odd game names cannot escape the backup folder
assert R._backup_path("../../etc/x").parent == R.backup_dir()

print("test_relax: ok")
