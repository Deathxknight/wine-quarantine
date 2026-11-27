"""Qt-free logic for "Relax until it launches": a ladder of compatibility restrictions that can be
switched off one at a time, with the bookkeeping to undo all of it.

How it works: the dialog launches the game, and if it dies inside the quick-launch window it relaxes the
next step on the ladder (written to the game's own game.conf, so the real launcher and profile.sh see
exactly what a normal launch would) and tries again, until one launch survives the window.

What it never does: touch the monitoring and scanning switches (PRESCAN, YARA, CAPA, ClamAV,
MONITOR_KILL), the network settings, or the whitelists, and it never relaxes anything to get past a
pre-launch refusal, a sandbox-verifier failure or a monitor alert. Those are findings, not
compatibility problems, and loosening the sandbox does not fix them. The always-on floor
(no-new-privs, dropped capabilities, private home) is only offered as an explicit opt-in.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import wq_core as core

LOW, MEDIUM, HIGH = "low", "medium", "high"

# what it costs to switch each step off, in words. The shield score (wq_posture.PENALTY) has the numbers.
RISK_TEXT = {
    LOW: "small cost",
    MEDIUM: "moderate cost",
    HIGH: "large cost: the game can see or reach much more of your system",
}

BOOL, CLEAR = "bool", "clear"          # BOOL: set KEY=0.  CLEAR: set KEY= (empty), for a text value


@dataclass(frozen=True)
class Step:
    key: str
    label: str
    why: str                     # why Wine / Proton / a launcher commonly needs this off
    risk: str = LOW
    kind: str = BOOL
    hints: tuple[str, ...] = ()  # regexes: if a failed launch's log matches one, this step is tried first
    opt_in: bool = False         # off in the dialog until the person ticks it


# Order = the order tried when the log gives no hint: most often the culprit and cheapest first.
LADDER: tuple[Step, ...] = (
    Step("FJ_RESTRICT_NS", "Restrict namespaces",
         "Proton's runtime and many launchers create their own namespaces (bubblewrap, pressure-vessel).",
         MEDIUM, hints=(r"bwrap", r"pressure-vessel", r"unshare", r"clone\(\)", r"namespace",
                        r"setting up uid map|creating new namespace")),
    Step("FJ_MDWX", "Deny write+execute memory",
         "Wine, DXVK and every JIT map memory that is writable and executable.",
         MEDIUM, hints=(r"mprotect", r"memory-deny-write-execute", r"Permission denied.*exec",
                        r"SIGSEGV|segmentation fault")),
    Step("FJ_MEMFD", "Block memfd_create",
         "Wine, Mesa, SDL and Wayland use anonymous memory files.",
         MEDIUM, hints=(r"memfd", r"Bad system call|SIGSYS")),
    Step("FJ_SECCOMP_EXTRA", "Extra seccomp syscalls",
         "Newer Wine reads other processes' memory (process_vm_readv) and some tools use ptrace.",
         MEDIUM, kind=CLEAR, hints=(r"process_vm", r"ptrace", r"Bad system call|SIGSYS")),
    Step("FJ_GAME_RO", "Read-only game folder",
         "Games that write saves, shader caches or logs next to the exe fail on a read-only folder.",
         MEDIUM, hints=(r"[Rr]ead-only file ?system", r"EROFS", r"[Cc]annot (?:create|write|open).*for writing")),
    Step("FJ_NOSOUND", "Block audio",
         "Some engines abort when no audio device can be opened.",
         LOW, hints=(r"pulse", r"alsa", r"audio", r"snd_", r"XAudio|FAudio")),
    Step("FJ_NOINPUT", "Hide raw input devices",
         "Gamepads, force-feedback and some anti-idle code read /dev/input.",
         LOW, hints=(r"/dev/input", r"controller|gamepad|joystick|evdev|SDL_Joystick")),
    Step("FJ_IPC_NS", "Private IPC namespace",
         "MIT-SHM, which X11 games draw through, crosses SysV shared memory.",
         LOW, hints=(r"MIT-SHM|shmget|shmat", r"BadAccess|BadShmSeg", r"X Error")),
    Step("FJ_PRIVATE_DEV", "Minimal /dev",
         "GPU nodes, /dev/shm, /dev/fuse and /dev/uinput are missing from a minimal /dev.",
         MEDIUM, hints=(r"/dev/dri|/dev/nvidia|/dev/shm|/dev/fuse", r"vk[A-Z]\w+ failed|VK_ERROR|no (?:GPU|device)",
                        r"libEGL|GLX|EGL")),
    Step("FJ_NOROOT", "No root user namespace",
         "A user namespace with only your user mapped breaks tools that expect a root-mapped namespace.",
         MEDIUM, hints=(r"uid_map|gid_map|setgroups", r"Operation not permitted")),
    Step("FJ_PROTOCOL", "Only normal socket types",
         "Wine uses netlink and a few other socket families.",
         LOW, hints=(r"[Aa]ddress family not supported|EAFNOSUPPORT", r"socket.*(?:fail|denied)", r"netlink")),
    Step("FJ_PRIVATE_TMP", "Private /tmp",
         "Wine's server socket and some launchers rendezvous through /tmp.",
         LOW, hints=(r"/tmp/\.wine|/tmp/umu|/tmp/\.X11-unix", r"wineserver.*(?:connect|socket)")),
    Step("FJ_NODBUS", "Block D-Bus",
         "Some launchers and overlays expect the session bus (portals, screensaver inhibit).",
         LOW, hints=(r"dbus|D-Bus|portal",)),
    Step("FJ_NOGROUPS", "Drop supplementary groups",
         "On some systems the video / render / input groups are what grant GPU access.",
         MEDIUM, hints=(r"render node|/dev/dri.*[Pp]ermission", r"[Pp]ermission denied.*(?:video|render)")),
    Step("FJ_BLOCK_SOCKETS", "Hide host control sockets",
         "A launcher that talks to PipeWire, pulse or a gamemode daemon over a socket in /run.",
         MEDIUM, hints=(r"pipewire", r"gamemode", r"/run/user")),
    Step("FJ_XEPHYR", "Private X server (Xephyr)",
         "Fullscreen, GL and mode-setting do not always work inside the nested server. "
         "Turning it off shares your real display and keyboard with the game.",
         HIGH, hints=(r"GLX|glX", r"XOpenDisplay|[Cc]annot open display", r"RandR|XRandR|XF86VidMode")),
    # explicit opt-in only: these are the walls the whole sandbox rests on
    Step("FJ_NONEWPRIVS", "No new privileges",
         "Some setuid helpers (rare for games) cannot start with it on.",
         HIGH, opt_in=True, hints=(r"no_new_privs|setuid|sudo|pkexec",)),
    Step("FJ_CAPS_DROP", "Drop all capabilities",
         "Some launchers try to raise their own priority or open raw sockets.",
         HIGH, opt_in=True, hints=(r"CAP_\w+", r"Operation not permitted.*(?:nice|setpriority|sched)")),
    Step("FJ_PRIVATE_HOME", "Hide home directory",
         "The game looks for settings or a launcher under your real home folder.",
         HIGH, opt_in=True, hints=(r"\$HOME|/home/\w+/\.", r"[Nn]o such file.*\.config|\.local/share")),
)
LADDER_BY_KEY = {s.key: s for s in LADDER}

# never offered, whatever the log says
NEVER = frozenset({"PRESCAN", "CLAM_SCAN", "YARA_SCAN", "CAPA_SCAN", "MONITOR_KILL", "MONITOR_SYS32_SCORE",
                   "FJ_NET", "FJ_NET_OPEN", "FJ_NET_LEARN", "FJ_NET_LOG", "FJ_NET_DNS",
                   "FJ_SECCOMP", "FJ_BLOCK_MEDIA"})

# Exit codes the launcher gives for "this was not a crash": 90/91 sandbox verification failed, 97 preflight.
NOT_A_CRASH_CODES = frozenset({90, 91, 97})

# Outcomes of one trial launch
SURVIVED, CRASHED, REFUSED, ALERT, NEVER_STARTED, STOPPED = (
    "survived", "crashed", "refused", "alert", "never_started", "stopped")


def is_on(game: core.Game, defaults: dict[str, list[str]], step: Step) -> bool:
    """True when this step still restricts the game (so there is something to relax)."""
    if step.kind == CLEAR:
        return bool(game.scalar(step.key, defaults, core.TEXT_KEYS.get(step.key, "")).strip())
    if step.key not in core.ALL_BOOLS:
        return False
    return game.flag(step.key, defaults)


def plan(game: core.Game, defaults: dict[str, list[str]], include_opt_in: bool = False) -> list[Step]:
    """The steps that would change something for this game, in ladder order.

    Steps that are already off are left out."""
    out = []
    for s in LADDER:
        if s.key in NEVER or (s.opt_in and not include_opt_in):
            continue
        if is_on(game, defaults, s):
            out.append(s)
    return out


# Lines every run prints whatever the game does. The firejail banner lists the whole seccomp drop list
# (ptrace, process_vm_readv ...) and the verifier prints an "ok" per check, so matching hints against
# them would blame the wrong step every time.
_NOISE_RE = re.compile(r"^\s*(?:\[SANDBOX-VERIFY\]|Seccomp list in:|Warning: |Parent pid|Base filesystem|"
                       r"Child process initialized|firejail version|Reading profile|wq: )")


def game_side_text(log_text: str) -> str:
    """The part of a launch log that came from the game and its runtime.

    The sandbox verifier runs right before the game starts, so everything after its last line is the
    game's side. Without a verifier line (firejail itself failed to start) the whole log is used,
    minus the lines every run prints."""
    lines = core.strip_ansi(log_text or "").splitlines()
    last = max((i for i, ln in enumerate(lines) if "[SANDBOX-VERIFY]" in ln), default=-1)
    return "\n".join(ln for ln in lines[last + 1:] if not _NOISE_RE.match(ln))


def pick_next(remaining: list[Step], log_text: str) -> tuple[Step, str]:
    """Choose which remaining step to relax next -> (step, reason).

    If the failed launch's log matches a step's hint, that step goes first (the earliest in ladder
    order among the matches); otherwise it is simply the next one in ladder order."""
    if not remaining:
        raise ValueError("nothing left to relax")
    text = game_side_text(log_text)
    if text:
        for s in remaining:
            for rx in s.hints:
                m = re.search(rx, text)
                if m:
                    seen = text[max(0, m.start() - 20): m.end() + 40].replace("\n", " ").strip()
                    return s, f"the log mentions “{seen[:70]}”"
    return remaining[0], "next on the list"


# --- is the sandbox itself still running? --------------------------------------------------------
# The launcher stays alive long after the game: before it there are the pre-launch scans and prefix setup,
# after it the registry diff and the ClamAV / YARA scans. So "the launcher is running" says nothing about
# whether the game survived. The firejail process is the sandbox: it appears when the sandbox starts and
# is gone when the game ends. wq-ui starts the launcher in its own session, so everything it spawns,
# firejail included, shares its process group.


def group_comms(pgid: int, proc_root: str = "/proc") -> set[str]:
    """Names (comm) of the processes in process group `pgid`."""
    out: set[str] = set()
    try:
        names = os.listdir(proc_root)
    except OSError:
        return out
    for n in names:
        if not n.isdigit():
            continue
        try:
            raw = Path(proc_root, n, "stat").read_text(errors="replace")
        except OSError:
            continue
        lp, rp = raw.find("("), raw.rfind(")")          # comm may contain spaces and parentheses
        if lp < 0 or rp < lp:
            continue
        fields = raw[rp + 2:].split()                    # state ppid pgrp ...
        try:
            if int(fields[2]) == pgid:
                out.add(raw[lp + 1:rp])
        except (IndexError, ValueError):
            continue
    return out


def sandbox_up(pgid: int, proc_root: str = "/proc") -> bool:
    return pgid > 1 and "firejail" in group_comms(pgid, proc_root)


# --- reading one trial's logs ---------------------------------------------------------------------


def _newest_since(logs: Path, pattern: str, since: float) -> Path | None:
    best, best_t = None, since
    try:
        for p in logs.glob(pattern):
            try:
                t = p.stat().st_mtime
            except OSError:
                continue
            if t >= best_t:
                best, best_t = p, t
    except OSError:
        return None
    return best


def read_trial_logs(game_path: Path | str, since: float, tail_bytes: int = 48_000) -> tuple[str, str]:
    """(launch log text, alert log text) of the run that started at or after `since` (unix time).

    Only logs written during this trial count: an older run's verdict must never be mistaken for it.
    Slightly lenient on the clock (filesystems round times) so a log created right at the start still counts."""
    logs = Path(game_path) / "logs"
    since = since - 2.0
    launch_p = _newest_since(logs, "launch-*.log", since)
    alert_p = _newest_since(logs, "alerts-*.log", since)

    def read(p: Path | None, tail: bool) -> str:
        if p is None:
            return ""
        try:
            with p.open("rb") as f:
                if tail:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - tail_bytes))
                return f.read(tail_bytes if tail else 4 * tail_bytes).decode("utf-8", "replace")
        except OSError:
            return ""
    return read(launch_p, tail=False), read(alert_p, tail=True)


_SETUP_RE = re.compile(r"^(?:FATAL: (?!firejail failed to start)|Error: |\[launcher\] umu runtime is not downloaded).*$", re.M)


def classify(exited: bool, exit_code: int | None, ran_seconds: float, window: float,
             launch_text: str, alert_text: str, stopped_by_user: bool = False,
             sandbox_started: bool = True) -> tuple[str, str]:
    """-> (outcome, explanation) for one trial.

    `exited` False means the sandbox was still running when the quick-launch window ended.
    `sandbox_started` False means the firejail process never appeared (the launcher ended first)."""
    if stopped_by_user:
        return STOPPED, "You stopped this launch."
    clean_launch = core.strip_ansi(launch_text or "")
    status, vtext = core.run_verdict(clean_launch, alert_text or "")
    if status in ("leak", "blocked") or (exit_code in NOT_A_CRASH_CODES):
        why = {"leak": "the sandbox check found a leak", "blocked": "the pre-launch checks refused the launch"}.get(
            status, f"the launcher stopped before the game started (code {exit_code})")
        return REFUSED, (f"Not a compatibility problem: {why}. Relaxing the sandbox would not help. "
                         "Look at the Runs tab and the launch log first.")
    if status == "alert":
        return ALERT, (f"The monitor raised an alert ({vtext}). That is a finding about the game, so nothing was "
                       "relaxed. Review it on the Monitor tab before trying again.")
    if not exited:
        return SURVIVED, f"The sandbox was still running after {window:.0f} s."
    if not sandbox_started:
        m = _SETUP_RE.search(clean_launch)
        if m:
            return REFUSED, (f"Not a compatibility problem: the launcher stopped before the sandbox started "
                             f"(“{m.group(0).strip()[:100]}”). Relaxing the sandbox would not help.")
        if "firejail failed to start" not in clean_launch:
            return NEVER_STARTED, ("The launcher ended before the sandbox started, and the log does not say why. "
                                   "Nothing was relaxed. Check the console and the launch log.")
    return CRASHED, f"The sandbox ended after {ran_seconds:.0f} s" + (f" (launcher code {exit_code})." if exit_code is not None else ".")


# --- changing game.conf, and undoing it ----------------------------------------------------------


def relax_value(step: Step) -> str:
    return "0" if step.kind == BOOL else ""


def snapshot(conf_path: Path, keys: list[str]) -> dict[str, list[str] | None]:
    """The lines game.conf has for each key right now: a list, or None when the key is absent
    (the game inherits the default). Restoring this puts game.conf back exactly."""
    cur = core.parse_kv(conf_path)
    return {k: (list(cur[k]) if k in cur else None) for k in keys}


def apply_step(conf_path: Path, step: Step) -> None:
    core.write_kv(conf_path, {step.key: relax_value(step)})


def restore(conf_path: Path, snap: dict[str, list[str] | None]) -> None:
    core.write_kv(conf_path, {k: v for k, v in snap.items()})


# The backup lives outside the game folder (and so outside anything the game can write), so a crash
# in the middle of a session does not leave a game quietly relaxed with nothing to undo it.
def backup_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "wq-ui" / "relax"


def _backup_path(game_name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", game_name)[:80] or "game"
    return backup_dir() / f"{safe}.json"


def save_backup(game_name: str, conf_path: Path, snap: dict[str, list[str] | None], relaxed: list[str]) -> None:
    p = _backup_path(game_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {"game": game_name, "conf": str(conf_path), "time": time.time(), "snapshot": snap, "relaxed": relaxed}
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".relax-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_backup(game_name: str) -> dict | None:
    try:
        data = json.loads(_backup_path(game_name).read_text())
    except (OSError, ValueError):
        return None
    snap = data.get("snapshot")
    if not isinstance(snap, dict) or not all(
            k in LADDER_BY_KEY and (v is None or (isinstance(v, list) and all(isinstance(x, str) for x in v)))
            for k, v in snap.items()):
        return None                      # not something this feature wrote: ignore it rather than act on it
    return data


def clear_backup(game_name: str) -> None:
    try:
        _backup_path(game_name).unlink()
    except OSError:
        pass


def describe_changes(snap: dict[str, list[str] | None], conf_path: Path) -> list[str]:
    """Human-readable list of what differs between the snapshot and game.conf now."""
    cur = core.parse_kv(conf_path)
    out = []
    for k, old in snap.items():
        new = cur.get(k)
        if new != old:
            label = LADDER_BY_KEY[k].label if k in LADDER_BY_KEY else k
            out.append(f"{label}: {'default' if old is None else ','.join(old) or 'empty'} → "
                       f"{'default' if new is None else ','.join(new) or 'empty'}")
    return out
