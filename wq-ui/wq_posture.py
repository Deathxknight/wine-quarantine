"""Qt-free "shield" score for a game's sandbox profile.

The game list shows a ring with a number from 0 to 100 next to every game. It answers one
question at a glance: how much of the sandbox is still switched on for this game? It reads the
same effective settings the launcher does (game.conf, else profile.defaults.conf, else stock),
so it can't drift from what actually runs.

It is a summary of the profile, not a measurement. It says nothing about whether the sandbox
works (verify-sandbox.sh and Test sandbox do that) or about whether the game is hostile. A
score of 100 means "every switch is on and nothing is exposed", not "safe".

Each relaxed setting costs points. The weights are in PENALTY and are deliberately blunt:
things that let a game see or touch your real data (home folder, display, network, writable
host folders, scripts that run outside the sandbox) cost the most, comfort switches such as
audio cost almost nothing. Everything is plain data, so the numbers are easy to argue with and
change.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

import wq_core as core

# points lost when the setting is NOT in its protective state
# (key, penalty, short title, runner or "" for both)
PENALTY: tuple[tuple[str, int, str, str], ...] = (
    ("FJ_PRIVATE_HOME", 14, "Your home folder is visible", ""),
    ("FJ_SECCOMP", 10, "No syscall filter", ""),
    ("FJ_XEPHYR", 10, "Shares your display (host X11)", ""),
    ("FJ_CAPS_DROP", 8, "Keeps Linux capabilities", ""),
    ("FJ_NONEWPRIVS", 8, "Can gain privileges", ""),
    ("FJ_NODBUS", 6, "D-Bus reachable", ""),
    ("FJ_BLOCK_SOCKETS", 6, "Host control sockets visible", ""),
    ("MONITOR_KILL", 6, "Alerts don't stop the game", ""),
    ("FJ_NOINPUT", 5, "Raw input devices visible", ""),
    ("FJ_NOGROUPS", 4, "Inherits your group memberships", ""),
    ("FJ_PRIVATE_TMP", 4, "Shares /tmp", ""),
    ("FJ_PRIVATE_DEV", 4, "Full /dev visible", ""),
    ("FJ_BLOCK_MEDIA", 4, "Other drives visible", ""),
    ("FJ_NOVIDEO", 4, "Webcams visible", ""),
    ("FJ_NOU2F", 3, "Security keys visible", ""),
    ("FJ_NOTV", 1, "TV / DVB devices visible", ""),
    ("FJ_NODVD", 1, "Optical drives visible", ""),
    ("FJ_GAME_RO", 3, "Game can patch its own files", ""),
    ("FJ_PROTOCOL", 3, "Unusual socket families allowed", ""),
    ("FJ_IPC_NS", 2, "Shares host shared memory / IPC", ""),
    # Wine/Proton usually need these three off, but that is a compatibility trade, not a free pass: switching
    # them off (by hand, by a preset, or with Relax) weakens the sandbox for every runner, so every runner pays.
    ("FJ_MEMFD", 2, "Fileless execution (memfd_create) allowed", ""),
    ("FJ_MDWX", 3, "Memory can be writable and executable", ""),
    ("FJ_RESTRICT_NS", 3, "Can create namespaces", ""),
    ("PRESCAN", 4, "No pre-launch scan", ""),
    ("CLAM_SCAN", 3, "No ClamAV scan after runs", ""),
    ("MONITOR_SYS32_SCORE", 1, "system32 changes aren't scored", ""),
    ("YARA_SCAN", 2, "No YARA scan", ""),
    ("CAPA_SCAN", 1, "No capa behaviour scan", ""),
    ("FJ_MACHINE_ID", 2, "Can recognise this PC", ""),
    ("FJ_NOROOT", 1, "Sees the real user namespace", ""),
    ("FJ_NOSOUND", 1, "Audio devices visible", ""),
)
PENALTY_BY_KEY = {k: (pts, title, runner) for k, pts, title, runner in PENALTY}

NET_PENALTY = {"off": 0, "filtered": 6, "learn": 30, "open": 45}
NET_TITLE = {
    "filtered": "Network on (filtered)",
    "learn": "Network in learn mode (everything allowed)",
    "open": "Network wide open",
}
DNS_PENALTY = 3
WIDE_ENTRY_PENALTY = 4          # per allow-list entry that is a big range or any port
WIDE_ENTRY_CAP = 8
WL_RW_EACH, WL_RW_CAP, WL_RW_HOME = 5, 15, 25
WL_RO_EACH, WL_RO_CAP, WL_RO_HOME = 1, 4, 10
HOOK_EACH = 6

GRADES = ((90, "A"), (75, "B"), (55, "C"), (35, "D"), (0, "F"))
OK_AT, WARN_AT = 75, 55         # ring colour: green, amber, red


@dataclass(frozen=True)
class Finding:
    key: str
    severity: str        # bad | warn | info
    title: str
    detail: str
    penalty: int


@dataclass(frozen=True)
class Posture:
    score: int
    grade: str
    status: str          # ok | warn | bad (same words the theme uses for text colours)
    findings: tuple[Finding, ...]

    def headline(self) -> str:
        if not self.findings:
            return "Every protection is on"
        n = len(self.findings)
        return f"{n} thing{'s' if n != 1 else ''} weaken{'' if n != 1 else 's'} the sandbox"

    def tooltip(self, name: str = "", limit: int = 6) -> str:
        head = f"{name}: " if name else ""
        lines = [f"{head}shield {self.score}/100 (grade {self.grade}) - {self.headline()}"]
        for f in self.findings[:limit]:
            lines.append(f"  -{f.penalty}  {f.title}")
        if len(self.findings) > limit:
            rest = sum(f.penalty for f in self.findings[limit:])
            lines.append(f"  -{rest}  {len(self.findings) - limit} more")
        lines.append("A summary of the profile, not a safety guarantee.")
        return "\n".join(lines)


@dataclass
class PostureInputs:
    """Resolved settings. flags: key -> True/False, or None when the games being shown differ
    (counted as relaxed, same rule as wq_core.is_relaxed)."""
    flags: dict[str, bool | None]
    runner: str = "wine"
    wl_rw: tuple[str, ...] = ()
    wl_ro: tuple[str, ...] = ()
    net_allow: tuple[str, ...] = ()
    hooks: int = 0
    home: str = ""


def inputs_from_game(g: core.Game, defaults: dict[str, list[str]], home: str | None = None) -> PostureInputs:
    keys = [k for k, *_ in PENALTY] + ["FJ_NET", "FJ_NET_OPEN", "FJ_NET_LEARN", "FJ_NET_DNS", "FJ_XEPHYR"]
    flags = {k: g.flag(k, defaults) for k in dict.fromkeys(keys)}
    hooks = sum(1 for k in ("FJ_HOOK_PRE", "FJ_HOOK_POST") if g.conf.get(k) and any(v.strip() for v in g.conf[k]))
    return PostureInputs(
        flags=flags, runner=g.runner,
        wl_rw=tuple(g.effective_lines("FJ_WL_RW", defaults)),
        wl_ro=tuple(g.effective_lines("FJ_WL_RO", defaults)),
        net_allow=tuple(g.effective_lines("FJ_NET_ALLOW", defaults)),
        hooks=hooks, home=home if home is not None else os.path.expanduser("~"))


def net_mode_of(flags: dict[str, bool | None]) -> str:
    """off | filtered | learn | open. A network switch the selected games disagree on (None)
    counts as on, and only an explicit open/learn switch raises it further."""
    if flags.get("FJ_NET", False) is False:
        return "off"
    if flags.get("FJ_NET_OPEN") is True:
        return "open"
    return "learn" if flags.get("FJ_NET_LEARN") is True else "filtered"


def _covers_home(path: str, home: str) -> bool:
    """Is path your home folder, or a parent of it (/, /home, ...)?"""
    if not path.startswith("/") or not home:
        return False
    p, h = os.path.normpath(path), os.path.normpath(home)
    return p == h or h.startswith(p.rstrip("/") + "/") or p == "/"


def _wide(entry: str) -> bool:
    """An allow-list entry that opens a lot: a range of 65k+ addresses, or any port."""
    m = core.ALLOW_RE.match(entry)
    if not m:
        return False
    try:
        net = ipaddress.ip_network(m.group(2), strict=False)
    except ValueError:
        return False
    return net.prefixlen <= 16 or m.group(3) == "*"


def score(inp: PostureInputs) -> Posture:
    found: list[Finding] = []

    def add(key: str, severity: str, title: str, detail: str, pts: int) -> None:
        if pts > 0:
            found.append(Finding(key, severity, title, detail, pts))

    for key, pts, title, runner in PENALTY:
        if runner and runner != inp.runner:
            continue
        state = inp.flags.get(key)
        if state is True:
            continue
        sev = "bad" if pts >= 8 else "warn" if pts >= 4 else "info"
        detail = core.PLAIN.get(key, "")
        if state is None:
            detail = "The selected games disagree on this. " + detail
        add(key, sev, title, detail, pts)

    mode = net_mode_of(inp.flags)
    base = NET_PENALTY[mode]
    if base:
        add("FJ_NET", "bad" if base >= 30 else "warn", NET_TITLE[mode], core.PLAIN.get(
            {"filtered": "FJ_NET", "learn": "FJ_NET_LEARN", "open": "FJ_NET_OPEN"}[mode], ""), base)
    if mode != "off" and inp.flags.get("FJ_NET_DNS"):
        add("FJ_NET_DNS", "warn", "Name lookups allowed", core.PLAIN["FJ_NET_DNS"], DNS_PENALTY)
    if mode == "filtered":
        wide = [e for e in inp.net_allow if _wide(e)]
        if wide:
            add("FJ_NET_ALLOW", "warn", f"{len(wide)} wide allow-list entr{'ies' if len(wide) != 1 else 'y'}",
                "Large ranges or any-port entries let a game talk to far more than one server: "
                + ", ".join(wide[:3]) + (" ..." if len(wide) > 3 else ""),
                min(WIDE_ENTRY_CAP, WIDE_ENTRY_PENALTY * len(wide)))

    rw_home = [p for p in inp.wl_rw if _covers_home(p, inp.home)]
    if rw_home:
        add("FJ_WL_RW", "bad", "Your whole home folder is writable",
            f"{rw_home[0]} is whitelisted read-write, which undoes 'hide home directory'.", WL_RW_HOME)
    elif inp.wl_rw:
        add("FJ_WL_RW", "warn", f"{len(inp.wl_rw)} extra writable folder{'s' if len(inp.wl_rw) != 1 else ''}",
            "Anything the game writes there stays on your PC: " + ", ".join(inp.wl_rw[:3])
            + (" ..." if len(inp.wl_rw) > 3 else ""), min(WL_RW_CAP, WL_RW_EACH * len(inp.wl_rw)))
    ro_home = [p for p in inp.wl_ro if _covers_home(p, inp.home)]
    if ro_home:
        add("FJ_WL_RO", "warn", "Your whole home folder is readable",
            f"{ro_home[0]} is whitelisted read-only: the game can read your files.", WL_RO_HOME)
    elif inp.wl_ro:
        add("FJ_WL_RO", "info", f"{len(inp.wl_ro)} extra readable folder{'s' if len(inp.wl_ro) != 1 else ''}",
            "The game can read: " + ", ".join(inp.wl_ro[:3]) + (" ..." if len(inp.wl_ro) > 3 else ""),
            min(WL_RO_CAP, WL_RO_EACH * len(inp.wl_ro)))
    if inp.hooks:
        add("FJ_HOOK", "bad", f"{inp.hooks} launch script{'s' if inp.hooks != 1 else ''} run outside the sandbox",
            "Before-launch and after-exit scripts run as you, on your machine, with no sandbox.",
            HOOK_EACH * inp.hooks)

    found.sort(key=lambda f: (-f.penalty, f.title))
    total = max(0, 100 - sum(f.penalty for f in found))
    grade = next(g for floor, g in GRADES if total >= floor)
    status = "ok" if total >= OK_AT else "warn" if total >= WARN_AT else "bad"
    return Posture(total, grade, status, tuple(found))


def posture_for_game(g: core.Game, defaults: dict[str, list[str]], home: str | None = None) -> Posture:
    return score(inputs_from_game(g, defaults, home))
