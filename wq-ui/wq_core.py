"""Qt-free logic for wq-ui: game.conf IO, game discovery, path checks,
firejail trace parsing and CSS token handling. Kept separate so it can be
tested without a display."""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULTS_NAME = "profile.defaults.conf"

# options


@dataclass(frozen=True)
class BoolOpt:
    key: str
    label: str
    default: bool          # matches the stock wine-quarantine sandbox
    tip: str
    group: str


BOOL_OPTS: list[BoolOpt] = [
    BoolOpt("FJ_PRIVATE_HOME", "Hide home directory", True, "$HOME is an empty tmpfs; only whitelisted paths show up (--private).", "isolation"),
    BoolOpt("FJ_PRIVATE_TMP", "Private /tmp", True, "Own empty /tmp (--private-tmp)", "isolation"),
    BoolOpt("FJ_NONEWPRIVS", "No new privileges", True, "No privilege gain via setuid etc. (--nonewprivs)", "isolation"),
    BoolOpt("FJ_CAPS_DROP", "Drop all capabilities", True, "Drops all Linux capabilities (--caps.drop=all)", "isolation"),
    BoolOpt("FJ_NODBUS", "Block D-Bus", True, "No D-Bus access (--nodbus)", "isolation"),
    BoolOpt("FJ_SECCOMP", "Seccomp syscall filter", True, "Blocks risky syscalls. The list is SECCOMP_DROP in config.sh.", "isolation"),
    BoolOpt("FJ_NOROOT", "No root user namespace", False, "User namespace with only your user mapped (--noroot).", "isolation"),
    BoolOpt("FJ_MACHINE_ID", "Spoof machine-id", True, "Random /etc/machine-id instead of this PC's (--machine-id).", "isolation"),
    BoolOpt("FJ_NOGROUPS", "Drop supplementary groups", True,
            "Game runs without docker/input/libvirt/wheel... group membership (--nogroups). "
            "Firejail ignores this on NVIDIA systems.", "isolation"),
    BoolOpt("FJ_PRIVATE_DEV", "Minimal /dev", True,
            "Only a small set of device nodes instead of the host's /dev (--private-dev).", "isolation"),
    BoolOpt("FJ_NOINPUT", "Hide raw input devices", True,
            "Hides /dev/input/*, so a game can't read keystrokes system-wide (--noinput). "
            "Turn off for gamepads/joysticks that need evdev.", "isolation"),
    BoolOpt("FJ_BLOCK_SOCKETS", "Hide host control sockets", True,
            "Hides docker/podman/libvirt/containerd/systemd, gpg/ssh-agent and resolver sockets. "
            "Resolver sockets stay visible in unrestricted network mode.", "isolation"),
    BoolOpt("FJ_RESTRICT_NS", "Restrict namespaces", False,
            "Blocks creating new namespaces (--restrict-namespaces). On by default for native games, "
            "off for Wine/Proton games (pressure-vessel and some launchers need namespaces).", "isolation"),
    BoolOpt("FJ_IPC_NS", "Private IPC namespace", True,
            "Own SysV shared memory, semaphores and message queues, so the game can't see the host's (--ipc-namespace). "
            "Turn off only if a game draws nothing under the private X server.", "isolation"),
    BoolOpt("FJ_PROTOCOL", "Only normal socket types", True,
            "Allows unix, inet, inet6 and netlink sockets only (--protocol). Raw packet, vsock, bluetooth, AF_ALG and "
            "other unusual families, where kernel exploits have come in, are refused.", "isolation"),
    BoolOpt("FJ_MEMFD", "Block memfd_create (fileless exec)", False,
            "Blocks memfd_create with seccomp, so a program can't build an executable in anonymous memory and run it "
            "without touching disk. Many Wine/Proton games, Mesa, SDL and Wayland clients use memfd_create, so turn it "
            "on for native games or one game at a time. Needs the seccomp filter on.", "isolation"),
    BoolOpt("FJ_MDWX", "Deny write+execute memory", False,
            "Memory can't be writable and executable at once, and a program can't add execute to memory it wrote "
            "(--memory-deny-write-execute). Stops in-process shellcode and loaders. Wine/Proton, DXVK and every JIT "
            "(Mono, Java, JavaScript engines) need that, so turn it on for native games without a JIT.", "isolation"),
    BoolOpt("FJ_BLOCK_MEDIA", "Hide other drives", True,
            "Hides /media, /run/media and /mnt (USB sticks and other mounted disks). "
            "Skipped for any of them that contains the game, umu data or a whitelisted path.", "isolation"),
    BoolOpt("FJ_GAME_RO", "Read-only game folder", False,
            "Mounts game/ read-only so a game can't patch its own files or leave payloads between runs. "
            "Wine saves go to the prefix, but native games that save inside game/ will fail to save.", "isolation"),
    BoolOpt("FJ_NOSOUND", "Block audio", False, "No audio devices (--nosound)", "devices"),
    BoolOpt("FJ_NOVIDEO", "Block webcams", False, "No webcams (--novideo)", "devices"),
    BoolOpt("FJ_NOU2F", "Block U2F / security keys", False, "No security keys (--nou2f)", "devices"),
    BoolOpt("FJ_NOTV", "Block TV / DVB devices", False, "No TV/DVB devices (--notv)", "devices"),
    BoolOpt("FJ_NODVD", "Block optical drives", False, "No optical drives (--nodvd)", "devices"),
    BoolOpt("PRESCAN", "Pre-launch scan", True,
            "Before the sandbox starts: ClamAV, out-of-date signature check and static checks for packed or "
            "disguised programs. A bad result refuses the launch (PRESCAN=0 turns it off).",
            "monitoring"),
    BoolOpt("CLAM_SCAN", "ClamAV scan after each run", True,
            "Scans what the run changed with clamscan (CLAM_SCAN=0 turns it off). "
            "Wine games: first-run bootstrap files are skipped.",
            "monitoring"),
    BoolOpt("YARA_SCAN", "YARA scan", True,
            "Matches the game's files against the bundled YARA rules (signature-base, Yara-Rules) before launch "
            "and again for what a run changed. Needs the yara package: ticked without it, the launch is refused. "
            "The ruleset builds itself on first use (YARA_SCAN=0 turns it off). High-risk rule matches refuse the launch, medium ones are warnings, informational ones (packer/file-type rules) are one quiet line (YARA_LEVEL=AUTO; WARN or ALERT treat every match alike).",
            "monitoring"),
    BoolOpt("CAPA_SCAN", "capa behaviour scan", True,
            "Before launch, runs capa with the bundled capa-rules on the game's executables and flags startup "
            "persistence and keylogging behaviour. Needs the capa program: ticked without it, the launch is refused "
            "(CAPA_SCAN=0 turns it off).",
            "monitoring"),
    BoolOpt("MONITOR_KILL", "Alerts stop the sandbox", True,
            "On: the first ALERT kills the sandbox. Off: alerts are logged but the game keeps "
            "running (MONITOR_KILL=0).",
            "monitoring"),
    BoolOpt("MONITOR_SYS32_SCORE", "Score system32 changes instead of stopping", False,
            "On: a system32 change that is not Proton's own file adds PRESCAN_SYS32_POINTS (5, the launch "
            "limit) to the game's score and the game keeps running. The next launch is refused until the "
            "log is reviewed and logs/.run-score deleted. Proton's own files are never counted.",
            "monitoring"),
]
BOOL_BY_KEY = {o.key: o for o in BOOL_OPTS}

# --- presets and UI grouping --------------------------------------------------
# Rarely changed isolation options, shown under "Advanced" in the Protection tab.
ADVANCED_KEYS = ("FJ_MACHINE_ID", "FJ_RESTRICT_NS", "FJ_NOROOT", "FJ_PRIVATE_DEV", "FJ_NOINPUT",
                 "FJ_BLOCK_SOCKETS", "FJ_NOGROUPS", "FJ_IPC_NS", "FJ_PROTOCOL", "FJ_MEMFD", "FJ_MDWX")
# On in every preset: turning these off is possible, but it is never part of a preset.
PRESET_FLOOR = ("FJ_PRIVATE_HOME", "FJ_PRIVATE_TMP", "FJ_NONEWPRIVS", "FJ_CAPS_DROP", "FJ_NODBUS", "FJ_SECCOMP",
                "FJ_MACHINE_ID", "FJ_BLOCK_SOCKETS", "FJ_NOGROUPS", "FJ_PRIVATE_DEV", "FJ_BLOCK_MEDIA",
                "FJ_IPC_NS", "FJ_PROTOCOL",
                "CLAM_SCAN", "YARA_SCAN", "CAPA_SCAN", "MONITOR_KILL", "PRESCAN")
_STRICT = {o.key: True for o in BOOL_OPTS}
_STRICT.update({"FJ_NET": False, "FJ_NET_OPEN": False, "FJ_NET_LEARN": False})
_BALANCED = {**_STRICT, "FJ_GAME_RO": False, "FJ_RESTRICT_NS": False, "FJ_NOSOUND": False, "FJ_MEMFD": False, "FJ_MDWX": False}
_COMPAT = {**_BALANCED, "FJ_NOINPUT": False, "FJ_NOROOT": False, "FJ_NET": True}
PRESETS: dict[str, dict[str, bool]] = {"Strict": _STRICT, "Balanced": _BALANCED, "Compatibility": _COMPAT}
PRESET_NOTES = {
    "Strict": "Everything on, no network. Wine and Proton games usually need Balanced.",
    "Balanced": "Read-only game folder, audio blocking, namespace restriction, memfd blocking and write+execute denial are off. Works for most games.",
    "Compatibility": "Balanced, plus gamepads and a filtered network connection (pick an interface in Network).",
}


def preset_match(states: dict[str, bool | None]) -> str:
    """Name of the preset the given box states equal, else \"Custom\". None = games differ."""
    for name, want in PRESETS.items():
        if all(states.get(k) is v for k, v in want.items()):
            return name
    return "Custom"


def is_relaxed(key: str, state: bool | None) -> bool:
    """True when a setting is weaker than Strict. Games that disagree (None) count as relaxed."""
    want = PRESETS["Strict"].get(key)
    return want is not None and (state is None or state != want)


PLAIN = {
    "FJ_PRIVATE_HOME": "The game sees an empty private home folder instead of yours.",
    "FJ_PRIVATE_TMP": "The game gets its own empty /tmp, so it can't read other programs' temp files.",
    "FJ_NONEWPRIVS": "Stops the game from gaining extra privileges, for example through setuid programs.",
    "FJ_CAPS_DROP": "Removes all special Linux powers from the game's processes.",
    "FJ_NODBUS": "Blocks access to the desktop message bus, which controls many system services.",
    "FJ_SECCOMP": "Blocks a list of risky system calls (the list is SECCOMP_DROP in config.sh).",
    "FJ_NOROOT": "The game runs in a user namespace where only your user exists.",
    "FJ_MACHINE_ID": "The game sees a random machine ID, so it can't recognise this PC.",
    "FJ_NOGROUPS": "The game doesn't inherit your group memberships (docker, input, wheel and so on).",
    "FJ_PRIVATE_DEV": "The game sees a short list of device files instead of everything in /dev.",
    "FJ_NOINPUT": "Hides raw keyboard and mouse devices so the game can't log keystrokes system-wide. Gamepads may need this off.",
    "FJ_BLOCK_SOCKETS": "Hides the sockets used to control docker, libvirt, gpg-agent, ssh-agent and similar.",
    "FJ_RESTRICT_NS": "Stops the game from creating new namespaces. Wine and Proton launchers often need this off.",
    "FJ_BLOCK_MEDIA": "Hides USB sticks and other mounted drives.",
    "FJ_IPC_NS": "The game gets its own shared-memory and message-queue space, so it can't reach the host's.",
    "FJ_MEMFD": "The game can't create anonymous in-memory files, which is how payloads run without touching disk. Many Wine and Proton games need this off.",
    "FJ_MDWX": "Memory can't be both writable and executable, so a program can't write code into memory and run it. Wine, Proton and anything with a JIT need this off.",
    "FJ_PROTOCOL": "The game can only open ordinary sockets (unix, internet, netlink), not the unusual kinds exploits have used.",
    "FJ_GAME_RO": "The game folder can't be changed, so a game can't patch itself. Games that save inside it will fail to save.",
    "FJ_NOSOUND": "No sound in the game.",
    "FJ_NOVIDEO": "The game can't use webcams.",
    "FJ_NOU2F": "The game can't talk to security keys.",
    "FJ_NOTV": "The game can't use TV tuner devices.",
    "FJ_NODVD": "The game can't use optical drives.",
    "PRESCAN": "Checks the game's files before it starts and refuses to launch it if they look like malware.",
    "CLAM_SCAN": "Scans the files the game changed with ClamAV after each run.",
    "YARA_SCAN": "Checks the game's files against the bundled YARA rules before it starts and after each run.",
    "CAPA_SCAN": "Runs capa on the game's programs before it starts and flags persistence and keylogging behaviour.",
    "MONITOR_KILL": "Stops the game as soon as the monitor raises an alert.",
    "MONITOR_SYS32_SCORE": "Unlisted system32 changes add points to the game's score instead of stopping the game.",
    "FJ_NET": "Gives the game a network connection behind a default-deny filter.",
    "FJ_NET_OPEN": "Removes all network filtering. The game can reach anything you can.",
    "FJ_NET_DNS": "Lets the game look up host names.",
    "FJ_NET_LOG": "Records the game's connection attempts so you can review them.",
    "FJ_NET_LEARN": "Allows every connection and logs it, to build a whitelist from.",
    "FJ_XEPHYR": "Runs the game in its own X server window so it can't see your screen or keystrokes.",
}

NET_BOOLS: dict[str, bool] = {
    "FJ_NET": False,        # network enabled at all
    "FJ_NET_OPEN": False,   # ...and unfiltered
    "FJ_NET_DNS": False,
    "FJ_NET_LOG": False,
    "FJ_NET_LEARN": False,  # filtered, but everything is allowed (and logged)
    "FJ_XEPHYR": False,
}
ALL_BOOLS: dict[str, bool] = {**{o.key: o.default for o in BOOL_OPTS}, **NET_BOOLS}
TEXT_KEYS = {"FJ_NET_IFACE": "", "FJ_XEPHYR_SIZE": "", "FJ_TASKS_MAX": "", "FJ_MEMORY_MAX": "", "FJ_SECCOMP_EXTRA": ""}
TEXT_HINTS = {
    "FJ_NET_IFACE": "e.g. enp5s0 or br0",
    "FJ_XEPHYR_SIZE": "WIDTHxHEIGHT",
    "FJ_TASKS_MAX": "empty = no limit, e.g. 4096",
    "FJ_MEMORY_MAX": "empty = no limit, e.g. 8G",
    "FJ_SECCOMP_EXTRA": "extra syscalls, comma separated",
}
EXTRA_ARGS_KEY = "FJ_EXTRA_ARGS"      # free-form firejail options, one per line, allow-listed
LIST_KEYS = ("FJ_NET_ALLOW", "FJ_WL_RW", "FJ_WL_RO", "FJ_DEV_BLOCK", "FJ_HOOK_PRE", "FJ_HOOK_POST", EXTRA_ARGS_KEY)
# everything "Reset to defaults" clears from game.conf (FJ_EXTRA_ARGS is a list, but it is
# part of the profile, unlike the whitelists / hooks, which are kept)
MANAGED_SCALARS = tuple(ALL_BOOLS) + tuple(TEXT_KEYS) + (EXTRA_ARGS_KEY,)

# KEY=value files (read as data, same as read_game_conf in config.sh)


def parse_kv(path: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        k, v = line.split("=", 1)
        out.setdefault(k.strip(), []).append(v.rstrip("\r"))
    return out


def write_kv(path: Path, updates: dict[str, list[str] | str | None]) -> None:
    """Rewrite `path`, replacing/removing the given keys and leaving every
    other line (EXE=, comments, ...) untouched. None removes the key."""
    try:
        old = path.read_text(errors="replace").splitlines()
    except OSError:
        old = []
    norm: dict[str, list[str]] = {}
    for k, v in updates.items():
        if v is None:
            norm[k] = []
        elif isinstance(v, str):
            norm[k] = [v]
        else:
            norm[k] = list(v)
    for k, vs in norm.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", k):
            raise ValueError(f"bad key {k!r}")
        for v in vs:
            if "\n" in v or "\r" in v:
                raise ValueError(f"newline in value for {k}")

    placed: set[str] = set()
    out: list[str] = []
    for line in old:
        k = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
        if k in norm:
            if k not in placed:
                out.extend(f"{k}={v}" for v in norm[k])
                placed.add(k)
            continue          # drop the old line (and any duplicates)
        out.append(line)
    for k, vs in norm.items():
        if k not in placed:
            out.extend(f"{k}={v}" for v in vs)

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".wq-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(out) + ("\n" if out else ""))
        try:
            os.chmod(tmp, path.stat().st_mode & 0o777)
        except OSError:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# games


@dataclass
class Game:
    name: str
    path: Path
    conf: dict[str, list[str]] = field(default_factory=dict)
    has_launcher: bool = False

    @property
    def exe(self) -> str:
        v = self.conf.get("EXE", [""])
        return v[0] if v else ""

    @property
    def runner(self) -> str:
        """"wine" or "native" (RUNNER=native in game.conf)."""
        v = self.conf.get("RUNNER", [""])
        return "native" if v and v[0] == "native" else "wine"

    @property
    def exe_ready(self) -> bool:
        return bool(self.exe) and self.exe not in ("CHANGE_ME.exe", "CHANGE_ME.sh")

    def scalar(self, key: str, defaults: dict[str, list[str]], builtin: str) -> str:
        """game.conf > profile.defaults.conf > builtin (first value wins)."""
        for src in (self.conf, defaults):
            vals = src.get(key)
            if vals:
                return vals[0]
        return builtin

    def flag(self, key: str, defaults: dict[str, list[str]]) -> bool:
        builtin = ALL_BOOLS[key]
        if key == "FJ_RESTRICT_NS" and self.runner == "native":
            builtin = True                 # same runner-dependent default as profile.sh
        return self.scalar(key, defaults, "1" if builtin else "0") == "1"

    def effective_lines(self, key: str, defaults: dict[str, list[str]]) -> list[str]:
        """Non-blank values of a list key. If game.conf has the key at all (even as an
        empty `KEY=` line, which means "none, ignore the defaults") it wins, otherwise
        the defaults file is used. profile.sh does the same."""
        src = self.conf if key in self.conf else defaults
        return [v.strip() for v in src.get(key, []) if v.strip()]

    def net_mode(self, defaults: dict[str, list[str]]) -> str:
        if not self.flag("FJ_NET", defaults):
            return "off"
        if self.flag("FJ_NET_OPEN", defaults):
            return "open"
        return "learn" if self.flag("FJ_NET_LEARN", defaults) else "filtered"


def scan_games(qroot: Path) -> list[Game]:
    games: list[Game] = []
    try:
        entries = sorted(qroot.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return games
    for d in entries:
        if d.name.startswith(("_", ".")) or not d.is_dir():
            continue
        if not (d / "game").is_dir():       # same test _launch-core.sh uses
            continue
        games.append(Game(d.name, d, parse_kv(d / "game.conf"), (d / "launch-quarantine.sh").exists()))
    return games


# paths

# firejail --whitelist only works under $HOME and these top-level dirs
WHITELIST_TOPS = {"/dev", "/media", "/mnt", "/opt", "/srv", "/sys", "/tmp", "/var"}
SYSTEM_TOPS = {"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/proc", "/run"}


def classify_path(p: str | Path, home: str | Path | None = None) -> tuple[str, str]:
    """-> (kind, explanation); kind in home|ok|system|unsupported|missing"""
    home = os.path.realpath(home or Path.home())
    path = Path(p)
    real = os.path.realpath(path)
    if not path.exists():
        return "missing", "Path does not exist"
    if real == home or real.startswith(home + os.sep):
        return "home", ("Inside $HOME. --private hides all of home except whitelisted paths, so this is "
                        "blocked unless you whitelist it.")
    top = "/" + real.split("/")[1] if real.count("/") >= 1 and real != "/" else "/"
    if top in WHITELIST_TOPS:
        return "ok", f"Under {top}: firejail can whitelist it."
    if top in SYSTEM_TOPS:
        return "system", f"Under {top}: already visible read-only inside the sandbox; it cannot be made writable."
    return "unsupported", (f"Under {top}: firejail can only whitelist paths in $HOME or under "
                           f"{', '.join(sorted(WHITELIST_TOPS))}. Move it somewhere supported.")


def list_interfaces() -> list[tuple[str, str]]:
    """-> [(name, kind)] kind in ethernet|wireless|bridge|other"""
    out = []
    base = Path("/sys/class/net")
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for n in names:
        if n == "lo":
            continue
        d = base / n
        kind = "wireless" if (d / "wireless").exists() else "bridge" if (d / "bridge").exists() else "ethernet" if n.startswith(("en", "eth")) else "other"
        out.append((n, kind))
    return out


# connection attempts from `firejail --trace`
# firejail --trace lines look like "<pid>:<comm>:connect <addr>:<port> ..." as far as I know,
# but this regex is deliberately loose. If yours prints something different, this is the one
# place to change.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Two formats are supported, in priority order:

# 1. Kernel netfilter LOG (preferred, from iptables -j LOG --log-prefix "wq-net: "):
#    wq-net: IN= OUT=eth0-12345 SRC=192.168.3.88 DST=1.1.1.1 ... PROTO=TCP SPT=54321 DPT=443 ...
#    Doesn't depend on process bitness, can't be bypassed, no libtrace.so preload.
_KCONN = re.compile(
    r"wq-net(?:\[[^\]]*\])?:\s.*?\bDST=(?P<v4>\d{1,3}(?:\.\d{1,3}){3})\b"
    r".*?\bDPT=(?P<port>\d{1,5})\b")

# 2. firejail --trace format (legacy, kept for old logs):
#    <pid>:<comm>:connect <fd> <addr> port <port>:<retval>
#    Unix sockets (e.g. /run/systemd/resolve/io.systemd.Resolve) have no IP and are ignored.
_CONNECT = re.compile(
    r"connect\s+\d+\s+"
    r"(?:\[(?P<v6>[0-9a-fA-F:]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3}))"
    r"\s+port\s+(?P<port>\d{1,5})")


def strip_ansi(s: str) -> str:
    return _ANSI.sub("", s)


def parse_connect(line: str) -> tuple[str, int] | None:
    stripped = strip_ansi(line)
    m = _KCONN.search(stripped)
    if m:
        return m.group("v4"), int(m.group("port"))
    m = _CONNECT.search(stripped)
    if not m:
        return None
    addr = m.group("v4") or m.group("v6")
    port = int(m.group("port"))
    if not 0 < port < 65536:
        return None
    if m.group("v4") and any(int(o) > 255 for o in addr.split(".")):
        return None
    return addr, port


_KPROTO = re.compile(r"\bPROTO=(TCP|UDP)\b")


def parse_proto(line: str) -> str:
    """"tcp" or "udp" from a kernel firewall log line (PROTO=TCP), else "". The legacy
    firejail trace format doesn't say, so it gives "" and the UI asks."""
    m = _KPROTO.search(strip_ansi(line))
    return m.group(1).lower() if m else ""


_KGAME = re.compile(r"wq-net\[(?P<game>[^\]]*)\]:")


def parse_klog(line: str):
    """Kernel log line -> (game_tag, addr, port), or None."""
    s = strip_ansi(line)
    m = _KGAME.search(s)
    hit = parse_connect(s)
    if not m or not hit:
        return None
    return m.group("game"), hit[0], hit[1]


ALLOW_RE = re.compile(r"^(tcp|udp):((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?):(\d{1,5}|\*)$")


def is_special_addr(addr: str) -> bool:
    """Multicast / limited broadcast / unspecified: nothing worth whitelisting."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    return ip.is_multicast or ip.is_unspecified or addr == "255.255.255.255"


def valid_allow(entry: str) -> bool:
    import ipaddress
    m = ALLOW_RE.match(entry)
    if not m:
        return False
    try:
        net = ipaddress.ip_network(m.group(2), strict=False)   # rejects 300.1.1.1, /33, 010.x
    except ValueError:
        return False
    if net.prefixlen == 0:                                      # 0.0.0.0/0 switches the filter off
        return False
    port = m.group(3)
    return port == "*" or 1 <= int(port) <= 65535


def allow_matches(entries: list[str], addr: str, port: int) -> bool:
    """Is addr:port covered by any allow entry (cidr + wildcard port aware)?"""
    import ipaddress
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    for e in entries:
        m = ALLOW_RE.match(e)
        if not m:
            continue
        try:
            net = ipaddress.ip_network(m.group(2), strict=False)
        except ValueError:
            continue
        if ip in net and (m.group(3) == "*" or int(m.group(3)) == port):
            return True
    return False


# CSS

DARK = {
    "indicator_border": "#6b6b6b",
    "surface": "#16181c", "surface_container": "#1e2227", "surface_container_high": "#2a2f36",
    "on_surface": "#e3e5e8", "on_surface_variant": "#9aa1ab", "primary": "#7fc4b8",
    "on_primary": "#00201b", "outline": "#3a4048", "error": "#f2736b",
    "ok": "#7fd69a", "warn": "#e8b95a",
}
LIGHT = {
    "indicator_border": "#8a8a8a",
    "surface": "#f6f7f8", "surface_container": "#ffffff", "surface_container_high": "#e9ecef",
    "on_surface": "#1b1e22", "on_surface_variant": "#5b6470", "primary": "#2a7f72",
    "on_primary": "#ffffff", "outline": "#c9ced4", "error": "#c0392b",
    "ok": "#2f8f4e", "warn": "#a8741a",
}

_DEFINE = re.compile(r"^\s*@define-color\s+([A-Za-z_][\w-]*)\s+(.+?)\s*;\s*$", re.M)
_TOKEN = re.compile(r"@([A-Za-z_][\w-]*)")


def split_css(text: str) -> tuple[dict[str, str], str]:
    """Pull `@define-color name value;` lines out of a CSS file."""
    defs = {m.group(1).replace("-", "_"): m.group(2) for m in _DEFINE.finditer(text)}
    return defs, _DEFINE.sub("", text)


def substitute_tokens(sheet: str, tokens: dict[str, str]) -> str:
    return _TOKEN.sub(lambda m: tokens.get(m.group(1).replace("-", "_"), m.group(0)), sheet)


_ALERT_META = re.compile(r"Kill switch triggered|No terminal emulator found|ClamAV flagged \d+ of|ClamAV: \.\.\. and \d+ more")


def count_alerts(text: str) -> tuple[int, int]:
    """(alerts, warnings) in a monitor alert log. One finding is one alert: lines that only
    describe another alert (kill switch fired, ClamAV's totals) are not counted. Same rule as
    summarize-run.sh."""
    lines = text.splitlines()
    alerts = [ln for ln in lines if "[ALERT]" in ln]
    n = sum(1 for ln in alerts if not _ALERT_META.search(ln))
    if alerts:
        n = max(n, 1)
    return n, sum(1 for ln in lines if "[WARN]" in ln)


# game type: Windows or native Linux, guessed from what a source contains
_WIN_STRONG = (".exe", ".bat", ".cmd", ".msi", ".lnk")
_LIN_STRONG = (".sh", ".appimage", ".x86_64", ".x86", ".run", ".elf")
_SO_RE = re.compile(r"\.so(\.\d+)*$")
_TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2")
_LIST_TOOLS = (".7z", ".rar", ".iso", ".img")
TYPE_LABEL = {"wine": "Windows game", "native": "Native Linux game"}


def classify_names(names) -> tuple[str | None, str]:
    """("wine" | "native" | None, reason) from the file names inside a source.

    Files near the top (the root, or one wrapper folder) decide first, so a Windows game
    that ships a stray helper script is still Windows. Both kinds at the same level, or
    neither, gives None and the user chooses."""
    win_top, lin_top, win_all, lin_all, dll, so, mac = [], [], [], [], 0, 0, 0
    for raw in names:
        n = str(raw).replace("\\", "/").strip("/")
        low = n.lower()
        if not n or low.startswith("__macosx/"):
            continue
        base = low.rsplit("/", 1)[-1]
        shallow = low.count("/") <= 1
        if base.endswith(_WIN_STRONG):
            win_all.append(n.rsplit("/", 1)[-1])
            if shallow:
                win_top.append(win_all[-1])
        elif base.endswith(_LIN_STRONG):
            lin_all.append(n.rsplit("/", 1)[-1])
            if shallow:
                lin_top.append(lin_all[-1])
        elif base.endswith(".dll"):
            dll += 1
        elif _SO_RE.search(base):
            so += 1
        elif ".app/contents/macos/" in low:
            mac += 1

    def say(kind: str, found: list[str]) -> str:
        more = f" and {len(found) - 1} more" if len(found) > 1 else ""
        return f"{'Windows' if kind == 'wine' else 'Linux'} files: {found[0]}{more}"

    for w, l in ((win_top, lin_top), (win_all, lin_all)):
        if w and not l:
            return "wine", say("wine", w)
        if l and not w:
            return "native", say("native", l)
        if w and l:
            return None, f"it has both Windows ({w[0]}) and Linux ({l[0]}) files"
    if dll and not so:
        return "wine", f"{dll} Windows .dll file(s), no start file"
    if so and not dll:
        return "native", f"{so} Linux .so file(s), no start file"
    if mac:
        return None, "this looks like a macOS game, which is not supported"
    return None, "no .exe, .sh, AppImage or similar start file found"


def _walk_names(root: Path, limit: int = 4000, max_depth: int = 4) -> list[str]:
    out: list[str] = []
    base = str(root)
    for cur, dirs, files in os.walk(base, followlinks=False):
        if cur[len(base):].count(os.sep) >= max_depth:
            dirs[:] = []
        for f in files:
            rel = os.path.relpath(os.path.join(cur, f), base)
            full = os.path.join(cur, f)
            low = f.lower()
            if ("." not in f and os.access(full, os.X_OK) and _is_elf(full)) or (low.endswith(".bin") and _is_elf(full)):
                rel += ".elf"                              # an ELF without a telling name is a native binary
            out.append(rel)
            if len(out) >= limit:
                return out
    return out


def _list_archive(path: Path, limit: int = 4000) -> list[str] | None:
    """Names inside an archive without unpacking it. None when it can't be listed."""
    import shutil
    import subprocess
    import tarfile
    import zipfile
    low = path.name.lower()
    try:
        if low.endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                return z.namelist()[:limit]
        if low.endswith(_TAR_SUFFIXES):
            names = []
            with tarfile.open(path, "r:*") as t:
                for m in t:                               # stops early; never reads the whole file
                    names.append(m.name)
                    if len(names) >= limit:
                        break
            return names
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, EOFError):
        return None
    if not low.endswith(_LIST_TOOLS):
        return None

    def run(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=45, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return None
        return r.stdout if r.stdout else None

    for exe in ("7z", "7zz", "7za"):
        if shutil.which(exe):
            out = run([exe, "l", "-slt", "-ba", "--", str(path)])
            names = [ln[7:] for ln in (out or "").splitlines() if ln.startswith("Path = ")]
            if names:
                return names[:limit]
    if low.endswith(".rar") and shutil.which("unrar"):
        out = run(["unrar", "lb", "--", str(path)])
        if out:
            return out.splitlines()[:limit]
    if shutil.which("bsdtar"):
        out = run(["bsdtar", "-tf", str(path)])
        if out:
            return out.splitlines()[:limit]
    return None


def detect_source_type(source: Path | str) -> tuple[str | None, str]:
    """Guess "wine" or "native" for a folder, archive, .iso or single file, without unpacking
    or running anything. Returns (kind or None, why)."""
    p = Path(source).expanduser()
    if not p.exists():
        return None, "source not found"
    if p.is_dir():
        return classify_names(_walk_names(p))
    low = p.name.lower()
    if low.endswith(_WIN_STRONG + _LIN_STRONG):
        return classify_names([p.name])
    if low.endswith((".zip",) + _TAR_SUFFIXES + _LIST_TOOLS):
        names = _list_archive(p)
        if names is None:
            return None, "can't look inside it (a lister such as 7z or bsdtar may be missing)"
        kind, why = classify_names(names)
        return kind, why
    try:                                                       # unknown extension: look at the first bytes
        with p.open("rb") as f:
            head = f.read(4)
    except OSError as e:
        return None, f"can't read it ({e.strerror})"
    if head[:2] == b"MZ":
        return "wine", "it is a Windows program (MZ header)"
    if head == b"\x7fELF":
        return "native", "it is a Linux program (ELF header)"
    if head[:2] == b"#!":
        return "native", "it is a script (starts with #!)"
    return None, "not a program or a known archive type"


# last run: what the game list shows in its "Last run" column
_LEAK_RE = re.compile(r"\[LEAK\]|SANDBOX LEAK")
_BLOCKED_RE = re.compile(r"SANDBOX-VERIFY\] (?:FAIL|ABORT)|wq: aborting launch")
_RUN_CACHE: dict[str, tuple[tuple, tuple[str, str, float]]] = {}


def _read_part(path: Path, tail: bool, n: int = 65536) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            if tail:
                f.seek(max(0, size - n))
            return f.read(n).decode("utf-8", "replace")
    except OSError:
        return ""


def last_run(game_path: Path | str) -> tuple[str, str, float]:
    """(status, short text, unix time) for the most recent run, read from the game's logs.

    status is one of never, clean, notes, alert, blocked, leak. Same priority as
    summarize-run.sh: a leak beats a blocked launch beats alerts beats warnings. The
    launch log is read from its start, because the preflight that reports a leak or a
    block runs before the game prints anything. The alert log is read from its end, the
    way the Monitor tab does. Results are cached until a log changes, so calling this
    for every game on every refresh is cheap."""
    logs = Path(game_path) / "logs"
    alerts = sorted(logs.glob("alerts-*.log"))
    launches = sorted(logs.glob("launch-*.log"))
    a_log = alerts[-1] if alerts else None
    l_log = launches[-1] if launches else None
    sig, stamp = [], 0.0
    for p in (a_log, l_log):
        try:
            st = p.stat() if p else None
        except OSError:
            st = None
        sig.append((p.name, st.st_mtime_ns, st.st_size) if st else None)
        if st:
            stamp = max(stamp, st.st_mtime)
    key = str(game_path)
    sig_t = tuple(sig)
    hit = _RUN_CACHE.get(key)
    if hit and hit[0] == sig_t:
        return hit[1]
    if not any(sig_t):
        res = ("never", "never run", 0.0)
    else:
        launch_text = strip_ansi(_read_part(l_log, tail=False)) if l_log else ""
        alert_text = _read_part(a_log, tail=True) if a_log else ""
        status, text = run_verdict(launch_text, alert_text)
        res = (status, text, stamp)
    _RUN_CACHE[key] = (sig_t, res)
    return res


def run_verdict(launch_text: str, alert_text: str) -> tuple[str, str]:
    """(status, short text) for one run, from its launch log (read from the start, ANSI
    stripped) and its alert log. status is clean, notes, alert, blocked or leak. last_run and
    the Runs tab's history strip both use this, so a run never gets two different verdicts."""
    n_alert, n_warn = count_alerts(alert_text)
    if _LEAK_RE.search(launch_text):
        return "leak", "✗ sandbox leak"
    if _BLOCKED_RE.search(launch_text):
        return "blocked", "✗ launch blocked"
    if n_alert:
        return "alert", f"✗ {n_alert} alert{'s' if n_alert != 1 else ''}"
    if n_warn:
        return "notes", f"⚠ {n_warn} note{'s' if n_warn != 1 else ''}"
    return "clean", "✓ clean"


def human_ago(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


BUILTIN_QSS = """
* { font-size: 13px; }
QWidget { color: @on_surface; }
QMainWindow, QDialog, QWidget#central { background: @surface; }
QToolTip { background: @surface_container_high; color: @on_surface; border: 1px solid @outline; padding: 4px; }

QToolBar { background: @surface_container; border: 0; border-bottom: 1px solid @outline; spacing: 6px; padding: 6px; }
QToolButton { background: transparent; border: 1px solid transparent; border-radius: 6px; padding: 5px 10px; }
QToolButton:hover { background: @surface_container_high; border-color: @outline; }
QToolButton:disabled { color: @on_surface_variant; }

QTabWidget::pane { border: 1px solid @outline; border-radius: 8px; background: @surface_container; top: -1px; }
QTabBar::tab { background: transparent; color: @on_surface_variant; padding: 7px 16px; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: @on_surface; border-bottom: 2px solid @primary; }
QTabBar::tab:hover { color: @on_surface; }

QTreeWidget, QTableWidget, QListWidget, QPlainTextEdit, QLineEdit, QComboBox, QSpinBox {
    background: @surface_container; border: 1px solid @outline; border-radius: 6px;
    selection-background-color: @primary; selection-color: @on_primary; }
QTreeWidget#gameList { border-radius: 8px; }
QTreeWidget::item, QTableWidget::item, QListWidget::item { padding: 4px 2px; }
QTreeWidget, QTableWidget, QListWidget { outline: 0; }   /* no dotted focus box around the current cell */
QHeaderView::section { background: @surface_container_high; color: @on_surface_variant; border: 0; padding: 5px 8px; }
QLineEdit, QComboBox { padding: 5px 8px; }
QComboBox QAbstractItemView { background: @surface_container; selection-background-color: @primary; selection-color: @on_primary; }
QLineEdit:focus, QComboBox:focus { border-color: @primary; }
QLineEdit:disabled, QComboBox:disabled { color: @on_surface_variant; }
QPlainTextEdit#console, QPlainTextEdit#alerts { font-family: monospace; font-size: 12px; }

QPushButton { background: @surface_container_high; border: 1px solid @outline; border-radius: 6px; padding: 6px 14px; }
QPushButton:hover { border-color: @primary; }
QPushButton:disabled { color: @on_surface_variant; border-color: @outline; }
QPushButton[accent="true"] { background: @primary; color: @on_primary; border-color: @primary; font-weight: 600; }
QPushButton[accent="true"]:disabled { background: @surface_container_high; color: @on_surface_variant; border-color: @outline; }
QPushButton[danger="true"] { color: @error; }

QGroupBox { border: 1px solid @outline; border-radius: 8px; margin-top: 14px; padding: 14px 10px 8px 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: @on_surface_variant; }
QCheckBox { spacing: 8px; padding: 2px 0; }
QCheckBox:disabled { color: @on_surface_variant; }
QCheckBox[danger="true"] { color: @error; }
QCheckBox[relaxed="true"] { color: @warn; }
QPushButton[seg="true"]:checked { background: @primary; color: @on_primary; }

/* Checkbox indicators are PNGs drawn at startup (Qt stylesheets cannot load
   data: URIs, which is why the old SVG-in-QSS check marks never showed). The
   cb_ tokens below are file paths filled in by ThemeManager. */
QCheckBox::indicator { width: 16px; height: 16px; border: none; background: transparent; image: url("@cb_off"); }
QCheckBox::indicator:hover { image: url("@cb_off_hover"); }
QCheckBox::indicator:checked { image: url("@cb_on"); }
QCheckBox::indicator:indeterminate { image: url("@cb_part"); }
QCheckBox::indicator:disabled { image: url("@cb_off_dis"); }
QCheckBox::indicator:checked:disabled { image: url("@cb_on_dis"); }
QCheckBox::indicator:indeterminate:disabled { image: url("@cb_part_dis"); }

QMenu { background: @surface_container; border: 1px solid @outline; border-radius: 6px; padding: 4px; }
QMenu::item { padding: 6px 22px 6px 14px; border-radius: 4px; }
QMenu::item:selected { background: @primary; color: @on_primary; }
QMenu::item:disabled { color: @on_surface_variant; }
QMenu::separator { height: 1px; background: @outline; margin: 4px 8px; }
QToolButton::menu-indicator { subcontrol-position: right center; right: 4px; }

QLabel[status="ok"] { color: @ok; }
QLabel[status="warn"] { color: @warn; }
QLabel[status="bad"] { color: @error; }
QLabel[status="muted"], QLabel#hint { color: @on_surface_variant; }
QLabel#badge { border-radius: 9px; padding: 1px 10px; border: 1px solid @outline; }
QLabel#badge[status="ok"] { color: @ok; border-color: @ok; }
QLabel#badge[status="warn"] { color: @warn; border-color: @warn; }
QLabel#badge[status="bad"] { color: @error; border-color: @error; }
QLabel#banner { background: @surface_container_high; border: 1px solid @outline; border-radius: 6px; padding: 8px 10px; }
QLabel#banner[status="warn"] { border-color: @warn; }
QLabel#banner[status="bad"] { border-color: @error; }

QSplitter::handle { background: transparent; }
QScrollArea { border: 0; background: transparent; }
QScrollBar:vertical { background: transparent; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: @outline; border-radius: 5px; min-height: 28px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: @outline; border-radius: 5px; min-width: 28px; margin: 2px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QStatusBar { background: @surface_container; border-top: 1px solid @outline; }
"""

SAMPLE_CSS = """/* wq-ui custom stylesheet - reloaded automatically whenever this file changes.
 *
 * Two things work in here:
 *
 * 1) Colour tokens, GTK-style. Define any of these and the built-in theme picks
 *    them up (names match matugen / Material 3, so a matugen template can emit
 *    them directly - see matugen/):
 *
 *      surface  surface_container  surface_container_high
 *      on_surface  on_surface_variant  primary  on_primary
 *      outline  error  ok  warn
 *
 *    @define-color primary #7fc4b8;
 *
 * 2) Plain Qt stylesheet (QSS) rules, applied on top. Tokens can be used with
 *    @name. Useful hooks:
 *
 *      QTreeWidget#gameList      the game list
 *      QPlainTextEdit#console    launcher output
 *      QPlainTextEdit#alerts     monitor alerts
 *      QLabel#banner[status="warn"]
 *      QPushButton[accent="true"]  primary buttons
 *
 *    QPushButton { border-radius: 14px; }
 */
"""

# misc

_SIZE = re.compile(r"^\d{3,5}x\d{3,5}$")


def valid_size(s: str) -> bool:
    return bool(_SIZE.match(s))


# limits and extra firejail options
# These mirror profile.sh (_wq_extra_arg_ok & co). profile.sh is the authority and re-checks
# everything at launch, this copy only lets the UI complain early. test_core.py runs both on the
# same inputs so they can't drift apart.

_TASKS = re.compile(r"[1-9][0-9]{0,8}")
_MEMORY = re.compile(r"[1-9][0-9]{0,9}[KMGT]?")
_SYSCALLS = re.compile(r"[A-Za-z0-9_@]+(,[A-Za-z0-9_@]+)*")


def valid_tasks(s: str) -> bool:
    return bool(_TASKS.fullmatch(s))


def valid_memory(s: str) -> bool:
    return bool(_MEMORY.fullmatch(s))


def valid_syscalls(s: str) -> bool:
    return bool(_SYSCALLS.fullmatch(s))


_EXTRA_FLAGS = {"--machine-id", "--nosound", "--novideo", "--nou2f", "--notv", "--nodvd", "--noroot"}
_EXTRA_RE = [re.compile(r) for r in (
    r"--rlimit-(nproc|nofile|fsize|cpu|as|sigpending)=[0-9]{1,18}[KMG]?",
    r"--timeout=[0-9]{1,3}:[0-5][0-9]:[0-5][0-9]",
    r"--nice=([0-9]|1[0-9])",
    r"--cpu=[0-9]+(,[0-9]+)*",
    r"--rmenv=[A-Za-z_][A-Za-z0-9_]*",
)]
_EXTRA_PATH_RE = re.compile(r"--(blacklist|noexec|read-only)=(/[A-Za-z0-9_./@%+:=,-]*)")


def check_extra_arg(line: str) -> str:
    """"" if `line` is an allowed extra firejail option, else a reason. Only options
    that can make the sandbox tighter are accepted: no --net, --noprofile, --ignore,
    --allow-*, --netfilter, --whitelist (those have their own switches or none)."""
    if not line or line.startswith("#"):
        return ""
    if line in _EXTRA_FLAGS or any(r.fullmatch(line) for r in _EXTRA_RE):
        return ""
    m = _EXTRA_PATH_RE.fullmatch(line)
    if m:
        if any(seg == ".." for seg in m.group(2).split("/")):
            return "paths may not contain .."
        return ""
    return "not an allowed option"


# checkbox images (the Qt side draws them from this)
# token -> (border colour key, fill colour key, glyph, glyph colour key)
CB_ICONS: dict[str, tuple[str, str, str | None, str | None]] = {
    "cb_off":       ("indicator_border", "surface", None, None),
    "cb_off_hover": ("primary", "surface", None, None),
    "cb_on":        ("primary", "primary", "check", "on_primary"),
    "cb_part":      ("primary", "primary", "dash", "on_primary"),
    "cb_off_dis":   ("outline", "surface_container", None, None),
    "cb_on_dis":    ("outline", "outline", "check", "on_surface_variant"),
    "cb_part_dis":  ("outline", "outline", "dash", "on_surface_variant"),
}
for _t in (DARK, LIGHT):
    for _k in CB_ICONS:
        _t.setdefault(_k, "")          # filled in at runtime


def icon_signature(tokens: dict[str, str]) -> str:
    """Hash of the colours the checkbox images use. It goes in the file name so a
    theme change doesn't pick up a stale cached pixmap."""
    import hashlib
    keys = sorted({k for spec in CB_ICONS.values() for k in (spec[0], spec[1], spec[3]) if k})
    return hashlib.sha1("|".join(f"{k}={tokens.get(k, '')}" for k in keys).encode()).hexdigest()[:10]


# new games and picking the exe

MAX_NAME = 64


def validate_game_name(name: str, existing: set[str] | None = None, qroot: Path | None = None) -> str:
    """Return "" if the name is fine, otherwise why not. Same rules as
    new-quarantine.sh, plus scan_games() hides names starting with _ or ."""
    n = name.strip()
    if not n:
        return "Enter a name."
    if n != name:
        return "Remove the leading/trailing spaces."
    if len(n) > MAX_NAME:
        return f"Keep the name under {MAX_NAME} characters."
    if "/" in n or n in (".", ".."):
        return "The name cannot contain “/”."
    if any(ord(c) < 32 or ord(c) == 127 for c in n):
        return "The name cannot contain control characters."
    if n.startswith(("_", ".", "-")):
        return "The name cannot start with “_”, “.” or “-” (those are hidden from the game list / look like options)."
    low = n.lower()
    if existing and any(e.lower() == low for e in existing):
        return "A game with that name already exists."
    if qroot is not None and (Path(qroot) / n).exists():
        return f"{Path(qroot) / n} already exists."
    return ""


def valid_exe_rel(rel: str) -> bool:
    """Same check as valid_exe_rel in config.sh."""
    if not rel or rel.startswith("/") or "\n" in rel or "\r" in rel:
        return False
    return ".." not in rel.split("/")


_EXE_SKIP = ("unins*", "*redist*", "*vcredist*", "*directx*", "dxsetup*", "*crashhandler*", "*crashpad*")


_NATIVE_EXT = (".sh", ".appimage", ".x86_64", ".x86", ".bin", ".run")
_NATIVE_SKIP = ("unins*", "uninstall*", "install*")


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def find_exes(gamedir: Path, runner: str = "wine", limit: int = 300, max_depth: int = 8) -> list[str]:
    """Start candidates under <game>/game/ as relative paths. Wine: .exe files with
    the same filters as new-quarantine.sh. Native: .sh, AppImage and ELF files."""
    import fnmatch
    if runner == "native":
        return _find_native(gamedir, limit, min(max_depth, 4))
    base = Path(gamedir) / "game"
    out: list[str] = []
    if not base.is_dir():
        return out
    base_s = str(base)
    for root, dirs, files in os.walk(base_s, followlinks=False):
        depth = root[len(base_s):].count(os.sep)
        if depth >= max_depth:
            dirs[:] = []
        for f in files:
            low = f.lower()
            if not low.endswith(".exe") or any(fnmatch.fnmatch(low, pat) for pat in _EXE_SKIP):
                continue
            rel = os.path.relpath(os.path.join(root, f), base_s)
            if valid_exe_rel(rel):
                out.append(rel)
            if len(out) >= limit:
                break
    out.sort(key=lambda r: (r.count("/"), r.lower()))
    return out + find_prefix_exes(gamedir)       # what an installer put in the prefix comes last


def _find_native(gamedir: Path, limit: int, max_depth: int) -> list[str]:
    import fnmatch
    base = Path(gamedir) / "game"
    out: list[str] = []
    if not base.is_dir():
        return out
    base_s = str(base)
    for root, dirs, files in os.walk(base_s, followlinks=False):
        if root[len(base_s):].count(os.sep) >= max_depth:
            dirs[:] = []
        for f in files:
            low = f.lower()
            if any(fnmatch.fnmatch(low, pat) for pat in _NATIVE_SKIP):
                continue
            full = os.path.join(root, f)
            if low.endswith(_NATIVE_EXT) or ("." not in f and os.access(full, os.X_OK) and _is_elf(full)):
                rel = os.path.relpath(full, base_s)
                if valid_exe_rel(rel):
                    out.append(rel)
        if len(out) >= limit:
            break
    out.sort(key=lambda r: (r.count("/"), r.lower()))
    return out


PREFIX_TAG = "@prefix/"      # EXE=@prefix/drive_c/... : a program an installer put into the Wine prefix


def exe_root(gamedir: Path, exe: str) -> tuple[str, str]:
    """-> (root directory, path relative to it). Same rule as wq_exe_root/wq_exe_rel in config.sh:
    a plain EXE is relative to game/, an @prefix/ one to prefix/."""
    if exe.startswith(PREFIX_TAG):
        return str(Path(gamedir) / "prefix"), exe[len(PREFIX_TAG):]
    return str(Path(gamedir) / "game"), exe


def exe_path(gamedir: Path, exe: str) -> Path:
    root, rel = exe_root(gamedir, exe)
    return Path(root) / rel


def exe_inside_game(gamedir: Path, rel: str) -> bool:
    """True if the program (<game>/game/<rel>, or <game>/prefix/<x> for @prefix/<x>) is a real file that
    stays inside that folder once symlinks are resolved."""
    if not valid_exe_rel(rel):
        return False
    root, sub = exe_root(gamedir, rel)
    if not sub:
        return False
    base = os.path.realpath(root)
    target = os.path.realpath(os.path.join(base, sub))
    return os.path.isfile(target) and target.startswith(base + os.sep)


# Folders in a Wine prefix that hold Wine/Proton/Windows itself, not something an installer added
_PREFIX_SKIP = ("windows", "programdata/microsoft", "program files/common files", "program files (x86)/common files",
                "program files/internet explorer", "program files (x86)/internet explorer",
                "program files/windows media player", "program files (x86)/windows media player",
                "program files/windows nt", "program files (x86)/windows nt", "program files/wine",
                "program files (x86)/wine", "users/steamuser/appdata/local/temp")


def find_prefix_exes(gamedir: Path, limit: int = 200, max_depth: int = 7) -> list[str]:
    """Programs an installer left in prefix/drive_c, as "@prefix/drive_c/..." paths (not Wine's own files)."""
    import fnmatch
    base = Path(gamedir) / "prefix" / "drive_c"
    out: list[str] = []
    if not base.is_dir():
        return out
    base_s = str(base)
    for root, dirs, files in os.walk(base_s, followlinks=False):
        rel_root = os.path.relpath(root, base_s).lower().replace(os.sep, "/")
        rel_root = "" if rel_root == "." else rel_root
        dirs[:] = [d for d in dirs
                   if (rel_root + "/" + d.lower()).lstrip("/") not in _PREFIX_SKIP
                   and not (rel_root + "/" + d.lower()).lstrip("/").startswith("users/steamuser/appdata/local/temp")]
        if (rel_root.count("/") + 1 if rel_root else 0) >= max_depth:
            dirs[:] = []
        for f in files:
            low = f.lower()
            if not low.endswith(".exe") or any(fnmatch.fnmatch(low, pat) for pat in _EXE_SKIP):
                continue
            rel = PREFIX_TAG + "drive_c/" + os.path.relpath(os.path.join(root, f), base_s).replace(os.sep, "/")
            if valid_exe_rel(rel):
                out.append(rel)
        if len(out) >= limit:
            break
    out.sort(key=lambda r: (r.count("/"), r.lower()))
    return out


_SETUP_PATTERNS = ("setup*.exe", "install*.exe", "*installer*.exe", "*_setup*.exe", "*-setup*.exe",
                   "setup*.sh", "install*.sh", "*installer*.sh", "gog_*.sh", "*.run", "*.appimage")


def find_setups(gamedir: Path, runner: str = "wine", limit: int = 100, max_depth: int = 4) -> list[str]:
    """Setup / installer files in game/ that look like they should be run once, as relative paths."""
    import fnmatch
    base = Path(gamedir) / "game"
    out: list[str] = []
    if not base.is_dir():
        return out
    native = runner == "native"
    base_s = str(base)
    for root, dirs, files in os.walk(base_s, followlinks=False):
        if root[len(base_s):].count(os.sep) >= max_depth:
            dirs[:] = []
        for f in files:
            low = f.lower()
            if not any(fnmatch.fnmatch(low, pat) for pat in _SETUP_PATTERNS):
                continue
            if native == low.endswith(".exe"):          # wine runs .exe files, native runs everything else
                continue
            rel = os.path.relpath(os.path.join(root, f), base_s)
            if valid_exe_rel(rel):
                out.append(rel)
    out.sort(key=lambda r: (r.count("/"), r.lower()))
    return out[:limit]


# /dev nodes to hide (FJ_DEV_BLOCK)

# the sandbox needs these
DEV_ESSENTIAL = {"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty",
                 "/dev/ptmx", "/dev/pts", "/dev/shm", "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"}
# allowed, but the game will probably lose graphics, input or sound
DEV_NOTABLE = (("/dev/dri", "GPU access - the game will fall back to software rendering or fail"),
               ("/dev/nvidia", "NVIDIA GPU access - the game will probably not start"),
               ("/dev/input", "keyboards, mice and gamepads - the game will get no input"),
               ("/dev/snd", "audio - the game will be silent (the Block audio box does the same)"),
               ("/dev/uinput", "synthetic input injection"),
               ("/dev/fuse", "FUSE mounts"))


def device_risk(path: str) -> tuple[str, str]:
    """-> (level, note), level is essential, notable or ok."""
    p = os.path.normpath(path)
    if p in DEV_ESSENTIAL or any(p.startswith(e + "/") for e in ("/dev/pts", "/dev/shm", "/dev/fd")):
        return "essential", "The sandbox (Wine, the shell) needs this one - it cannot be blocked."
    for prefix, note in DEV_NOTABLE:
        if p == prefix or p.startswith(prefix + "/") or (prefix == "/dev/nvidia" and p.startswith("/dev/nvidia")):
            return "notable", f"Blocking this removes {note}."
    return "ok", ""


def validate_device_path(path: str) -> tuple[bool, str]:
    """Check a typed or picked path -> (ok, message)."""
    p = path.strip()
    if not p:
        return False, "Enter a path under /dev."
    if "\n" in p or "\r" in p or "\0" in p:
        return False, "Invalid characters in path."
    if not p.startswith("/dev/") or p.rstrip("/") == "/dev":
        return False, "Only paths below /dev/ can be blocked here (not /dev itself)."
    if ".." in p.split("/"):
        return False, "“..” is not allowed in the path."
    norm = os.path.normpath(p)
    if not os.path.lexists(norm):
        return False, f"{norm} does not exist on this machine."
    real = os.path.realpath(norm)
    if not (real == "/dev" or real.startswith("/dev/")):
        return False, f"{norm} points to {real}, which is outside /dev."
    if device_risk(norm)[0] == "essential" or device_risk(real)[0] == "essential":
        return False, device_risk(norm if device_risk(norm)[0] == "essential" else real)[1]
    return True, ""


_DEV_SKIP = {"null", "zero", "full", "random", "urandom", "tty", "ptmx", "pts", "shm", "fd", "stdin",
             "stdout", "stderr", "core", "mqueue", "hugepages", "log"}


def _dev_kind(path: str) -> str:
    n = path[len("/dev/"):]
    if n.startswith("input/"):
        return "input"
    if n.startswith("dri/") or n.startswith("nvidia"):
        return "gpu"
    if n.startswith("snd/"):
        return "audio"
    if n.startswith(("video", "media", "v4l/")):
        return "camera/video"
    if n.startswith(("hidraw", "bus/usb", "usb")):
        return "usb/hid"
    if n.startswith(("sd", "nvme", "mmcblk", "sr", "loop", "dm-", "md", "vd", "hd")):
        return "storage"
    if n.startswith(("tty", "pts", "console", "vcs")):
        return "terminal"
    if n.startswith(("dvb", "lirc", "cec")):
        return "tv/remote"
    if n.startswith(("kvm", "vhost", "uinput", "fuse", "net/", "rfkill", "mem", "kmsg", "cpu")):
        return "system"
    return "other"


def list_devices(limit: int = 600) -> list[tuple[str, str, str]]:
    """Device nodes under /dev -> [(path, kind, note)]. Goes one level into input,
    dri, snd and so on. /dev/bus/usb is one entry, it has a node per USB device."""
    out: list[tuple[str, str, str]] = []
    dev = Path("/dev")

    def add(p: str):
        if len(out) >= limit:
            return
        lvl, note = device_risk(p)
        if lvl == "essential":
            return
        out.append((p, _dev_kind(p), note))

    try:
        top = sorted(os.listdir(dev))
    except OSError:
        return out
    for name in top:
        if name in _DEV_SKIP:
            continue
        p = f"/dev/{name}"
        try:
            st = os.lstat(p)
        except OSError:
            continue
        import stat as _st
        if _st.S_ISDIR(st.st_mode):
            if name in ("input", "dri", "snd", "v4l", "dvb", "bus", "usb", "disk", "mapper"):
                add(p)
                if name in ("bus", "disk", "mapper"):
                    continue
                try:
                    for sub in sorted(os.listdir(p)):
                        add(f"{p}/{sub}")
                except OSError:
                    pass
            continue
        if _st.S_ISCHR(st.st_mode) or _st.S_ISBLK(st.st_mode) or _st.S_ISLNK(st.st_mode):
            add(p)
    return out


# launch scripts (FJ_HOOK_PRE / FJ_HOOK_POST)


def validate_hook_path(path: str) -> tuple[bool, str]:
    p = path.strip()
    if not p or not p.startswith("/"):
        return False, "Use an absolute path."
    if "\n" in p or "\r" in p:
        return False, "Invalid characters in path."
    if not os.path.isfile(p):
        return False, f"{p} is not a file."
    if not os.access(p, os.R_OK):
        return False, f"{p} is not readable."
    return True, ""


# removing a game
RESERVED_DIRS = {"wq-ui", "wq", "tests"}


def validate_removal(qroot: Path, name: str) -> str:
    """Return "" if <qroot>/<name> can be removed, otherwise why not. It has to be
    a real game folder directly inside qroot: no symlinks, no _umu-*, no wq-ui."""
    if not name or "/" in name or name in (".", "..") or name.startswith(("_", ".")) or name in RESERVED_DIRS:
        return f"“{name}” is not a game folder."
    q = Path(qroot).resolve()
    p = q / name
    if p.is_symlink():
        return f"{p} is a symlink; remove it by hand."
    if not p.is_dir():
        return f"{p} is not a folder."
    if p.resolve().parent != q:
        return f"{p} is not directly inside {q}."
    if not ((p / "game.conf").is_file() or (p / "game").is_dir()):
        return f"{p} does not look like a game folder (no game.conf or game/)."
    return ""


def stash_game(qroot: Path, path: Path) -> Path:
    """Move a game folder into <qroot>/.trash, for drives with no system Trash. It is a rename on the
    same drive, so nothing is copied or lost. Restore by moving the folder back into qroot.
    Returns where it went. scan_games skips dot-folders, so .trash never shows as a game."""
    stash = Path(qroot) / ".trash"
    stash.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest, n = stash / f"{path.name}-{stamp}", 2
    while dest.exists():
        dest, n = stash / f"{path.name}-{stamp}-{n}", n + 1
    shutil.move(str(path), str(dest))
    return dest


def dir_size(path: Path, max_entries: int = 200_000) -> tuple[int, bool]:
    """Bytes under path, not following symlinks -> (bytes, truncated)."""
    total, seen = 0, 0
    stack = [str(path)]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    seen += 1
                    if seen > max_entries:
                        return total, True
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total, False


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
