"""Qt-free logic for wq-ui: game.conf IO, game discovery, path checks,
firejail trace parsing and CSS token handling. Kept separate so it can be
tested without a display."""
from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULTS_NAME = "profile.defaults.conf"

# --------------------------------------------------------------------------
# options
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BoolOpt:
    key: str
    label: str
    default: bool          # matches the stock wine-quarantine sandbox
    tip: str
    group: str


BOOL_OPTS: list[BoolOpt] = [
    BoolOpt("FJ_PRIVATE_HOME", "Hide home directory", True, "--private: $HOME is an empty tmpfs. Only whitelisted paths show up inside.", "isolation"),
    BoolOpt("FJ_PRIVATE_TMP", "Private /tmp", True, "--private-tmp", "isolation"),
    BoolOpt("FJ_NONEWPRIVS", "No new privileges", True, "--nonewprivs", "isolation"),
    BoolOpt("FJ_CAPS_DROP", "Drop all capabilities", True, "--caps.drop=all", "isolation"),
    BoolOpt("FJ_NODBUS", "Block D-Bus", True, "--nodbus", "isolation"),
    BoolOpt("FJ_SECCOMP", "Seccomp syscall filter", True, "--seccomp.drop=... (list lives in config.sh: SECCOMP_DROP)", "isolation"),
    BoolOpt("FJ_NOROOT", "No root user namespace", False, "--noroot: user namespace with only the current user mapped.", "isolation"),
    BoolOpt("FJ_MACHINE_ID", "Spoof machine-id", True, "--machine-id: the game sees a random /etc/machine-id instead of the stable ID of this PC.", "isolation"),
    BoolOpt("FJ_NOSOUND", "Block audio", False, "--nosound", "devices"),
    BoolOpt("FJ_NOVIDEO", "Block webcams", False, "--novideo", "devices"),
    BoolOpt("FJ_NOU2F", "Block U2F / security keys", False, "--nou2f", "devices"),
    BoolOpt("FJ_NOTV", "Block TV / DVB devices", False, "--notv", "devices"),
    BoolOpt("FJ_NODVD", "Block optical drives", False, "--nodvd", "devices"),
    BoolOpt("CLAM_SCAN", "ClamAV scan after each run", True,
            "Scan what the run changed with clamscan. Off = no scan after runs (CLAM_SCAN=0). "
            "Wine games: the files from the first-run bootstrap are skipped, only what the game adds is scanned.",
            "monitoring"),
    BoolOpt("MONITOR_KILL", "Alerts stop the sandbox", True,
            "On: the first ALERT kills the sandbox (kill switch). Off: alerts are still logged and "
            "show in the summary, but the game keeps running (MONITOR_KILL=0).",
            "monitoring"),
]
BOOL_BY_KEY = {o.key: o for o in BOOL_OPTS}

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

# --------------------------------------------------------------------------
# KEY=value files (read as data, same as read_game_conf in config.sh)
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# games
# --------------------------------------------------------------------------


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
        return self.scalar(key, defaults, "1" if ALL_BOOLS[key] else "0") == "1"

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


# --------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------

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
        return "home", ("Inside $HOME. firejail --private hides everything in home except what is "
                        "whitelisted, so this is blocked unless it is whitelisted.")
    top = "/" + real.split("/")[1] if real.count("/") >= 1 and real != "/" else "/"
    if top in WHITELIST_TOPS:
        return "ok", f"Under {top}: firejail can whitelist it."
    if top in SYSTEM_TOPS:
        return "system", f"Under {top}: already visible read-only inside the sandbox; it cannot be made writable."
    return "unsupported", (f"Under {top}: firejail can only whitelist paths in $HOME or under "
                           f"{', '.join(sorted(WHITELIST_TOPS))}. Move it or bind-mount it somewhere supported.")


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


# --------------------------------------------------------------------------
# connection attempts from `firejail --trace`
# --------------------------------------------------------------------------
# Format of trace lines is "<pid>:<comm>:connect <addr>:<port> ..." as far as
# I know, but this regex is deliberately loose. If your firejail prints
# something different, this is the one place to adjust.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Two formats are supported, in priority order:

# 1. Kernel netfilter LOG (preferred, from iptables -j LOG --log-prefix "wq-net: "):
#    wq-net: IN= OUT=eth0-12345 SRC=192.168.3.88 DST=1.1.1.1 ... PROTO=TCP SPT=54321 DPT=443 ...
#    Unaffected by process bitness, cannot be bypassed, no libtrace.so preload.
_KCONN = re.compile(
    r"wq-net(?:\[[^\]]*\])?:\s.*?\bDST=(?P<v4>\d{1,3}(?:\.\d{1,3}){3})\b"
    r".*?\bDPT=(?P<port>\d{1,5})\b")

# 2. Firejail --trace format (legacy, kept for compatibility with old logs):
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


# --------------------------------------------------------------------------
# CSS
# --------------------------------------------------------------------------

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

# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------

_SIZE = re.compile(r"^\d{3,5}x\d{3,5}$")


def valid_size(s: str) -> bool:
    return bool(_SIZE.match(s))


# --- limits and extra firejail options ---------------------------------------
# These mirror profile.sh (_wq_extra_arg_ok & co). profile.sh is the authority, it
# re-checks everything at launch; this copy only lets the UI complain early.
# test_core.py runs both on the same inputs so they cannot drift apart.

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


# --------------------------------------------------------------------------
# checkbox images (the Qt side draws them from this)
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# new games and picking the exe
# --------------------------------------------------------------------------

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


_NATIVE_EXT = (".sh", ".appimage", ".x86_64", ".x86", ".bin")
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
    return out


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


def exe_inside_game(gamedir: Path, rel: str) -> bool:
    """True if <game>/game/<rel> is a real file that stays inside game/ once symlinks are resolved."""
    if not valid_exe_rel(rel):
        return False
    base = os.path.realpath(Path(gamedir) / "game")
    target = os.path.realpath(os.path.join(base, rel))
    return os.path.isfile(target) and (target == base or target.startswith(base + os.sep))


# --------------------------------------------------------------------------
# /dev nodes to hide (FJ_DEV_BLOCK)
# --------------------------------------------------------------------------

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


# --------------------------------------------------------------------------
# launch scripts (FJ_HOOK_PRE / FJ_HOOK_POST)
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# removing a game
# --------------------------------------------------------------------------
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
