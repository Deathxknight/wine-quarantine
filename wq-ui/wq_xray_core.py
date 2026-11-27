"""Qt-free logic for the X-Ray tab.

Snapshot a game's folders, compare against a baseline taken before the run, build a
size tree and lay it out as a treemap. Nothing here imports Qt, so test_xray.py
covers it without a display.

"new" and "modified" are decided by comparing two snapshots (size + mtime_ns per file),
not by file dates alone: Wine and installers keep the dates of the files they copy, so
a file's mtime says little about when it arrived.

The second half of the file models what the sandbox may touch (build_policy, apply_policy):
the profile's whitelists and blacklists become a list of path rules, and every tile on the
map is resolved against them as read-write, read-only or hidden. It is a model of the
firejail arguments profile.sh builds, read from game.conf and profile.defaults.conf as data;
it does not ask a running firejail.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import os
import re
import stat
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from wq_core import DEFAULTS_NAME, parse_kv   # noqa: F401  (DEFAULTS_NAME is re-exported for the UI)

SCAN_DIRS = ("game", "prefix", "home")   # the folders a sandboxed game can write to
KEEP_BIG = 40        # per folder: largest children always shown separately
KEEP_CHANGED = 60    # per folder: further new/modified children shown separately
BOOST = 0.35         # tile area ~ size**BOOST when "boost small files" is on
CHANGED_FLOOR = 0.03   # with boost: a new/modified item gets at least this share of its folder...
CHANGED_CAP = 0.4      # ...but all floors together never take more than this share
KEEP_MARKED = 20       # per folder: further children that carry a sandbox rule, shown separately

Snap = dict          # relative path -> (size, mtime_ns), files only


# snapshot / baseline / diff
def _walk(path: str, rel: str, out: Snap, stop: Callable[[], bool] | None) -> bool:
    """Add every file under path to out as rel/...; a plain file is recorded as rel itself.
    Returns False if stop() asked to give up."""
    try:
        if not os.path.isdir(path):
            st = os.stat(path, follow_symlinks=False)
            if os.path.isfile(path) or os.path.islink(path):
                out[rel] = (st.st_size, st.st_mtime_ns)
            return True
    except OSError:
        return True
    stack = [(path, rel)]
    while stack:
        if stop and stop():
            return False
        path, rel = stack.pop()
        try:
            with os.scandir(path) as it:
                for e in it:
                    r = rel + "/" + e.name
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append((e.path, r))
                        else:
                            st = e.stat(follow_symlinks=False)
                            out[r] = (st.st_size, st.st_mtime_ns)
                    except OSError:
                        pass
        except OSError:
            pass
    return True


def snapshot(root: Path | str, dirs=SCAN_DIRS, stop: Callable[[], bool] | None = None,
             extra: dict[str, str] | None = None) -> Snap:
    """Every file under root/<dirs>, plus every file under each extra {name: absolute path}
    (the profile's whitelisted folders and files that live outside the game folder; they appear
    on the map as a top-level tile called name). Symlinks are recorded as themselves and never
    followed, so a link out of a folder cannot pull outside files into the picture."""
    out: Snap = {}
    for top in dirs:
        if not _walk(os.path.join(str(root), top), top, out, stop):
            return out
    for name, path in (extra or {}).items():
        if not _walk(path, name, out, stop):
            return out
    return out


def baseline_path(cache_dir: Path | str, game_path: Path | str) -> Path:
    gp = Path(game_path)
    return Path(cache_dir) / "xray" / f"{gp.name}-{hashlib.sha1(str(gp).encode()).hexdigest()[:8]}.json.gz"


def save_baseline(path: Path | str, snap: Snap, taken: float | None = None,
                  tops: Iterable[str] | None = None) -> None:
    import time
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"v": 1, "taken": taken if taken is not None else time.time(),
            "tops": sorted(tops if tops is not None else SCAN_DIRS),
            "files": {p: [s, m] for p, (s, m) in snap.items()}}
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".wq-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            gz.write(json.dumps(data, separators=(",", ":")).encode())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_baseline_info(path: Path | str) -> tuple[Snap | None, float, frozenset[str]]:
    """(snapshot, unix time it was taken, names of the top-level folders it covered).
    Baselines written before extra folders existed covered only SCAN_DIRS."""
    try:
        with gzip.open(path, "rb") as f:
            data = json.load(f)
        files = {p: (int(v[0]), int(v[1])) for p, v in data["files"].items()}
        tops = frozenset(str(t) for t in data.get("tops", SCAN_DIRS))
        return files, float(data.get("taken", 0.0)), tops
    except (OSError, ValueError, KeyError, TypeError, EOFError, IndexError):
        return None, 0.0, frozenset()


def load_baseline(path: Path | str) -> tuple[Snap | None, float]:
    """(snapshot, unix time it was taken), or (None, 0.0) if there is none or it is unreadable."""
    snap, taken, _tops = load_baseline_info(path)
    return snap, taken


def diff(base: Snap | None, now: Snap, base_tops: Iterable[str] | None = None) -> tuple[dict[str, str], list[str]]:
    """({path: "new" | "mod"}, [paths that are gone]). Unchanged files are left out.
    base_tops: the top-level folders the baseline covered. Files under any other top are not
    compared (a folder added to the profile after the baseline would otherwise be all "new");
    None compares everything."""
    if base is None:
        return {}, []
    covered = None if base_tops is None else set(base_tops)
    st: dict[str, str] = {}
    for p, v in now.items():
        if covered is not None and p.split("/", 1)[0] not in covered:
            continue
        b = base.get(p)
        if b is None:
            st[p] = "new"
        elif b != v:
            st[p] = "mod"
    return st, [p for p in base if p not in now]


def summary(now: Snap, status: dict[str, str], gone: list[str]) -> dict[str, int]:
    new = [p for p, s in status.items() if s == "new"]
    mod = [p for p, s in status.items() if s == "mod"]
    return {"files": len(now), "bytes": sum(v[0] for v in now.values()),
            "new": len(new), "new_bytes": sum(now[p][0] for p in new),
            "mod": len(mod), "mod_bytes": sum(now[p][0] for p in mod), "gone": len(gone)}


# what a changed file is
# A new .png and a new .exe are not the same news. Files that are new or modified since the
# baseline get a quick look at their first bytes, so the map can say "this is a program".
PROGRAM_KINDS = {"pe": "Windows program", "elf": "Linux program", "script": "script",
                 "launcher": "launcher or shortcut"}
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".hta"}
LAUNCHER_EXT = {".desktop", ".lnk", ".service", ".timer", ".url"}
HEAD_BYTES = 64 * 1024
SNIFF_LIMIT = 400                 # changed files looked at per scan; new ones first
PACKED_ENTROPY = 7.2              # bits per byte over the first HEAD_BYTES of a program
PACKED_MIN = 8 * 1024             # smaller programs are too short for the number to mean anything


def _read_head(path: str) -> bytes | None:
    """First HEAD_BYTES of a regular file, or None. Never follows a symlink, and never blocks on
    a FIFO or device a game may have left in its folder (opened non-blocking, then checked)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, HEAD_BYTES)
    except OSError:
        return None
    finally:
        os.close(fd)


def _is_pe(data: bytes) -> bool:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return False
    off = int.from_bytes(data[0x3C:0x40], "little")
    return 0 < off <= len(data) - 4 and data[off:off + 4] == b"PE\0\0"


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = all one byte, 8 = random)."""
    n = len(data)
    if not n:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def sniff_file(path: str, head: bytes | None = None) -> tuple[str, bool]:
    """(kind, packed). kind is pe, elf, script, launcher, or "" for anything that is not a
    program. packed is only ever True for pe/elf files whose bytes look packed or encrypted:
    ordinary game data (pak files, audio, textures) is compressed too, which is why a high
    number on a data file means nothing and is not reported."""
    data = _read_head(path) if head is None else head
    ext = os.path.splitext(path.lower())[1]
    if data is None:
        return "", False
    if data[:4] == b"\x7fELF":
        kind = "elf"
    elif _is_pe(data):
        kind = "pe"
    elif data[:2] == b"#!":
        kind = "script"
    elif ext in LAUNCHER_EXT or data[:8] == b"L\x00\x00\x00\x01\x14\x02\x00":
        kind = "launcher"
    elif ext in SCRIPT_EXT:
        kind = "script"
    else:
        return "", False
    return kind, kind in ("pe", "elf") and len(data) >= PACKED_MIN and entropy(data) >= PACKED_ENTROPY


def abs_of(root: Path | str, rel: str, extra: dict[str, str] | None = None) -> str:
    """Absolute path of a snapshot path: game/x lives under root, a whitelisted extra folder's
    files live wherever that folder is."""
    top, _, rest = rel.partition("/")
    if extra and top in extra:
        return os.path.join(extra[top], rest) if rest else extra[top]
    return os.path.join(str(root), rel)


def sniff_changed(root: Path | str, status: dict[str, str], extra: dict[str, str] | None = None,
                  limit: int = SNIFF_LIMIT, stop: Callable[[], bool] | None = None) -> dict[str, tuple[str, bool]]:
    """{path: (kind, packed)} for the new and modified files that are programs. Runs in a worker
    thread; stop() ends it early."""
    order = sorted(status, key=lambda p: (status[p] != "new", p))[:limit]
    out: dict[str, tuple[str, bool]] = {}
    for p in order:
        if stop and stop():
            break
        kind, packed = sniff_file(abs_of(root, p, extra))
        if kind:
            out[p] = (kind, packed)
    return out


def kind_label(n: "Node") -> str:
    if not n.kind:
        return ""
    return ("packed " if n.packed else "") + PROGRAM_KINDS.get(n.kind, n.kind)


def program_counts(kinds: dict[str, tuple[str, bool]], status: dict[str, str]) -> dict[str, int]:
    """How many new / modified files are programs, and how many of those look packed."""
    c = {"new": 0, "mod": 0, "packed": 0}
    for p, (_k, packed) in kinds.items():
        st = status.get(p)
        if st in ("new", "mod"):
            c[st] += 1
            c["packed"] += int(packed)
    return c


# tree
@dataclass(eq=False)
class Node:
    name: str
    size: int = 0
    status: str = "old"                  # old | mod | new (a folder shows its worst child)
    is_dir: bool = False
    files: int = 1
    new: int = 0
    mod: int = 0
    more: int = 0                        # >0: stands for that many collapsed files
    pin: bool = False                    # this node, or something under it, is named by a sandbox rule
    acc: str = ""                        # rw | ro | hidden once apply_policy has run ("" = not applied)
    nx: bool = False                     # a no-exec rule covers it
    kind: str = ""                       # pe | elf | script | launcher when sniff_changed recognised a program
    packed: bool = False                 # a program whose bytes look packed, encrypted or compressed
    progs: int = 0                       # new/modified programs under it (this node, if it is one)
    n_ro: int = 0                        # files under it that are read-only for the game
    n_hid: int = 0                       # files under it that are hidden from the game
    n_bad: int = 0                       # new/modified files under it where the profile does not let the game write
    kids: list["Node"] = field(default_factory=list)
    parent: "Node | None" = None
    w: float = 0.0                       # layout weight, set by assign_weights
    _idx: dict = field(default_factory=dict, repr=False)

    @property
    def path(self) -> str:
        parts, n = [], self
        while n is not None and n.parent is not None:
            parts.append(n.name)
            n = n.parent
        return "/".join(reversed(parts))


def _worst(new: int, mod: int) -> str:
    return "new" if new else "mod" if mod else "old"


def build_tree(now: Snap, status: dict[str, str], pins: Iterable[str] = (),
               kinds: dict[str, tuple[str, bool]] | None = None) -> Node:
    """pins: relative paths named by a sandbox rule. Those nodes (and their folders) are never
    folded into a "…N more" group, so a small read-only or hidden item stays on the map."""
    pinset = pins if isinstance(pins, (set, frozenset)) else set(pins)
    root = Node("", is_dir=True)
    for p, (size, _m) in now.items():
        parts = p.split("/")
        cur = root
        pre = ""
        for part in parts[:-1]:
            if pinset:
                pre = pre + "/" + part if pre else part
            nxt = cur._idx.get(part)
            if nxt is None:
                nxt = cur._idx[part] = Node(part, is_dir=True, parent=cur, pin=bool(pinset) and pre in pinset)
                cur.kids.append(nxt)
            cur = nxt
        s = status.get(p, "old")
        kind, packed = (kinds or {}).get(p, ("", False))
        leaf = Node(parts[-1], size=size, status=s, parent=cur, new=int(s == "new"), mod=int(s == "mod"),
                    pin=bool(pinset) and p in pinset, kind=kind, packed=packed,
                    progs=int(bool(kind) and s != "old"))
        cur.kids.append(leaf)
    _finish(root)
    return root


def _finish(n: Node) -> None:
    if not n.is_dir:
        return
    for k in n.kids:
        _finish(k)
    n.size = sum(k.size for k in n.kids)
    n.files = sum(k.files for k in n.kids)
    n.new = sum(k.new for k in n.kids)
    n.mod = sum(k.mod for k in n.kids)
    n.progs = sum(k.progs for k in n.kids)
    n.status = _worst(n.new, n.mod)
    n.pin = n.pin or any(k.pin for k in n.kids)
    n.kids.sort(key=lambda k: -k.size)
    head = n.kids[:KEEP_BIG]
    tail = n.kids[KEEP_BIG:]
    changed = [k for k in tail if k.new or k.mod]
    marked = [k for k in tail if k.pin and not (k.new or k.mod)]
    quiet = [k for k in tail if not (k.new or k.mod or k.pin)]
    shown = head + changed[:KEEP_CHANGED] + marked[:KEEP_MARKED]
    for label, group in (("changed", changed[KEEP_CHANGED:]), ("more", marked[KEEP_MARKED:] + quiet)):
        if not group:
            continue
        if len(group) == 1:
            shown.append(group[0])
            continue
        g = Node(f"…{len(group)} {label}", size=sum(k.size for k in group), is_dir=False,
                 files=sum(k.files for k in group), new=sum(k.new for k in group),
                 mod=sum(k.mod for k in group), more=sum(k.files for k in group), parent=n,
                 progs=sum(k.progs for k in group),
                 pin=any(k.pin for k in group))
        g.status = _worst(g.new, g.mod)
        shown.append(g)
    for k in shown:
        k.parent = n
    n.kids = shown


# treemap layout
def _cap_weights(kids: list, cap: float) -> None:
    """Clamp child weights so no child takes more than `cap` of its folder's total.
    Closed form: with m children clamped to L, L = cap * (m*L + rest), so L = cap*rest / (1 - cap*m).
    cap is raised to 1/len(kids) if lower (the tightest cap that can be met: all tiles equal)."""
    n = len(kids)
    if n < 2 or cap >= 1.0:
        return
    c = max(cap, 1.0 / n)
    ws = sorted((k.w for k in kids), reverse=True)
    rest = sum(ws)
    for m in range(n):
        den = 1.0 - c * m
        if den <= 1e-12:
            return
        limit = c * rest / den
        if ws[m] <= limit * (1 + 1e-12):
            for k in kids:
                if k.w > limit:
                    k.w = limit
            return
        rest -= ws[m]


def assign_weights(n: Node, boost: bool, pins: bool = False, power: float = BOOST, cap: float = 1.0) -> float:
    """Layout weight per node. With boost, area follows size**power (0 = every file the same size,
    1 = true proportions), and anything new or modified gets a minimum share so it can't shrink
    to a sliver. With pins, a node named by a sandbox rule gets the same minimum.
    cap < 1 limits any one tile to that share of its folder (applies with or without boost)."""
    if n.kids:
        ws = [assign_weights(k, boost, pins, power, cap) for k in n.kids]
        if boost:
            changed = [k for k in n.kids if k.new or k.mod or (pins and k.pin)]
            if changed:
                floor = min(CHANGED_FLOOR, CHANGED_CAP / len(changed)) * sum(ws)
                for k in changed:
                    k.w = max(k.w, floor)
        _cap_weights(n.kids, cap)
        n.w = sum(k.w for k in n.kids)
    else:
        n.w = (n.size + 1) ** power if boost else float(n.size + 1)
    return n.w


def squarify(items: list[tuple[object, float]], w: float, h: float) -> list[tuple[object, float, float, float, float]]:
    """Squarified treemap. items = [(key, weight)]; returns [(key, x, y, w, h)] inside a w x h box."""
    items = sorted((i for i in items if i[1] > 0), key=lambda i: -i[1])
    out: list = []
    x = y = 0.0
    rem = sum(i[1] for i in items)
    i = 0
    while i < len(items) and w > 0 and h > 0 and rem > 0:
        side = min(w, h)
        k = w * h / rem
        areas: list[float] = []
        total = 0.0
        best = float("inf")
        j = i
        while j < len(items):
            a = items[j][1] * k
            t2 = total + a
            # areas are non-increasing, so the largest is areas[0] and the smallest is a
            mx = areas[0] if areas else a
            worst = max(side * side * mx / (t2 * t2), t2 * t2 / (side * side * a))
            if areas and worst > best:
                break
            areas.append(a)
            total, best = t2, worst
            j += 1
        th = total / side
        off = 0.0
        for t in range(i, j):
            ln = areas[t - i] / th
            out.append((items[t][0], x, y + off, th, ln) if w >= h else (items[t][0], x + off, y, ln, th))
            off += ln
        if w >= h:
            x += th
            w -= th
        else:
            y += th
            h -= th
        rem -= sum(items[t][1] for t in range(i, j))
        i = j
    return out


@dataclass(eq=False)
class Tile:
    node: Node
    x: float
    y: float
    w: float
    h: float
    depth: int
    inner: bool          # True: children are drawn inside this tile


def layout(top: Node, width: float, height: float, boost: bool = True, max_depth: int = 3,
           header: int = 16, min_inner_w: int = 80, min_inner_h: int = 50, pins: bool = False,
           power: float = BOOST, cap: float = 1.0) -> list[Tile]:
    """Flat list of tiles, parents before children, so painting in order and hit-testing
    in reverse order both behave. Tiles under 3 px are dropped."""
    assign_weights(top, boost, pins, power, cap)
    tiles: list[Tile] = []

    def rec(n: Node, x: float, y: float, w: float, h: float, d: int) -> None:
        for k, kx, ky, kw, kh in squarify([(k, k.w) for k in n.kids], w, h):
            if kw < 3 or kh < 3:
                continue
            inner = bool(k.kids) and d < max_depth - 1 and kw > min_inner_w and kh > min_inner_h
            tiles.append(Tile(k, x + kx, y + ky, kw, kh, d, inner))
            if inner:
                rec(k, x + kx + 1, y + ky + header, kw - 2, kh - header - 1, d + 1)

    rec(top, 0.0, 0.0, float(width), float(height), 0)
    return tiles


def tile_at(tiles: list[Tile], px: float, py: float) -> Tile | None:
    for t in reversed(tiles):
        if t.x <= px < t.x + t.w and t.y <= py < t.y + t.h:
            return t
    return None


# sandbox policy: what the profile lets the game see and write
# What's modelled, and where it comes from (profile.sh / config.sh):
#   built-in   game/ is read-write, prefix/ too for Windows games, home/ for native games while
#              "private home" is on
#   FJ_WL_RW / FJ_WL_RO   extra whitelisted paths. profile.sh reads game.conf AND the defaults
#              file and uses both, so the model does too
#   FJ_EXTRA_ARGS         --blacklist=P (hidden), --read-only=P, --noexec=P. game.conf replaces
#              the defaults file as a whole, as in _wq_list_effective
#   FJ_DEV_BLOCK          /dev nodes hidden from the game (outside the map)
# Anything no rule mounts isn't visible to the game at all, so it counts as hidden.
# Not modelled: the launcher's fixed hides (docker/libvirt/resolver sockets), config.sh arrays
# like HOME_BLACKLIST (bash, never read here) and system directories firejail leaves visible
# read-only. Where rules overlap the most specific mount wins, read-only beats read-write on a
# tie, and a blacklist beats every mount.
EXTRA_ARG_RE = re.compile(r"--(blacklist|read-only|noexec)=(/\S*)")
_MODE_OF_ARG = {"blacklist": "hide", "read-only": "ro", "noexec": "noexec"}
MODE_WORD = {"rw": "read-write", "ro": "read-only", "hide": "hidden", "noexec": "no-exec", "hidden": "hidden"}
_SRC_WORD = {"built-in": "built in", "game.conf": "this game's profile", "defaults": "the default profile"}


@dataclass(frozen=True)
class Rule:
    path: str       # absolute, symlinks resolved when the path exists
    mode: str       # rw | ro | hide | noexec
    key: str        # mount | FJ_WL_RW | FJ_WL_RO | FJ_EXTRA_ARGS | FJ_DEV_BLOCK
    src: str        # built-in | game.conf | defaults

    def describe(self) -> str:
        if self.key == "mount":
            what = f"mounted {MODE_WORD[self.mode]}"
        elif self.key in ("FJ_WL_RW", "FJ_WL_RO"):
            what = f"whitelisted {MODE_WORD[self.mode]}"
        elif self.key == "FJ_DEV_BLOCK":
            what = "device hidden"
        else:
            what = {"hide": "--blacklist", "ro": "--read-only", "noexec": "--noexec"}.get(self.mode, self.mode)
        return f"{what}: {self.path} ({_SRC_WORD.get(self.src, self.src)})"


@dataclass
class Policy:
    tops: dict[str, str]                     # scanned folder -> the real path it is mounted from
                                             # (game/prefix/home, then any extra whitelisted paths)
    rules: list[Rule] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)      # entries profile.sh skips or refuses

    @property
    def extra_tops(self) -> dict[str, str]:
        """Whitelisted folders/files outside the game folder that are scanned and drawn on the map."""
        return {k: v for k, v in self.tops.items() if k not in SCAN_DIRS}

    def signature(self) -> tuple:
        return (tuple(sorted(self.tops.items())), tuple(self.rules))


def _covers(rule_path: str, p: str) -> bool:
    base = rule_path.rstrip("/")
    return p == rule_path or p == base or p.startswith(base + "/")


def _resolve(path: str, real: Callable[[str], str], exists: Callable[[str], bool]) -> str:
    out = real(path) if exists(path) else os.path.normpath(path)
    return out if out == "/" else out.rstrip("/")


def _first(conf: dict, defaults: dict, key: str, builtin: str) -> str:
    for src in (conf, defaults):
        vals = src.get(key)
        if vals:
            return vals[0]
    return builtin


def build_policy(game_path: Path | str, conf: dict[str, list[str]], defaults: dict[str, list[str]],
                 dirs=SCAN_DIRS, real: Callable[[str], str] = os.path.realpath,
                 exists: Callable[[str], bool] = os.path.exists) -> Policy:
    """conf / defaults are the parsed game.conf and profile.defaults.conf (wq_core.parse_kv)."""
    gp = str(game_path)
    native = (conf.get("RUNNER") or [""])[0] == "native"
    pol = Policy(tops={t: _resolve(os.path.join(gp, t), real, exists) for t in dirs})
    seen: set[tuple[str, str, str]] = set()

    def add(path: str, mode: str, key: str, src: str) -> None:
        k = (path, mode, key)
        if k not in seen:
            seen.add(k)
            pol.rules.append(Rule(path, mode, key, src))

    add(pol.tops["game"], "rw", "mount", "built-in")
    if native:
        if _first(conf, defaults, "FJ_PRIVATE_HOME", "1") == "1":
            add(pol.tops["home"], "rw", "mount", "built-in")
    else:
        add(pol.tops["prefix"], "rw", "mount", "built-in")

    both = (("game.conf", conf), ("defaults", defaults))
    for key, mode in (("FJ_WL_RW", "rw"), ("FJ_WL_RO", "ro")):
        for src, d in both:
            for v in d.get(key, []):
                if not v:
                    continue
                if not v.startswith("/"):
                    pol.notes.append(f"{key}: {v} is not an absolute path, ignored at launch")
                elif not exists(v):
                    pol.notes.append(f"{key}: {v} does not exist, skipped at launch")
                else:
                    add(_resolve(v, real, exists), mode, key, src)

    _add_extra_tops(pol, real, exists)

    src, d = ("game.conf", conf) if "FJ_EXTRA_ARGS" in conf else ("defaults", defaults)
    for line in d.get("FJ_EXTRA_ARGS", []):
        line = line.strip()
        m = EXTRA_ARG_RE.fullmatch(line)
        if not m:
            continue                                    # other options do not touch paths
        if ".." in m.group(2).split("/"):
            pol.notes.append(f"{line}: contains .., the launch is cancelled")
            continue
        add(_resolve(m.group(2), real, exists), _MODE_OF_ARG[m.group(1)], "FJ_EXTRA_ARGS", src)

    for src, d in both:
        for v in d.get("FJ_DEV_BLOCK", []):
            if v.startswith("/dev/") and ".." not in v.split("/"):
                if exists(v):
                    add(_resolve(v, real, exists), "hide", "FJ_DEV_BLOCK", src)
                else:
                    pol.notes.append(f"FJ_DEV_BLOCK: {v} does not exist, skipped at launch")
    return pol


def _add_extra_tops(pol: Policy, real: Callable[[str], str], exists: Callable[[str], bool]) -> None:
    """Whitelisted folders and files that sit outside the scanned folders become extra tops, so
    X-Ray scans them and draws them as tiles of their own. Left out: anything already inside a
    scanned folder, anything nested in another extra, and anything so broad that it would pull
    in the game folder or the whole home directory (those stay in the "off this map" line)."""
    home = _resolve(os.path.expanduser("~"), real, exists)
    for r in sorted((r for r in pol.rules if r.key in ("FJ_WL_RW", "FJ_WL_RO")), key=lambda r: (len(r.path), r.path)):
        if any(_covers(t, r.path) for t in pol.tops.values()):
            continue                                    # inside a scanned folder or an earlier extra
        if r.path == "/" or _covers(r.path, home) or any(_covers(r.path, t) for t in pol.tops.values()):
            pol.notes.append(f"{r.path} is too broad to scan and show on the map")
            continue
        name = os.path.basename(r.path.rstrip("/")) or "root"
        n, base = 1, name
        while name in pol.tops:
            n += 1
            name = f"{base}~{n}"
        pol.tops[name] = r.path


def load_policy(game_path: Path | str) -> Policy:
    """Policy for a game folder, read fresh from game.conf and the defaults file next to it."""
    gp = Path(game_path)
    return build_policy(gp, parse_kv(gp / "game.conf"), parse_kv(gp.parent / DEFAULTS_NAME))


def decide(covering: Iterable[Rule]) -> tuple[str, bool, Rule | None]:
    """(rw | ro | hidden, no-exec?, the rule that decided it; None = nothing mounts this path)."""
    hide = best = None
    nx = False
    for r in covering:
        if r.mode == "hide":
            if hide is None or len(r.path) < len(hide.path):
                hide = r                                # the outermost blacklist explains it
        elif r.mode == "noexec":
            nx = True
        elif best is None or (len(r.path), r.mode == "ro") > (len(best.path), best.mode == "ro"):
            best = r
    if hide is not None:
        return "hidden", nx, hide
    if best is not None:
        return best.mode, nx, best
    return "hidden", nx, None


def _inside(pol: Policy) -> dict[str, list[Rule]]:
    """Rules that name something strictly inside a scanned folder, by path relative to the game folder."""
    out: dict[str, list[Rule]] = {}
    for top, rt in pol.tops.items():
        for r in pol.rules:
            if r.path != rt and _covers(rt, r.path):
                out.setdefault(top + r.path[len(rt.rstrip("/")):], []).append(r)
    return out


def pin_paths(pol: Policy | None) -> set[str]:
    """Relative paths build_tree should keep on the map."""
    return set(_inside(pol)) if pol is not None else set()


def apply_policy(root: Node, pol: Policy) -> None:
    """Fill in acc / nx and the n_ro, n_hid, n_bad counts on every node of a built tree."""
    inside = _inside(pol)
    cover = {top: tuple(r for r in pol.rules if _covers(r.path, rt)) for top, rt in pol.tops.items()}

    def walk(n: Node, rel: str | None, cov: tuple) -> None:
        ex = inside.get(rel) if rel is not None else None
        if ex:
            cov = cov + tuple(ex)
        n.acc, n.nx, _why = decide(cov)
        if n.kids:
            n.n_ro = n.n_hid = n.n_bad = 0
            for k in n.kids:
                walk(k, None if k.more else rel + "/" + k.name, cov)      # a "…N more" group is not a path
                n.n_ro += k.n_ro
                n.n_hid += k.n_hid
                n.n_bad += k.n_bad
        else:
            n.n_ro = n.files if n.acc == "ro" else 0
            n.n_hid = n.files if n.acc == "hidden" else 0
            n.n_bad = n.new + n.mod if n.acc != "rw" else 0

    root.n_ro = root.n_hid = root.n_bad = 0
    for k in root.kids:
        walk(k, k.name, cover.get(k.name, ()))
        root.n_ro += k.n_ro
        root.n_hid += k.n_hid
        root.n_bad += k.n_bad
    root.acc = "rw"


def uniform_access(n: Node) -> str:
    """rw | ro | hidden | mixed, from what is under the node rather than from its own rule."""
    if not n.acc or not (n.n_ro or n.n_hid):
        return "rw"
    if n.n_ro == n.files:
        return "ro"
    if n.n_hid == n.files:
        return "hidden"
    return "mixed"


def node_abs(pol: Policy, n: Node) -> str | None:
    while n is not None and n.more:
        n = n.parent
    if n is None or not n.path:
        return None
    top, _, rest = n.path.partition("/")
    rt = pol.tops.get(top)
    return None if rt is None else rt.rstrip("/") + ("/" + rest if rest else "")


def access_info(pol: Policy | None, n: Node) -> tuple[str, str]:
    """(rw | ro | hidden | mixed, one line saying why) for the hover panel."""
    kind = uniform_access(n)
    if kind == "mixed":
        bits = ([f"{n.n_ro:,} read-only"] if n.n_ro else []) + ([f"{n.n_hid:,} hidden"] if n.n_hid else [])
        return kind, "mixed: " + ", ".join(bits) + f" of {n.files:,} files"
    if pol is None:
        return kind, ""
    p = node_abs(pol, n)
    if p is None:
        return kind, ""
    _mode, nx, why = decide(r for r in pol.rules if _covers(r.path, p))
    text = why.describe() if why is not None else "not mounted in the sandbox, so the game cannot see it"
    if nx:
        text += " · no-exec"
    return kind, text


def outside_summary(pol: Policy | None, home: str | None = None, limit: int = 4) -> list[tuple[str, list[str], int]]:
    """Rules about places the map does not show: [(mode, paths to list, how many more)]."""
    if pol is None:
        return []
    home = home or os.path.expanduser("~")
    out = []
    for mode in ("rw", "ro", "hide", "noexec"):
        paths = sorted({("~" + r.path[len(home):] if home != "/" and _covers(home, r.path) else r.path)
                        for r in pol.rules if r.mode == mode
                        and not any(_covers(rt, r.path) for rt in pol.tops.values())})
        if paths:
            out.append((mode, paths[:limit], max(0, len(paths) - limit)))
    return out


# text
def fmt_size(b: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024 or unit == "GB":
            return f"{int(b)} B" if unit == "B" else f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} GB"


def fmt_ago(seconds: float) -> str:
    s = int(max(0, seconds))
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


# command line: take the X-Ray baseline of a game folder without the UI
def default_cache_dir() -> Path:
    """Same folder wq_ui.py uses (CACHE_DIR), so the tab finds a baseline written from the shell."""
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "wq-ui"


def take_baseline(game_path: Path | str, cache_dir: Path | str | None = None) -> tuple[Path, int]:
    """Snapshot the game folders plus the profile's extra whitelisted paths and save them as the baseline,
    exactly as the tab's "Set baseline now" does. Returns (baseline file, number of files recorded)."""
    gp = Path(game_path)
    gp = gp.parent.resolve() / gp.name        # as the UI builds it: resolved QROOT / name (the baseline file name hashes this)
    try:
        extra = load_policy(gp).extra_tops
    except (OSError, KeyError):
        extra = {}
    snap = snapshot(gp, extra=extra)
    dest = baseline_path(cache_dir if cache_dir is not None else default_cache_dir(), gp)
    save_baseline(dest, snap, tops=list(SCAN_DIRS) + list(extra))
    return dest, len(snap)


def main(argv: list[str] | None = None) -> int:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] != "--baseline":
        print("usage: wq_xray_core.py --baseline <game folder>", file=sys.stderr)
        return 2
    if not (Path(args[1]) / "game").is_dir():
        print(f"X-Ray baseline: {args[1]} has no game/ folder", file=sys.stderr)
        return 1
    try:
        dest, n = take_baseline(args[1])
    except OSError as e:
        print(f"X-Ray baseline not saved: {e}", file=sys.stderr)
        return 1
    print(f"X-Ray baseline saved: {n} files ({dest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
