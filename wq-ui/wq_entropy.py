#!/usr/bin/env python3
"""Entropy calculation, block scanning, threshold suggestion, and file discovery."""
from __future__ import annotations

import math
from collections import Counter
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

BLOCK_SIZES: tuple[int, ...] = (64, 128, 256, 512, 1024, 4096)
DEFAULT_BLOCK: int = 256
DEFAULT_BLOCK_SIZE: int = DEFAULT_BLOCK
DEFAULT_THRESHOLD: float = 7.2

# How many bytes the inspector pane reads for a selected block (hex / text view).
HEX_BYTES: int = 512

# Chunk size used by analyse_file when streaming a file through the block scanner.
_READ_CHUNK: int = 1024 * 1024

_SKIP_DIRS: set[str] = {
    ".git",
    "__pycache__",
    ".cache",
    "pfx",
    "drive_c",
    "dosdevices",
    "compatdata",
}

_EXT_WEIGHTS: dict[str, int] = {
    ".exe": 50,
    ".dll": 45,
    ".so": 40,
    ".bin": 38,
    ".dat": 35,
    ".pak": 35,
    ".sh": 30,
    ".py": 25,
    ".b64": 25,
    ".hex": 25,
    ".conf": 15,
    ".cfg": 15,
    ".txt": 10,
    ".log": 5,
}


@dataclass(frozen=True)
class EntropyBlock:
    offset: int
    size: int
    entropy: float
    printable_ratio: float


@dataclass(frozen=True)
class EntropyRun:
    start_offset: int
    end_offset: int
    start_block: int
    end_block: int
    max_entropy: float
    mean_entropy: float

    @property
    def byte_length(self) -> int:
        return max(0, self.end_offset - self.start_offset)


@dataclass(frozen=True)
class GameFileEntry:
    path: Path
    rel_path: str
    size: int
    score: int
    mtime: float = 0.0
    read_count: int = 0

    @property
    def reads(self) -> int:
        # alias used by wq_entropy_tab; the field is named read_count
        return self.read_count

    @property
    def rel(self) -> str:
        # alias used by wq_entropy_tab; the field is named rel_path
        return self.rel_path

    def __str__(self) -> str:
        return self.rel_path


# The tab annotates self.candidates as list[E.CandidateFile]; the discovery
# function returns GameFileEntry, so CandidateFile is just an alias.
CandidateFile = GameFileEntry


class Cancelled(Exception):
    """Raised by analyse_file when the caller's cancelled() callback returns True."""


@dataclass
class Analysis:
    """Result of analyse_file: per-block entropy + printable ratio for one file.

    Attributes mirror what wq_entropy_tab expects:
      .path, .size, .blocks, .block, .ent (list[float]), .printable (list[float])
    """
    path: str
    size: int
    blocks: int
    block: int
    ent: list[float] = field(default_factory=list)
    printable: list[float] = field(default_factory=list)


@dataclass
class Region:
    """A contiguous run of flagged blocks, in both block and byte coordinates.

    .first and .end are block indices (inclusive), as the tab's _center_on expects.
    .offset and .length are byte offsets, .avg is the mean entropy across the run.
    """
    first: int          # first block index (inclusive)
    end: int            # last block index (inclusive)
    offset: int         # byte offset of first block
    length: int         # byte length of the run
    avg: float          # mean entropy over the run


_PRINTABLE = frozenset(list(range(32, 127)) + [9, 10, 13])


def _byte_counts(data: bytes | bytearray | memoryview) -> tuple[dict[int, int], int]:
    """Byte histogram computed in C (Counter over bytes) instead of a Python per-byte loop."""
    raw = bytes(data)
    return Counter(raw), len(raw)


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    """Compute Shannon entropy in bits/byte (0.0 to 8.0) for a byte sequence."""
    counts, length = _byte_counts(data)
    if length == 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(min(8.0, max(0.0, entropy)), 4)


def printable_ratio(data: bytes | bytearray | memoryview) -> float:
    """Return fraction (0.0 to 1.0) of printable ASCII + common whitespace bytes."""
    counts, length = _byte_counts(data)
    if length == 0:
        return 0.0
    return sum(c for b, c in counts.items() if b in _PRINTABLE) / length


def scan_blocks(
    data: bytes | bytearray | memoryview,
    block_size: int = DEFAULT_BLOCK,
) -> list[EntropyBlock]:
    """Split byte buffer into fixed-size blocks and calculate per-block entropy."""
    if block_size <= 0:
        raise ValueError("block_size must be positive")

    view = memoryview(data)
    total = len(view)
    blocks: list[EntropyBlock] = []

    for offset in range(0, total, block_size):
        chunk = view[offset : min(offset + block_size, total)]
        blocks.append(
            EntropyBlock(
                offset=offset,
                size=len(chunk),
                entropy=shannon_entropy(chunk),
                printable_ratio=printable_ratio(chunk),
            )
        )
    return blocks


def scan_file_blocks(
    path: str | Path,
    block_size: int = DEFAULT_BLOCK,
    max_bytes: int | None = None,
) -> list[EntropyBlock]:
    """Read a file (optionally capped at max_bytes) and return EntropyBlock entries."""
    file_path = Path(path)
    with file_path.open("rb") as fh:
        raw = fh.read(max_bytes) if max_bytes is not None else fh.read()
    return scan_blocks(raw, block_size=block_size)


def _median(sorted_vals: list[float]) -> float:
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return sorted_vals[mid]
    return 0.5 * (sorted_vals[mid - 1] + sorted_vals[mid])


def suggest_threshold(
    values: Iterable[float],
    floor: float = 4.5,
    plateau_cap: float = 7.2,
    ceiling: float = 7.95,
) -> float:
    """Suggest an entropy threshold using median + MAD with a high-entropy plateau guard."""
    vals = [float(v) for v in values if v is not None and math.isfinite(float(v))]
    if not vals:
        return DEFAULT_THRESHOLD

    ordered = sorted(vals)
    med = _median(ordered)
    deviations = sorted(abs(v - med) for v in ordered)
    mad = _median(deviations)

    sigma = 1.4826 * mad

    if med >= 6.8 and sigma < 0.25:
        plateau_thresh = max(floor, med - 0.15)
        return round(min(plateau_thresh, plateau_cap, ceiling), 2)

    suggested = med + max(1.5 * sigma, 0.35)
    return round(max(floor, min(suggested, ceiling)), 2)


def _build_run(blocks: list[EntropyBlock], start_idx: int, end_idx: int) -> EntropyRun:
    slice_blocks = blocks[start_idx : end_idx + 1]
    start_offset = slice_blocks[0].offset
    end_offset = slice_blocks[-1].offset + slice_blocks[-1].size
    max_ent = max(b.entropy for b in slice_blocks)
    mean_ent = sum(b.entropy for b in slice_blocks) / len(slice_blocks)
    return EntropyRun(
        start_offset=start_offset,
        end_offset=end_offset,
        start_block=start_idx,
        end_block=end_idx,
        max_entropy=round(max_ent, 4),
        mean_entropy=round(mean_ent, 4),
    )


def find_flagged_runs(
    blocks: list[EntropyBlock],
    threshold: float,
    min_run_blocks: int = 1,
) -> list[EntropyRun]:
    """Group contiguous blocks whose entropy meets or exceeds threshold into runs."""
    if not blocks or min_run_blocks < 1:
        return []

    runs: list[EntropyRun] = []
    run_start_idx: int | None = None

    for idx, blk in enumerate(blocks):
        flagged = blk.entropy >= threshold
        if flagged and run_start_idx is None:
            run_start_idx = idx
        elif not flagged and run_start_idx is not None:
            if idx - run_start_idx >= min_run_blocks:
                runs.append(_build_run(blocks, run_start_idx, idx - 1))
            run_start_idx = None

    if run_start_idx is not None and (len(blocks) - run_start_idx) >= min_run_blocks:
        runs.append(_build_run(blocks, run_start_idx, len(blocks) - 1))

    return runs


def flag_runs(
    ent: list[float],
    threshold: float,
    block_size: int,
    total_size: int,
    min_run_blocks: int = 1,
) -> list[Region]:
    """Turn a per-block entropy list into Region records for the tab's flagged list.

    Uses the same "contiguous blocks at/above threshold" rule as find_flagged_runs,
    but works directly on the raw lists that Analysis carries.
    """
    if not ent or block_size <= 0:
        return []

    regions: list[Region] = []
    run_start: int | None = None

    def close(start: int, end: int) -> None:
        if end - start + 1 < min_run_blocks:
            return
        offset = start * block_size
        # last block may be short
        last_end = min(total_size, (end + 1) * block_size)
        length = max(0, last_end - offset)
        avg = sum(ent[start : end + 1]) / (end - start + 1)
        regions.append(Region(first=start, end=end, offset=offset, length=length, avg=round(avg, 3)))

    for i, e in enumerate(ent):
        if e >= threshold and run_start is None:
            run_start = i
        elif e < threshold and run_start is not None:
            close(run_start, i - 1)
            run_start = None

    if run_start is not None:
        close(run_start, len(ent) - 1)

    return regions


def _parse_read_counts(game_root: Path) -> dict[str, int]:
    """Best-effort read-count lookup from monitor/alert logs if present."""
    counts: dict[str, int] = {}
    logs_dir = game_root / "logs"
    if not logs_dir.is_dir():
        return counts

    try:
        logs = sorted((f for f in logs_dir.glob("*.log") if f.is_file() and not f.is_symlink()),
                      key=lambda f: f.stat().st_mtime, reverse=True)[:20]
    except OSError:
        return counts
    for log_file in logs:
        try:
            with log_file.open("rb") as fh:                  # the tail only: a long run's log can be huge
                size = os.fstat(fh.fileno()).st_size
                fh.seek(max(0, size - 2 * 1024 * 1024))
                text = fh.read().decode("utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            for marker in ("game/", "sh_chain/"):
                idx = line.find(marker)
                if idx != -1:
                    token = line[idx:].split()[0].strip(",:;()[]'\"")
                    if token.startswith("game/"):
                        token = token[5:]
                    if token:
                        counts[token] = counts.get(token, 0) + 1
    return counts


# Folders inside the prefix roots that Wine/Proton create themselves (matched in lower case)
_PREFIX_STOCK: frozenset[str] = frozenset({"common files", "internet explorer", "windows nt", "windows media player",
                                           "windows defender", "wine", "microsoft"})

# Places inside the Wine prefix where installers put their files. drive_c/windows is left out on
# purpose: it holds thousands of stock Wine files that would drown out the installed program.
# (windows/temp is kept, since droppers like to use it.)
PREFIX_ROOTS: tuple[str, ...] = (
    "prefix/drive_c/Program Files",
    "prefix/drive_c/Program Files (x86)",
    "prefix/drive_c/ProgramData",
    "prefix/drive_c/users",
    "prefix/drive_c/windows/temp",
)


def discover_game_files(
    game_dir: str | Path | None,
    max_files: int = 2000,
    max_scan: int = 100_000,
    max_file_bytes: int = 64 * 1024 * 1024,
    include_prefix: bool = False,
    sort: str = "smart",
) -> list[GameFileEntry]:
    """Discover candidate files under a game directory and rank them by heuristic score.

    With include_prefix=True the installed files in the Wine prefix (Program Files, ProgramData,
    users, windows/temp) are listed too, so an installer's output can be checked, not just the
    installer itself.

    `sort` is "smart", "reads" or "size". The list is ordered by it BEFORE max_files is applied,
    so the cut keeps the files the chosen order puts first (e.g. the largest file for "size").
    """
    if not game_dir:
        return []

    root = Path(game_dir)
    if not root.is_dir():
        return []

    # If there's a game/ folder, start the search there.
    # This prevents listing launch scripts or config files at the quarantine root.
    search_root = root / "game" if (root / "game").is_dir() else root

    read_counts = _parse_read_counts(root)

    entries: list[GameFileEntry] = []

    # Additional dirs to skip that aren't in the global _SKIP_DIRS
    local_skip = {"logs", ".home-snapshot"}

    walk_roots = [search_root]
    if include_prefix:
        walk_roots += [root / r for r in PREFIX_ROOTS if (root / r).is_dir() and not (root / r).is_symlink()]

    scanned = [0]                               # files looked at in the current root

    def _walk():
        for wr in walk_roots:
            scanned[0] = 0                      # each root has its own budget: a huge game/ must not starve the prefix
            in_prefix = wr != search_root
            # os.walk does not follow directory symlinks (followlinks=False), and the prefix is
            # writable by the program being tested, so a link planted there must not be read.
            for dirpath, dirnames, filenames in os.walk(wr):
                if scanned[0] >= max_scan:      # a game with a huge asset tree must not freeze the tab
                    break
                # prune skip dirs in-place so os.walk doesn't descend into them. Wine's own stock
                # folders (Common Files, Internet Explorer, ...) are left out of the prefix too:
                # they are not what an installer added and would bury it in the list.
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and d not in local_skip
                               and not (in_prefix and d.lower() in _PREFIX_STOCK)]
                yield dirpath, filenames

    seen: set[str] = set()
    for dirpath, filenames in _walk():
        for fname in filenames:
            scanned[0] += 1
            key = os.path.join(dirpath, fname)
            if key in seen:
                continue
            seen.add(key)
            try:
                st = os.lstat(key)              # one call; a symlink shows as a link and is skipped
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size == 0 or st.st_size > max_file_bytes:     # nothing to plot in an empty file
                continue
            fpath = Path(key)

            # We compute the relative path from the *quarantine root* so the
            # list displays "game/foo.exe" rather than just "foo.exe".
            try:
                rel = str(fpath.relative_to(root))
            except ValueError:
                rel = fname

            # Look up read counts (which are stored relative to game/)
            rc_key = rel[len("game/"):] if rel.startswith("game/") else rel
            rc = read_counts.get(rc_key, 0)

            ext = fpath.suffix.lower()
            score = _EXT_WEIGHTS.get(ext, 0)
            score += 5                          # non-empty (checked above)
            if rel.startswith("game" + os.sep):
                score += 5
            if rc:
                score += min(rc, 20) * 2

            entries.append(
                GameFileEntry(
                    path=fpath,
                    rel_path=rel,
                    size=st.st_size,
                    score=score,
                    mtime=st.st_mtime,
                    read_count=rc,
                )
            )

    entries.sort(key=_sort_key(sort))
    return entries[:max_files]


def _sort_key(mode: str):
    """Sort key for discover_game_files. Unknown modes fall back to "smart"."""
    if mode == "reads":
        return lambda e: (-e.read_count, -e.size, -e.score, e.rel_path.lower())
    if mode == "size":
        return lambda e: (-e.size, -e.read_count, -e.score, e.rel_path.lower())
    # score, then recency, then name
    return lambda e: (-e.score, -e.mtime, e.rel_path)


def _open_regular(path: str | Path):
    """Open `path` read-only, refusing symlinks and anything that is not a regular file.

    The Wine prefix is writable by the program under test, so a planted symlink
    (e.g. to a private key in the host home) must never be read through the UI.
    """
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def analyse_file(
    path: str | Path,
    block_size: int = DEFAULT_BLOCK,
    progress: Callable[[int, int], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> Analysis:
    """Stream `path` through the block scanner, emitting per-block entropy.

    `progress(done, total)` is called periodically with byte counts; `cancelled()`
    is polled between chunks and, if it returns True, raises Cancelled.
    """
    if block_size <= 0 or block_size % 256:
        raise ValueError("block_size must be a positive multiple of 256")

    file_path = Path(path)

    ent: list[float] = []
    printable: list[float] = []
    done = 0

    with _open_regular(file_path) as fh:
        total = os.fstat(fh.fileno()).st_size
        leftover = b""
        while True:
            if cancelled is not None and cancelled():
                raise Cancelled()

            chunk = fh.read(_READ_CHUNK)
            if not chunk:
                break
            buf = leftover + chunk
            done += len(chunk)

            # consume whole blocks; keep the tail for the next chunk
            n_full = len(buf) // block_size
            usable = n_full * block_size
            for off in range(0, usable, block_size):
                piece = buf[off : off + block_size]
                ent.append(shannon_entropy(piece))
                printable.append(printable_ratio(piece))
            leftover = buf[usable:]

            if progress is not None and total:
                progress(min(done, total), total)

        # final short block, if any
        if leftover:
            ent.append(shannon_entropy(leftover))
            printable.append(printable_ratio(leftover))

    if progress is not None and total:
        progress(total, total)

    return Analysis(
        path=str(file_path),
        size=total,
        blocks=len(ent),
        block=block_size,
        ent=ent,
        printable=printable,
    )


def read_bytes(path: str | Path, offset: int, count: int) -> bytes:
    """Read up to `count` bytes starting at `offset` from `path`."""
    if count <= 0 or offset < 0:
        return b""
    file_path = Path(path)
    with _open_regular(file_path) as fh:
        fh.seek(offset)
        return fh.read(count)


def hexdump(data: bytes | bytearray | memoryview, base_offset: int = 0) -> str:
    """Classic 16-bytes-per-row hex + ASCII dump, with offsets relative to base_offset."""
    view = memoryview(data)
    lines: list[str] = []
    for row in range(0, len(view), 16):
        chunk = bytes(view[row : row + 16])
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # pad to 16 columns so the ASCII column aligns
        hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_offset + row:08X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)
