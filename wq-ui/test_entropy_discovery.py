import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_entropy as E  # noqa: E402

# --- discovery: installed files in the prefix (opt-in), symlinks never listed
q = Path(tempfile.mkdtemp())
(q / "game").mkdir()
(q / "game" / "setup.exe").write_bytes(b"MZ" + b"\x01" * 100)
pf = q / "prefix" / "drive_c" / "Program Files" / "Tool"
pf.mkdir(parents=True)
(pf / "tool.dll").write_bytes(b"MZ" + b"\x02" * 100)
(q / "prefix" / "drive_c" / "windows" / "system32").mkdir(parents=True)
(q / "prefix" / "drive_c" / "windows" / "system32" / "stock.dll").write_bytes(b"MZ" + b"\x03" * 100)
(q / "prefix" / "drive_c" / "windows" / "temp").mkdir(parents=True)
(q / "prefix" / "drive_c" / "windows" / "temp" / "drop.exe").write_bytes(b"MZ" + b"\x04" * 100)
secret = q / "secret.txt"
secret.write_text("host secret")
os.symlink(secret, pf / "link.txt")            # planted link must not be listed
os.symlink(q.parent, pf / "dirlink")           # nor followed
rels = {e.rel_path for e in E.discover_game_files(q)}
assert rels == {"game/setup.exe"}, rels        # default: unchanged, game/ only
rels = {e.rel_path for e in E.discover_game_files(q, include_prefix=True)}
assert rels == {"game/setup.exe",
                "prefix/drive_c/Program Files/Tool/tool.dll",
                "prefix/drive_c/windows/temp/drop.exe"}, rels   # stock windows/ files and symlinks excluded
# empty files, Wine's stock prefix folders and a log-heavy tree
(q / "game" / "empty.dll").write_bytes(b"")
for stock in ("Common Files", "Internet Explorer", "Windows NT"):
    d = q / "prefix" / "drive_c" / "Program Files" / stock
    d.mkdir(parents=True)
    (d / "wine_stock.dll").write_bytes(b"MZ" + b"\x05" * 50)
rels = {e.rel_path for e in E.discover_game_files(q, include_prefix=True)}
assert "game/empty.dll" not in rels, rels
assert not any("wine_stock" in r for r in rels), rels
assert "prefix/drive_c/Program Files/Tool/tool.dll" in rels
big = q / "game" / "many"
big.mkdir()
for i in range(30):
    (big / f"f{i}.bin").write_bytes(b"x" * 10)
assert len(E.discover_game_files(q, max_files=10)) == 10
assert len(E.discover_game_files(q, max_scan=5)) <= 5 + 30          # the walk stops early, never errors
# the size order must see every file, not just the top of the smart order: the cut happens after sorting
cap = Path(tempfile.mkdtemp())
(cap / "game" / "lib").mkdir(parents=True)
for i in range(2500):
    (cap / "game" / "lib" / f"m{i}.dll").write_bytes(b"MZ" + bytes([i % 250]) * 100)
(cap / "game" / "assets.txt").write_bytes(b"x" * 500_000)     # largest file, low extension weight
smart = E.discover_game_files(cap, sort="smart")
assert len(smart) == 2000 and not any(e.rel_path.endswith("assets.txt") for e in smart)
by_size = E.discover_game_files(cap, sort="size")
assert by_size[0].rel_path == "game/assets.txt", by_size[0].rel_path
print("entropy discovery tests ok")
