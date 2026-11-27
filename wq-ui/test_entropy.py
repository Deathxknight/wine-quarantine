import os
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_entropy as E  # noqa: E402

rng = random.Random(7)
noise = bytes(rng.getrandbits(8) for _ in range(8192))
text = (b"def main():\n    print('hello world')\n" * 300)[:8192]

# --- per-block maths
assert (E.shannon_entropy(b""), E.printable_ratio(b"")) == (0.0, 0.0)
bs = lambda b: (E.shannon_entropy(b), E.printable_ratio(b))
h0, p0 = bs(b"\x00" * 256)
assert h0 == 0.0 and p0 == 0.0          # zeros: no entropy, not printable
hn, _ = bs(noise[:256])
assert 7.0 < hn <= 8.0, hn              # random bytes sit near the top
ht, pt = bs(text[:256])
assert 3.0 < ht < 5.5 and pt == 1.0, (ht, pt)   # source code: mid entropy, all printable

# --- streamed analysis of a real file
d = Path(tempfile.mkdtemp())
f = d / "sample.bin"
f.write_bytes(b"\x00" * 4096 + noise + text)     # 4 KB zeros, 8 KB noise, 8 KB text
B = 1024   # 256-byte blocks are too small: random data only clears 7.2 about a third of the time
a = E.analyse_file(str(f), B)
assert a.size == len(f.read_bytes()) and a.blocks == a.size // B
assert a.ent[0] == 0.0 and a.ent[4] > 7.0 and a.ent[-1] < 5.5

# flagged runs: the noise section is one run, the zeros and text are not
runs = E.flag_runs(a.ent, E.DEFAULT_THRESHOLD, B, a.size)
assert len(runs) == 1, runs
r = runs[0]
assert r.first == 4 and r.end == 11 and r.offset == 4096 and r.length == 8192 and r.avg > 7.0

# a higher threshold can drop it; a single hot block is not a run
assert E.flag_runs(a.ent, 7.99, B, a.size) == []
assert E.flag_runs([0, 8, 0], 7.2, 256, 768, min_run_blocks=2) == []
assert len(E.flag_runs([8, 8, 0], 7.2, 256, 768)) == 1

# run that reaches the end of a short final block is clipped to the file size
tail = E.flag_runs([8.0, 8.0], 7.2, 256, 300)
assert tail[0].length == 300 - 0

# --- hex view and targeted reads
assert E.read_bytes(str(f), 4096, 4) == noise[:4]
line = E.hexdump(b"MZ\x90\x00abc", 0x10).splitlines()[0]
assert line.startswith("00000010  4D 5A 90 00") and line.endswith("|MZ..abc|"), line

# --- safety: symlinks and directories are refused, cancel works, bad sizes rejected
link = d / "link.bin"
os.symlink(f, link)
for bad in (link, d):
    try:
        E.analyse_file(str(bad), 256)
    except (OSError, ValueError):
        pass
    else:
        raise AssertionError(f"accepted {bad}")

def stop():
    return True
try:
    E.analyse_file(str(f), 1024, cancelled=stop)
except E.Cancelled:
    pass
else:
    raise AssertionError("cancel ignored")

try:
    E.analyse_file(str(f), 333)
except ValueError:
    pass
else:
    raise AssertionError("odd block size accepted")

empty = d / "empty"
empty.write_bytes(b"")
ea = E.analyse_file(str(empty), 1024)
assert ea.blocks == 0 and E.flag_runs(ea.ent, 7.2, 1024, 0) == []

print("test_entropy: all checks passed")
