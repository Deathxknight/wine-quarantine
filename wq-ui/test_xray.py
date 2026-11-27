import sys, os, tempfile, time, random
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_xray_core as x

d = Path(tempfile.mkdtemp())
g = d / "Game"


def put(rel, data=b"x", mtime=None):
    p = g / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    if mtime:
        os.utime(p, ns=(mtime, mtime))
    return p


# --- snapshot: only the writable folders, symlinks never followed
put("game/a.exe", b"A" * 1000, 1_000_000_000)
put("game/data/pak0.bin", b"B" * 5000, 1_000_000_000)
put("prefix/drive_c/windows/system.reg", b"R" * 300, 1_000_000_000)
put("logs/launch-1.log", b"noise")                  # app bookkeeping, not scanned
put("game.conf", b"EXE=a.exe\n")                     # not scanned
outside = d / "outside"; outside.mkdir(); (outside / "secret.txt").write_text("s")
os.symlink(outside, g / "game" / "link-out")
base = x.snapshot(g)
print(sorted(base))
assert sorted(base) == ["game/a.exe", "game/data/pak0.bin", "game/link-out", "prefix/drive_c/windows/system.reg"]
assert not any("secret" in p for p in base)          # symlinked folder not entered
assert "logs/launch-1.log" not in base and "game.conf" not in base
assert x.snapshot(g, stop=lambda: True) == {}        # stop callback honoured

# --- baseline round-trip, atomic, no litter, bad file tolerated
bp = x.baseline_path(d / "cache", g)
x.save_baseline(bp, base, taken=123.0)
back, taken = x.load_baseline(bp)
assert back == base and taken == 123.0
assert not list(bp.parent.glob(".wq-*.tmp"))
assert x.baseline_path(d / "cache", g) == bp and x.baseline_path(d / "cache", d / "other" / "Game") != bp
bp.write_bytes(b"not gzip"); assert x.load_baseline(bp) == (None, 0.0)
assert x.load_baseline(d / "nope.json.gz") == (None, 0.0)
x.save_baseline(bp, base)

# --- diff: new, modified (size or mtime), gone, unchanged
put("prefix/drive_c/users/me/save1.sav", b"S" * 40)                       # new
put("game/data/pak0.bin", b"B" * 6000, 1_000_000_000)                     # size changed
put("prefix/drive_c/windows/system.reg", b"R" * 300, 2_000_000_000)       # same size, newer mtime
(g / "game/a.exe").unlink()                                              # gone
now = x.snapshot(g)
st, gone = x.diff(x.load_baseline(bp)[0], now)
print(st, gone)
assert st == {"prefix/drive_c/users/me/save1.sav": "new", "game/data/pak0.bin": "mod",
              "prefix/drive_c/windows/system.reg": "mod"}
assert gone == ["game/a.exe"]
assert x.diff(None, now) == ({}, [])                                     # no baseline: nothing is "new"
sm = x.summary(now, st, gone)
assert (sm["new"], sm["mod"], sm["gone"], sm["new_bytes"]) == (1, 2, 1, 40)

# --- tree: counts add up, worst status bubbles up, paths right
root = x.build_tree(now, st)
assert root.files == len(now) and root.new == 1 and root.mod == 2 and root.status == "new"
pre = next(k for k in root.kids if k.name == "prefix")
assert pre.status == "new" and pre.size == 340
leaf = pre.kids[0]
while leaf.kids:
    leaf = leaf.kids[0]
assert leaf.path.startswith("prefix/") and leaf.parent is not None

# --- pruning never hides a change, and counts stay exact
big = {f"game/f{i:04d}.dat": (1000 + i, 1) for i in range(500)}
big_st = {f"game/f{i:04d}.dat": "new" for i in (3, 77, 480)}
big_st.update({f"game/f{i:04d}.dat": "mod" for i in (10, 11)})
t = x.build_tree(big, big_st)
game = t.kids[0]
names = {k.name for k in game.kids}
assert {"f0003.dat", "f0077.dat", "f0480.dat", "f0010.dat", "f0011.dat"} <= names, "changed files must stay visible"
assert len(game.kids) < 60 and game.files == 500 and game.new == 3 and game.mod == 2
assert any(k.more for k in game.kids)
assert sum(k.size for k in game.kids) == game.size
many = {f"prefix/n{i}.dll": (10, 1) for i in range(400)}
t2 = x.build_tree(many, {p: "new" for p in many})
grp = [k for k in t2.kids[0].kids if k.more]
assert grp and grp[0].status == "new" and t2.new == 400 and len(t2.kids[0].kids) <= x.KEEP_BIG + x.KEEP_CHANGED + 2

# --- squarify: areas conserved, nothing overlaps, everything inside the box
random.seed(1)
items = [(i, random.random() ** 3 * 100 + 0.1) for i in range(120)]
W, H = 837.0, 421.0
rects = x.squarify(items, W, H)
assert len(rects) == 120
tot = sum(w * h for _k, _x, _y, w, h in rects)
assert abs(tot - W * H) < 1e-6 * W * H, tot
wsum = sum(i[1] for i in items)
for k, _x, _y, w, h in rects:
    assert abs(w * h - items[k][1] / wsum * W * H) < 1e-6 * W * H
    assert -1e-9 <= _x and -1e-9 <= _y and _x + w <= W + 1e-6 and _y + h <= H + 1e-6
for i in range(len(rects)):
    for j in range(i + 1, len(rects)):
        a, b = rects[i], rects[j]
        ox = min(a[1] + a[3], b[1] + b[3]) - max(a[1], b[1])
        oy = min(a[2] + a[4], b[2] + b[4]) - max(a[2], b[2])
        assert not (ox > 1e-6 and oy > 1e-6), (a, b)
assert x.squarify([], 10, 10) == [] and x.squarify([("a", 0)], 10, 10) == [] and x.squarify([("a", 1)], 0, 10) == []

# --- layout: inside the box, children inside parents, boost keeps a tiny new file visible
junk = {f"game/big{i}.pak": (3_000_000_000, 1) for i in range(5)}
junk["prefix/save.sav"] = (200, 1)
js = {"prefix/save.sav": "new"}
tt = x.build_tree(junk, js)
for boost in (True, False):
    tiles = x.layout(tt, 900, 500, boost=boost)
    for tl in tiles:
        assert tl.x >= -1e-6 and tl.y >= -1e-6 and tl.x + tl.w <= 900 + 1e-6 and tl.y + tl.h <= 500 + 1e-6
    red = [tl for tl in tiles if tl.node.new and tl.w * tl.h >= 100]          # a visible tile that holds the new file
    print("boost" if boost else "true scale", "->", "new file visible" if red else "new file invisible")
    assert bool(red) == boost
    if boost:
        assert all(tl.node.status == "new" for tl in red)                        # and it is painted as new
# --- size ratio (power) and max tile share (cap)
def _share(tiles, name):               # share of the three files' combined area (the game/ tile adds a header)
    area = {tl.node.name: tl.w * tl.h for tl in tiles if tl.node.name in ("huge.pak", "mid.bin", "tiny.cfg")}
    return area[name] / sum(area.values())
pw_tree = x.build_tree({"game/huge.pak": (4_000_000_000, 1), "game/mid.bin": (5_000_000, 1), "game/tiny.cfg": (300, 1)}, {})
shares = [_share(x.layout(pw_tree, 900, 500, power=pw), "huge.pak") for pw in (1.0, 0.35, 0.1, 0.0)]
assert shares == sorted(shares, reverse=True), shares                    # lower ratio shrinks the big file
assert abs(_share(x.layout(pw_tree, 900, 500, power=0.0), "tiny.cfg") - 1 / 3) < 0.01   # 0 = equal tiles
assert _share(x.layout(pw_tree, 900, 500, boost=False), "huge.pak") > 0.99                 # true scale: it swallows the map
for cap in (0.6, 0.4, 0.34):
    capped = x.layout(pw_tree, 900, 500, boost=False, cap=cap)
    assert _share(capped, "huge.pak") <= max(cap, 1 / 3) + 0.01, cap      # nobody exceeds the cap
assert _share(x.layout(pw_tree, 900, 500, power=0.35, cap=1.0), "huge.pak") == _share(x.layout(pw_tree, 900, 500), "huge.pak")
print("size ratio / max tile share -> ok")

tiles = x.layout(root, 900, 500)
by = {id(tl.node): tl for tl in tiles}
for tl in tiles:
    p = tl.node.parent
    if p is not root and id(p) in by:
        q = by[id(p)]
        assert q.inner and tl.x >= q.x and tl.y >= q.y + 16 and tl.x + tl.w <= q.x + q.w + 1e-6 and tl.y + tl.h <= q.y + q.h + 1e-6
hit = x.tile_at(tiles, tiles[-1].x + 1, tiles[-1].y + 1)
assert hit is not None and x.tile_at(tiles, -5, -5) is None
assert x.layout(x.build_tree({}, {}), 300, 200) == []                      # empty game: no tiles, no crash

# --- speed: a Wine-prefix-sized tree must not stall the UI thread
huge = {f"prefix/drive_c/windows/d{i % 300}/f{i}.dll": (random.randint(1, 10**6), 1) for i in range(120_000)}
hs = {p: "new" for p in list(huge)[:40_000]}
t0 = time.time(); ht = x.build_tree(huge, hs); t1 = time.time(); x.layout(ht, 1200, 700); t2 = time.time()
print(f"120k files: build_tree {t1 - t0:.2f}s, layout {t2 - t1:.2f}s")
assert ht.files == 120_000 and ht.new == 40_000 and t2 - t0 < 8

# --- sandbox policy: the profile's whitelists and blacklists resolved against the map
pd = Path(tempfile.mkdtemp())
pg = pd / "q" / "Game"
for rel in ("game/bin/run.exe", "game/data/pak0.bin", "game/data/secret.key", "game/saves/s1.sav",
            "prefix/drive_c/windows/system.reg", "prefix/drive_c/users/me/doc.txt"):
    f = pg / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_bytes(b"x" * 100)
ext = pd / "shared"; ext.mkdir(); ext2 = pd / "roms"; ext2.mkdir()
dev = pd / "fakedev"; dev.mkdir()
(pd / "q" / "profile.defaults.conf").write_text(f"FJ_WL_RO={ext2}\n")
g_conf = {"EXE": ["bin/run.exe"], "FJ_WL_RW": [str(ext), "relative/path", str(pd / "nope")], "FJ_WL_RO": [str(ext2)],
          "FJ_EXTRA_ARGS": [f"--blacklist={pg}/game/data/secret.key", f"--read-only={pg}/game/data",
                            f"--noexec={pg}/game/saves", "--nosound", "--blacklist=/a/../b"]}
dfl = x.parse_kv(pd / "q" / "profile.defaults.conf")
pol = x.build_policy(pg, g_conf, dfl)
modes = {(r.key, r.mode, r.src) for r in pol.rules}
print(sorted(modes))
assert ("mount", "rw", "built-in") in modes and sum(r.key == "mount" for r in pol.rules) == 2       # game/ + prefix/
assert ("FJ_WL_RW", "rw", "game.conf") in modes and ("FJ_WL_RO", "ro", "game.conf") in modes
assert not any(r.path.endswith("relative/path") or r.path.endswith("nope") for r in pol.rules)
assert len(pol.notes) == 3 and any("not an absolute" in n for n in pol.notes) and any("does not exist" in n for n in pol.notes)
assert any("contains .." in n for n in pol.notes)
assert [r.mode for r in pol.rules if r.key == "FJ_EXTRA_ARGS"] == ["hide", "ro", "noexec"]           # --nosound is not a path rule
# FJ_WL_* is the union of game.conf and the defaults file (profile.sh reads both), FJ_EXTRA_ARGS is game.conf-or-defaults
u = x.build_policy(pg, {"FJ_WL_RO": [str(ext)]}, dfl)
assert {(r.path, r.src) for r in u.rules if r.key == "FJ_WL_RO"} == {(os.path.realpath(ext), "game.conf"), (os.path.realpath(ext2), "defaults")}
d_args = {"FJ_EXTRA_ARGS": [f"--blacklist={pg}/prefix"]}
assert [r.src for r in x.build_policy(pg, {}, d_args).rules if r.key == "FJ_EXTRA_ARGS"] == ["defaults"]
assert [r for r in x.build_policy(pg, {"FJ_EXTRA_ARGS": [""]}, d_args).rules if r.key == "FJ_EXTRA_ARGS"] == []   # empty line = none
# runner: native mounts home/ (while private home is on) instead of prefix/
nat = x.build_policy(pg, {"RUNNER": ["native"]}, {})
assert {os.path.basename(r.path) for r in nat.rules if r.key == "mount"} == {"game", "home"}
assert {os.path.basename(r.path) for r in x.build_policy(pg, {"RUNNER": ["native"], "FJ_PRIVATE_HOME": ["0"]}, {}).rules if r.key == "mount"} == {"game"}
# dev blocks: only existing /dev nodes, no ..
fx = lambda p: p == "/dev/video0" or os.path.exists(p)
dv = x.build_policy(pg, {"FJ_DEV_BLOCK": ["/dev/video0", "/dev/nothere", "/etc/passwd", "/dev/../etc"]}, {}, exists=fx, real=lambda p: p)
assert [r.path for r in dv.rules if r.key == "FJ_DEV_BLOCK"] == ["/dev/video0"] and len(dv.notes) == 1

# decide(): most specific mount wins, read-only wins a tie, a blacklist beats every mount, nothing mounted = hidden
R = x.Rule
assert x.decide([R("/a", "rw", "mount", "built-in"), R("/a/b", "ro", "FJ_WL_RO", "game.conf")])[:2] == ("ro", False)
assert x.decide([R("/a", "ro", "FJ_WL_RO", "game.conf"), R("/a/b", "rw", "FJ_WL_RW", "game.conf")])[0] == "rw"
assert x.decide([R("/a", "rw", "FJ_WL_RW", "game.conf"), R("/a", "ro", "FJ_EXTRA_ARGS", "game.conf")])[0] == "ro"
assert x.decide([R("/a", "rw", "mount", "built-in"), R("/a/b", "hide", "FJ_EXTRA_ARGS", "game.conf")])[0] == "hidden"
assert x.decide([R("/a", "hide", "FJ_EXTRA_ARGS", "game.conf"), R("/a/b", "rw", "FJ_WL_RW", "game.conf")])[0] == "hidden"
assert x.decide([]) == ("hidden", False, None) and x.decide([R("/a", "rw", "mount", "built-in"), R("/a", "noexec", "FJ_EXTRA_ARGS", "game.conf")])[:2] == ("rw", True)

# apply_policy: inheritance, exact paths, counts
psnap = x.snapshot(pg)
pst = {"game/data/secret.key": "mod", "game/data/pak0.bin": "new", "game/saves/s1.sav": "mod", "prefix/drive_c/users/me/doc.txt": "new"}
pt = x.build_tree(psnap, pst, pins=x.pin_paths(pol))
x.apply_policy(pt, pol)
node = lambda path: next(n for n in _walk(pt) if n.path == path)
def _walk(n):
    yield n
    for k in n.kids:
        yield from _walk(k)
assert node("game/bin/run.exe").acc == "rw" and node("game/saves/s1.sav").acc == "rw" and node("game/saves/s1.sav").nx
assert node("game/data").acc == "ro" and node("game/data/pak0.bin").acc == "ro" and node("game/data/secret.key").acc == "hidden"
assert x.uniform_access(node("game/data")) == "mixed" and x.uniform_access(node("game/data/pak0.bin")) == "ro"
assert x.uniform_access(node("game/bin")) == "rw" and x.uniform_access(node("prefix")) == "rw" and x.uniform_access(node("game")) == "mixed"
assert (pt.n_ro, pt.n_hid) == (1, 1) and pt.files == len(psnap)
assert pt.n_bad == 2                     # pak0.bin (new, read-only) and secret.key (modified, hidden); the rest is writable
assert node("game/data/pak0.bin").n_bad == 1 and node("game/saves").n_bad == 0
kind, why = x.access_info(pol, node("game/data/secret.key"))
assert kind == "hidden" and "--blacklist" in why and "this game's profile" in why
kind, why = x.access_info(pol, node("game/data"))
assert kind == "mixed" and "1 read-only" in why and "1 hidden" in why
assert "no-exec" in x.access_info(pol, node("game/saves/s1.sav"))[1] and "mounted read-write" in x.access_info(pol, node("game/bin/run.exe"))[1]
assert x.node_abs(pol, node("game/data/pak0.bin")) == os.path.realpath(pg / "game/data/pak0.bin")
# a folder with no files in it from the profile's point of view is simply not mounted: wine home/ is hidden
hs = dict(psnap); hs["home/.config/x"] = (5, 1)
ht2 = x.build_tree(hs, {}); x.apply_policy(ht2, pol)
assert next(k for k in ht2.kids if k.name == "home").acc == "hidden" and ht2.n_hid == 2
# rules about places off the map are summarised separately; the built-in mounts are not among them
ov = dict((m, (ps, more)) for m, ps, more in x.outside_summary(pol, home=str(pd)))
assert ov == {}, ov      # ~/shared and ~/roms are whitelisted folders: they are scanned and on the map now, so not "off this map"
assert set(pol.extra_tops) == {"shared", "roms"} and pol.extra_tops["shared"] == os.path.realpath(ext)
many = x.build_policy(pg, {"FJ_WL_RO": []}, {}); many.rules += [R(f"/mnt/x{i}", "ro", "FJ_WL_RO", "game.conf") for i in range(7)]
assert x.outside_summary(many, home="/nonexistent")[0] == ("ro", [f"/mnt/x{i}" for i in range(4)], 3)
assert x.outside_summary(None) == []
# a symlinked game/ folder: the rule lives at the real path, and the map still lines up with it
real_game = pd / "elsewhere"; (real_game / "sub").mkdir(parents=True); (real_game / "sub" / "f.bin").write_bytes(b"y" * 9)
lg = pd / "q" / "Linked"; (lg / "prefix").mkdir(parents=True); os.symlink(real_game, lg / "game")
lp = x.build_policy(lg, {"FJ_EXTRA_ARGS": [f"--read-only={real_game}/sub"]}, {})
ls = x.snapshot(lg); assert "game/sub/f.bin" in ls
lt = x.build_tree(ls, {}, pins=x.pin_paths(lp)); x.apply_policy(lt, lp)
assert next(n for n in _walk(lt) if n.path == "game/sub/f.bin").acc == "ro" and lt.n_ro == 1
# a rule that covers the whole game folder (whitelisting the parent read-only) cannot loosen game/ below its own mount
wide = x.build_policy(pg, {"FJ_WL_RO": [str(pg.parent)]}, {}); wt = x.build_tree(psnap, {}); x.apply_policy(wt, wide)
assert wt.n_ro == 0 and node.__name__ and all(k.acc == "rw" for k in wt.kids)
# signature changes when, and only when, the profile does
assert pol.signature() == x.build_policy(pg, g_conf, dfl).signature() and pol.signature() != u.signature()

# pruning never folds away a node named by a rule, even a tiny one in a crowd
crowd = {f"game/f{i:04d}.dat": (5000 - i, 1) for i in range(300)}
crowd["game/zz-tiny.cfg"] = (1, 1)
cp = x.Policy(tops={"game": "/g/game", "prefix": "/g/prefix", "home": "/g/home"},
              rules=[R("/g/game", "rw", "mount", "built-in"), R("/g/game/zz-tiny.cfg", "hide", "FJ_EXTRA_ARGS", "game.conf")])
plain = x.build_tree(crowd, {})
assert "zz-tiny.cfg" not in {k.name for k in plain.kids[0].kids}              # without pins it is folded into "…N more"
pinned = x.build_tree(crowd, {}, pins=x.pin_paths(cp)); x.apply_policy(pinned, cp)
gk = pinned.kids[0]
assert "zz-tiny.cfg" in {k.name for k in gk.kids} and gk.files == 301 and sum(k.size for k in gk.kids) == gk.size
assert next(k for k in gk.kids if k.name == "zz-tiny.cfg").acc == "hidden" and pinned.n_hid == 1
assert all(k.acc == "rw" for k in gk.kids if k.more)                          # the folded group is writable, and says so
assert x.build_tree(crowd, {}, pins=()).kids[0].files == 301
# with pins on, a tiny hidden file next to huge ones is given a visible tile (like a new file); with pins off it is a sliver
huge = {f"game/big{i}.pak": (10**12, 1) for i in range(5)}
huge["game/tiny.cfg"] = (1, 1)
hp = x.Policy(tops=cp.tops, rules=[R("/g/game", "rw", "mount", "built-in"), R("/g/game/tiny.cfg", "hide", "FJ_EXTRA_ARGS", "game.conf")])
ht = x.build_tree(huge, {}, pins=x.pin_paths(hp)); x.apply_policy(ht, hp)
for flag in (True, False):
    tl = x.layout(ht, 900, 500, boost=True, pins=flag)
    vis = [t for t in tl if t.node.name == "tiny.cfg" and t.w * t.h >= 100]
    assert bool(vis) == flag, (flag, len(vis))
assert not [t for t in x.layout(ht, 900, 500, boost=False, pins=True) if t.node.name == "tiny.cfg"]      # true scale stays true
# an empty policy leaves the tree untouched
e = x.build_tree({}, {}); x.apply_policy(e, pol); assert e.files == 0 and e.n_ro == 0

# --- text helpers
assert x.fmt_size(0) == "0 B" and x.fmt_size(1536) == "1.5 KB" and x.fmt_size(3 * 1024**3) == "3.0 GB"
assert x.fmt_ago(5) == "just now" and x.fmt_ago(300) == "5m ago" and x.fmt_ago(7200) == "2h ago" and x.fmt_ago(200000) == "2d ago"

print("wq_xray_core: ok (incl. sandbox policy)")

# --- extra whitelisted folders and files (Paths tab: Add folder / Add file) are scanned and drawn as tiles
ed = Path(tempfile.mkdtemp())
eg = ed / "q" / "G"; (eg / "game").mkdir(parents=True); (eg / "game" / "run.sh").write_bytes(b"x")
saves = ed / "mnt" / "Saves"; (saves / "slot1").mkdir(parents=True); (saves / "slot1" / "a.sav").write_bytes(b"1" * 10)
lib = ed / "mnt2" / "Saves"; lib.mkdir(parents=True); (lib / "lib.dat").write_bytes(b"2" * 20)      # same basename as saves
cfg = ed / "mnt" / "game.cfg"; cfg.write_bytes(b"c" * 5)                                           # a single file (Add file)
nested = saves / "slot1"                                                                           # inside an extra: no tile of its own
ep = x.build_policy(eg, {"FJ_WL_RW": [str(saves), str(lib), str(nested)], "FJ_WL_RO": [str(cfg)]}, {})
et = ep.extra_tops
assert set(et) == {"Saves", "Saves~2", "game.cfg"} and et["Saves"] == os.path.realpath(saves), et
assert all(k not in ep.tops or k not in x.SCAN_DIRS for k in et)
assert x.outside_summary(ep, home="/nonexistent") == []          # nothing is left "off the map"
es = x.snapshot(eg, extra=et)
assert es["Saves/slot1/a.sav"] == (10, es["Saves/slot1/a.sav"][1]) and "Saves~2/lib.dat" in es and es["game.cfg"][0] == 5 and "game/run.sh" in es
assert not any(k.startswith("Saves/Saves") for k in es)
assert "Saves/slot1/a.sav" not in x.snapshot(eg)                 # without extra the old behaviour is unchanged
assert x.snapshot(eg, extra={"gone": str(ed / "missing")}) == x.snapshot(eg)
assert x.snapshot(eg, stop=lambda: True, extra=et) == {}
# the tree has one tile per extra, and access comes from the whitelist that added it
etree = x.build_tree(es, {}, pins=x.pin_paths(ep)); x.apply_policy(etree, ep)
tk = {k.name: k for k in etree.kids}
assert {"game", "Saves", "Saves~2", "game.cfg"} <= set(tk)
assert tk["Saves"].acc == "rw" and tk["game.cfg"].acc == "ro" and etree.n_ro == 1
assert x.node_abs(ep, tk["game.cfg"]) == os.path.realpath(cfg)
assert x.node_abs(ep, tk["Saves"].kids[0]).startswith(os.path.realpath(saves))
assert "whitelisted read-write" in x.access_info(ep, tk["Saves"])[1] and "whitelisted read-only" in x.access_info(ep, tk["game.cfg"])[1]
# too broad (holds the game folder or the home directory): not scanned, still reported off the map
big = x.build_policy(eg, {"FJ_WL_RO": [str(ed)], "FJ_WL_RW": [str(ed / "q")]}, {})
assert big.extra_tops == {} and sum("too broad" in n for n in big.notes) == 2
assert [m for m, _p, _n in x.outside_summary(big, home="/nonexistent")] == ["rw", "ro"]
hp2 = x.build_policy(eg, {"FJ_WL_RW": [str(ed / "mnt")]}, {}, real=lambda p: p)
assert "mnt" in hp2.extra_tops
assert x.build_policy(eg, {"FJ_WL_RW": [os.path.expanduser("~")]}, {}).extra_tops == {}
assert ep.signature() != x.build_policy(eg, {}, {}).signature()   # adding a folder changes the policy signature
# a baseline remembers which tops it covered; a folder added later is not all "new"
bp2 = ed / "b.json.gz"
old_snap = x.snapshot(eg)
x.save_baseline(bp2, old_snap)
bs, _t, btops = x.load_baseline_info(bp2)
assert bs == old_snap and btops == frozenset(x.SCAN_DIRS) and x.load_baseline(bp2)[0] == old_snap
assert x.diff(bs, es)[0].get("Saves/slot1/a.sav") == "new"                    # legacy call: compares everything
assert x.diff(bs, es, btops)[0] == {}                                          # Saves was not in the baseline: not flagged
x.save_baseline(bp2, es, tops=list(x.SCAN_DIRS) + list(et))
bs2, _t, btops2 = x.load_baseline_info(bp2)
assert btops2 == frozenset(x.SCAN_DIRS) | set(et)
(saves / "dropped.elf").write_bytes(b"E" * 7)
es2 = x.snapshot(eg, extra=et)
assert x.diff(bs2, es2, btops2)[0] == {"Saves/dropped.elf": "new"}              # now it is
assert x.load_baseline_info(ed / "nope") == (None, 0.0, frozenset())
print("extra whitelisted paths: ok")

# --- command line: baseline taken right after a game is populated
cd_ = d / "cli"
cg = cd_ / "Fresh"
(cg / "game" / "bin").mkdir(parents=True)
(cg / "game" / "bin" / "run.sh").write_bytes(b"#!/bin/sh\n")
(cg / "game" / "data.pak").write_bytes(b"P" * 50)
(cg / "game.conf").write_text("EXE=bin/run.sh\n")
cache = d / "cli-cache"
XDG = os.environ.get("XDG_CACHE_HOME"); os.environ["XDG_CACHE_HOME"] = str(d / "xdg")
assert x.main(["--baseline", str(cg)]) == 0 and (d / "xdg" / "wq-ui" / "xray").is_dir()   # default cache dir = the UI's
os.environ.pop("XDG_CACHE_HOME") if XDG is None else os.environ.__setitem__("XDG_CACHE_HOME", XDG)
dest, n = x.take_baseline(cg, cache)
assert n == 2 and dest == x.baseline_path(cache, cg.parent.resolve() / cg.name)
bsnap, btime, btops = x.load_baseline_info(dest)
assert sorted(bsnap) == ["game/bin/run.sh", "game/data.pak"] and btime > 0 and btops == frozenset(x.SCAN_DIRS)
assert x.diff(bsnap, x.snapshot(cg), btops) == ({}, [])            # right after populating: all green
(cg / "game" / "dropped.dll").write_bytes(b"D")
assert x.diff(bsnap, x.snapshot(cg), btops)[0] == {"game/dropped.dll": "new"}
assert x.main(["--baseline", str(d / "nope")]) == 1 and x.main([]) == 2   # no game/ folder, bad usage
print("cli baseline: ok")


# ---- what a changed file is: programs, packed programs, and files that must not hang the scan
import random as _random
sd = Path(tempfile.mkdtemp()) / "G"
(sd / "game" / "bin").mkdir(parents=True); (sd / "home").mkdir(); (sd / "prefix").mkdir()
rng = _random.Random(7)
noise = bytes(rng.getrandbits(8) for _ in range(x.HEAD_BYTES))                    # high entropy (~8 bits/byte)


def pe(body: bytes) -> bytes:                                                    # MZ header, e_lfanew=0x80, "PE\0\0"
    h = bytearray(0x80); h[:2] = b"MZ"; h[0x3C:0x40] = (0x80).to_bytes(4, "little")
    return bytes(h) + b"PE\0\0" + body


files = {
    "game/plain.exe": pe(b"\x00" * 20000),                                      # a real PE, low entropy
    "game/packed.exe": pe(noise),                                               # PE with random-looking body
    "game/tiny.exe": pe(noise[:200]),                                           # too short for entropy to mean anything
    "game/fake.exe": b"just text pretending to be a program",                   # .exe name, not a PE
    "game/bin/tool": b"\x7fELF" + b"\x00" * 9000,
    "game/bin/packed.so": b"\x7fELF" + noise,
    "game/run.sh": b"#!/bin/sh\necho hi\n",
    "game/start.bat": b"@echo off\n",
    "game/readme.txt": b"hello",
    "game/data.pak": noise,                                                     # high entropy but data: never a program
    "game/pic.png": b"\x89PNG" + noise[:5000],
    "home/.config/autostart/a.desktop": b"[Desktop Entry]\n",
    "home/Link.lnk": b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 64,
    "home/py.py": b"print(1)\n",
}
for rel, data in files.items():
    f = sd / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_bytes(data)
os.symlink("/etc/hostname", sd / "game" / "link.sh")                            # a symlink is never opened
os.mkfifo(sd / "game" / "pipe.sh")                                              # a FIFO must not block the scan

got = {rel: x.sniff_file(str(sd / rel)) for rel in files}
assert got["game/plain.exe"] == ("pe", False) and got["game/packed.exe"] == ("pe", True)
assert got["game/tiny.exe"] == ("pe", False) and got["game/fake.exe"] == ("", False)
assert got["game/bin/tool"] == ("elf", False) and got["game/bin/packed.so"] == ("elf", True)
assert got["game/run.sh"] == ("script", False) and got["game/start.bat"] == ("script", False)
assert got["game/readme.txt"] == ("", False) and got["game/data.pak"] == ("", False) and got["game/pic.png"] == ("", False)
assert got["home/.config/autostart/a.desktop"][0] == "launcher" and got["home/Link.lnk"][0] == "launcher"
assert got["home/py.py"] == ("script", False)
assert x.sniff_file(str(sd / "game" / "link.sh")) == ("", False)                # O_NOFOLLOW
assert x.sniff_file(str(sd / "game" / "pipe.sh")) == ("", False)                # returned at once, no hang
assert x.sniff_file(str(sd / "nope")) == ("", False)
assert x.entropy(b"") == 0 and x.entropy(b"a" * 100) == 0 and 7.9 < x.entropy(noise) <= 8

# sniff_changed looks only at new/modified files, honours extra folders and the limit
snap = x.snapshot(sd)
st = {p: "new" for p in snap}
kinds = x.sniff_changed(sd, st)
assert "game/packed.exe" in kinds and "game/readme.txt" not in kinds and "game/data.pak" not in kinds
assert x.sniff_changed(sd, {}) == {}
st2 = {"game/plain.exe": "mod", "game/run.sh": "new", "game/start.bat": "new"}
assert set(x.sniff_changed(sd, st2, limit=2)) == {"game/run.sh", "game/start.bat"}       # new before modified
assert x.sniff_changed(sd, st, stop=lambda: True) == {}
ex = Path(tempfile.mkdtemp()); (ex / "saves").mkdir(); (ex / "saves" / "x.sh").write_bytes(b"#!/bin/sh\n"); (ex / "one.exe").write_bytes(pe(b"\0" * 9000))
assert x.abs_of(sd, "game/a", {"saves": str(ex / "saves")}) == str(sd / "game" / "a")
assert x.abs_of(sd, "saves/x.sh", {"saves": str(ex / "saves")}) == str(ex / "saves" / "x.sh")
assert x.abs_of(sd, "one.exe", {"one.exe": str(ex / "one.exe")}) == str(ex / "one.exe")    # a whitelisted single file
assert set(x.sniff_changed(sd, {"saves/x.sh": "new", "one.exe": "new"}, {"saves": str(ex / "saves"), "one.exe": str(ex / "one.exe")})) == {"saves/x.sh", "one.exe"}

# the tree carries the kinds: only new/modified programs count, folders add them up, groups keep the count
st = {"game/packed.exe": "new", "game/plain.exe": "mod", "game/run.sh": "new", "game/readme.txt": "new"}
kinds = {"game/packed.exe": ("pe", True), "game/plain.exe": ("pe", False), "game/run.sh": ("script", False),
         "game/bin/tool": ("elf", False)}                                       # tool is unchanged: not counted
root = x.build_tree(snap, st, kinds=kinds)
assert root.progs == 3
game = next(k for k in root.kids if k.name == "game")
assert game.progs == 3 and next(k for k in game.kids if k.name == "bin").progs == 0
leaf = next(k for k in game.kids if k.name == "packed.exe")
assert (leaf.kind, leaf.packed, leaf.progs) == ("pe", True, 1) and x.kind_label(leaf) == "packed Windows program"
assert x.kind_label(next(k for k in game.kids if k.name == "run.sh")) == "script"
assert x.kind_label(next(k for k in game.kids if k.name == "readme.txt")) == ""
assert x.program_counts(kinds, st) == {"new": 2, "mod": 1, "packed": 1}
assert x.build_tree(snap, st).progs == 0                                        # no kinds given: as before

# collapsed "…N more" groups keep their program count
many = {f"game/f{i:03}.exe": (10, 1) for i in range(x.KEEP_BIG + x.KEEP_CHANGED + 8)}
mst = {p: "new" for p in many}
mk = {p: ("pe", False) for p in many}
mroot = x.build_tree(many, mst, kinds=mk)
assert mroot.progs == len(many) and any(k.more for k in next(k for k in mroot.kids).kids)
print("sniff: ok")
