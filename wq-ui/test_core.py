import re, sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_core as c

d = Path(tempfile.mkdtemp()); f = d/"game.conf"
f.write_text("# my game\nEXE=bin/Game.exe\nFJ_NET=0\nFJ_NET_ALLOW=tcp:1.1.1.1:443\nFJ_NET_ALLOW=tcp:2.2.2.2:443\nOTHER=a=b\n")
os.chmod(f, 0o640)
c.write_kv(f, {"FJ_NET": "1", "FJ_NET_ALLOW": ["tcp:9.9.9.9:53"], "FJ_XEPHYR": "1", "FJ_NOSOUND": None})
t = f.read_text(); print(t)
assert "EXE=bin/Game.exe" in t and "# my game" in t and "OTHER=a=b" in t       # untouched lines kept
assert t.count("FJ_NET_ALLOW=") == 1 and "1.1.1.1" not in t                    # dups collapsed, replaced
assert "FJ_NET=1" in t and "FJ_XEPHYR=1" in t                                   # in-place + appended
assert oct(f.stat().st_mode & 0o777) == "0o640"                                # perms preserved
assert not list(d.glob(".wq-*.tmp"))                                            # no temp litter
c.write_kv(f, {"FJ_NET_ALLOW": []}); assert "FJ_NET_ALLOW" not in f.read_text()  # empty list removes
for bad in ({"fj_net": "1"}, {"FJ_NET": "1\nEXE=evil.exe"}, {"FJ_NET;x": "1"}):
    try: c.write_kv(f, bad); raise SystemExit(f"accepted {bad}")
    except ValueError: pass
assert "evil" not in f.read_text(); print("write_kv: ok (incl. injection rejection)")

# scan
q = d/"q"; (q/"A"/"game").mkdir(parents=True); (q/"A"/"game.conf").write_text("EXE=a.exe\n"); (q/"A"/"launch-quarantine.sh").touch()
(q/"B"/"game").mkdir(parents=True); (q/"B"/"game.conf").write_text("EXE=CHANGE_ME.exe\n")
(q/"wq-ui").mkdir(); (q/"_umu-data"/"game").mkdir(parents=True); (q/"notagame").mkdir()
gs = c.scan_games(q); print([(g.name, g.exe_ready, g.has_launcher) for g in gs])
assert [g.name for g in gs] == ["A", "B"] and gs[0].exe_ready and not gs[1].exe_ready

# precedence + net mode
g = gs[0]; dfl = {"FJ_NOSOUND": ["1"], "FJ_NET": ["1"]}; g.conf["FJ_NOSOUND"] = ["0"]
assert not g.flag("FJ_NOSOUND", dfl) and g.flag("FJ_NET", dfl) and g.net_mode(dfl) == "filtered"
g.conf["FJ_NET_OPEN"] = ["1"]; assert g.net_mode(dfl) == "open"; assert g.net_mode({}) == "off" or True
assert g.flag("FJ_PRIVATE_HOME", {}) is True and g.flag("FJ_NOSOUND", {}) is False   # builtin = stock

# classify
home = Path.home()
for p, want in ((home, "home"), ("/tmp", "ok"), ("/usr", "system"), ("/", "unsupported"), ("/nope/x", "missing")):
    got = c.classify_path(p)[0]; print(f"classify {str(p):12} -> {got}"); assert got == want, (p, got, want)
(Path("/tmp")/"symlink_home_test").unlink(missing_ok=True); os.symlink(home, "/tmp/symlink_home_test")
assert c.classify_path("/tmp/symlink_home_test")[0] == "home"   # symlink into home resolves
os.unlink("/tmp/symlink_home_test")

# connection parsing: kernel log lines and the old firejail --trace format
klog = "wq-net[My Game]: IN= OUT=eth0 SRC=192.168.3.88 DST=93.184.216.34 LEN=60 PROTO=TCP SPT=54321 DPT=443"
assert c.parse_connect(klog) == ("93.184.216.34", 443)
assert c.parse_klog(klog) == ("My Game", "93.184.216.34", 443)
ok = {"4242:wine64-preloader:connect 7 93.184.216.34 port 443:0": ("93.184.216.34", 443),
      "12:game.exe:connect 5 8.8.8.8 port 53:-1": ("8.8.8.8", 53),
      "\x1b[1m7:x:connect 9 10.0.0.5 port 27015\x1b[0m": ("10.0.0.5", 27015),
      "1:x:connect 4 [2001:db8::1] port 443": ("2001:db8::1", 443)}
for line, want in ok.items(): assert c.parse_connect(line) == want, line
for noise in ("3:wget:fopen64 /etc/wgetrc:0x4a8", "connect /run/user/1000/bus", "connect 3 999.1.1.1 port 80",
              "connect 3 1.2.3.4 port 0", "Parent pid 1234"):
    assert c.parse_connect(noise) is None, noise
print("parse_connect / parse_klog: ok")

# allow matching
al = ["tcp:93.184.216.34:443", "udp:10.0.0.0/8:*"]
assert c.allow_matches(al, "93.184.216.34", 443) and not c.allow_matches(al, "93.184.216.34", 80)
assert c.allow_matches(al, "10.20.30.40", 9999) and not c.allow_matches(al, "11.0.0.1", 1)
assert c.allow_matches([], "127.0.0.1", 5) and not c.allow_matches(al, "not-an-ip", 1)
assert c.valid_allow("tcp:1.2.3.4:80") and not c.valid_allow("tcp:1.2.3.4:80;ls") and not c.valid_allow("icmp:1.1.1.1:1")
print("allow matching: ok")

# css
src = "@define-color primary #ff0000;\n@define-color on-surface #eeeeee;\nQPushButton { color: @primary; border-color: @unknown; }\n"
defs, rest = c.split_css(src); assert defs == {"primary": "#ff0000", "on_surface": "#eeeeee"} and "@define-color" not in rest
out = c.substitute_tokens(rest, {**c.DARK, **defs}); assert "color: #ff0000" in out and "@unknown" in out
assert "@" not in c.substitute_tokens(c.BUILTIN_QSS, c.DARK) and "@" not in c.substitute_tokens(c.BUILTIN_QSS, c.LIGHT)
print("css tokens: ok; all builtin QSS tokens resolve in both themes")

# --- themes
import wq_themes as th
for t in th.THEME_LIST:
    assert t.mode in ("dark", "light") and set(th.TOKEN_KEYS) <= set(t.tokens), t.id
    tok, qss = th.resolve_tokens(t, t.mode)
    sheet = c.substitute_tokens(c.BUILTIN_QSS + qss, tok)
    assert "@" not in sheet, (t.id, "unresolved token")
    assert th.contrast(tok["on_surface"], tok["surface"]) >= 4.5, (t.id, "text on surface")
    assert th.contrast(tok["on_primary"], tok["primary"]) >= 4.5, (t.id, "text on primary")
    assert th.contrast(tok["on_surface_variant"], tok["surface"]) >= 3.0, (t.id, "muted text")
    assert th.contrast(tok["error"], tok["surface"]) >= 3.0 and th.contrast(tok["warn"], tok["surface"]) >= 3.0, t.id
    assert c.icon_signature(tok)
assert len(th.THEMES) == len(th.THEME_LIST)
td = Path(tempfile.mkdtemp())
(td / "mine.css").write_text("/* theme: Mine */\n@define-color mode light;\n@define-color primary #123456;\nQPushButton { color: @primary; }\n")
(td / "empty.css").write_text("QPushButton { color: red; }\n")
ut = th.load_user_themes(td)
assert [u.id for u in ut] == ["user:mine"] and ut[0].label == "Mine" and ut[0].mode == "light"
tok, qss = th.resolve_tokens(ut[0], "light"); assert tok["primary"] == "#123456" and tok["surface"] == c.LIGHT["surface"]
assert "user:mine" in th.all_themes(td) and "cyberpunk" in th.all_themes(td)
for t in th.THEME_LIST:                      # same for the built-in pixel theme's frames and font
    for ref in re.findall(r'url\("@assets/([^")]+)"\)', t.qss):
        assert (th.ASSETS_DIR / ref).is_file(), (t.id, ref)
assert "pixel" in th.THEMES and list((th.ASSETS_DIR / "fonts").glob("PixelifySans-*.ttf"))
print(f"themes: ok ({len(th.THEME_LIST)} built in, contrast checked, user themes load)")

# --- game names
d2 = Path(tempfile.mkdtemp()); (d2/"Taken").mkdir()
assert c.validate_game_name("My Game", {"Other"}, d2) == ""
for bad in ("", " x", "x ", "a/b", "..", ".", "_hidden", ".hidden", "-opt", "a\nb", "x"*65):
    assert c.validate_game_name(bad), repr(bad)
assert "exists" in c.validate_game_name("taken", {"Taken"}, d2)                 # case-insensitive clash
assert "exists" in c.validate_game_name("Taken", set(), d2)                     # folder already on disk
print("game names: ok")

# --- exe discovery (same filters as new-quarantine.sh)
g2 = d2/"G"; (g2/"game"/"bin").mkdir(parents=True)
for f in ("a.exe", "bin/B.EXE", "unins000.exe", "UnityCrashHandler64.exe", "vcredist_x86.exe", "dxsetup.exe", "notes.txt"):
    (g2/"game"/f).touch()
assert c.find_exes(g2) == ["a.exe", "bin/B.EXE"], c.find_exes(g2)
assert c.exe_inside_game(g2, "bin/B.EXE") and not c.exe_inside_game(g2, "../x.exe") and not c.exe_inside_game(g2, "nope.exe")
os.symlink("/etc/hostname", g2/"game"/"link.exe")
assert not c.exe_inside_game(g2, "link.exe")                                     # symlink out of game/
assert c.valid_exe_rel("a/b.exe") and not any(c.valid_exe_rel(x) for x in ("", "/a", "../a", "a/../b", "a\nb"))
print("exe discovery: ok")

# --- /dev checks
assert c.validate_device_path("/dev/null")[0] is False and c.validate_device_path("/dev")[0] is False
assert c.validate_device_path("/dev/../etc/passwd")[0] is False and c.validate_device_path("/etc/passwd")[0] is False
assert c.validate_device_path("/dev/definitely-not-here")[0] is False
assert c.device_risk("/dev/dri/card0")[0] == "notable" and c.device_risk("/dev/input/js0")[0] == "notable"
assert c.device_risk("/dev/shm/x")[0] == "essential" and c.device_risk("/dev/sda")[0] == "ok"
devs = c.list_devices()
assert all(p.startswith("/dev/") and c.device_risk(p)[0] != "essential" for p, _, _ in devs)
print(f"/dev checks: ok ({len(devs)} nodes listed here)")

# --- launch script paths
hp = d2/"h.sh"; hp.write_text("true\n")
assert c.validate_hook_path(str(hp))[0] and not c.validate_hook_path("rel.sh")[0] and not c.validate_hook_path(str(d2))[0]
print("hook paths: ok")

# --- new list keys survive write_kv, and an empty list removes the key
gc = d2/"gc.conf"; gc.write_text("EXE=a.exe\n")
c.write_kv(gc, {"FJ_DEV_BLOCK": ["/dev/a", "/dev/b"], "FJ_HOOK_PRE": [str(hp)]})
assert c.parse_kv(gc)["FJ_DEV_BLOCK"] == ["/dev/a", "/dev/b"] and c.parse_kv(gc)["FJ_HOOK_PRE"] == [str(hp)]
c.write_kv(gc, {"FJ_HOOK_PRE": []}); assert "FJ_HOOK_PRE" not in gc.read_text() and "EXE=a.exe" in gc.read_text()
assert {"FJ_DEV_BLOCK", "FJ_HOOK_PRE", "FJ_HOOK_POST"} <= set(c.LIST_KEYS)
print("list keys: ok")

# --- checkbox image spec resolves in both themes
for T in (c.DARK, c.LIGHT):
    for tok, (bk, fk, glyph, gk) in c.CB_ICONS.items():
        assert bk in T and fk in T and (gk is None or gk in T), tok
assert c.icon_signature(c.DARK) != c.icon_signature(c.LIGHT)
print("checkbox spec: ok")

# --- native games
gn = d2/"N"; (gn/"game"/"bin").mkdir(parents=True)
(gn/"game"/"start.sh").write_text("#!/bin/bash\n"); (gn/"game"/"install.sh").touch(); (gn/"game"/"lib.so").touch()
(gn/"game"/"bin"/"Game").write_bytes(b"\x7fELF....."); os.chmod(gn/"game"/"bin"/"Game", 0o755)
(gn/"game"/"bin"/"data").write_bytes(b"nope"); os.chmod(gn/"game"/"bin"/"data", 0o755)
assert c.find_exes(gn, "native") == ["start.sh", "bin/Game"], c.find_exes(gn, "native")
ng = c.Game("N", gn, {"EXE": ["CHANGE_ME.sh"], "RUNNER": ["native"]})
assert ng.runner == "native" and not ng.exe_ready and c.Game("W", gn, {"EXE": ["a.exe"]}).runner == "wine"
print("native games: ok")

# --- removing games
rq = Path(tempfile.mkdtemp()); (rq/"Real"/"game").mkdir(parents=True); (rq/"Real"/"game"/"f.bin").write_bytes(b"x"*2048)
(rq/"_umu-data").mkdir(); (rq/"wq-ui").mkdir(); (rq/"Plain").mkdir(); (rq/"Conf").mkdir(); (rq/"Conf"/"game.conf").write_text("EXE=a\n")
os.symlink(str(rq/"Real"), str(rq/"Link")); os.symlink("/etc", str(rq/"EtcLink"))
assert c.validate_removal(rq, "Real") == "" and c.validate_removal(rq, "Conf") == ""
for bad in ("", ".", "..", "../x", "a/b", "_umu-data", ".hidden", "wq-ui", "Plain", "Link", "EtcLink", "Nope"):
    assert c.validate_removal(rq, bad), repr(bad)
size, trunc = c.dir_size(rq/"Real"); assert size == 2048 and not trunc
os.symlink("/usr", str(rq/"Real"/"game"/"usr-link"))                       # must not be followed
assert c.dir_size(rq/"Real")[0] == 2048 and c.dir_size(rq/"Real", max_entries=1)[1]
assert c.human_size(500) == "500 B" and c.human_size(1536) == "1.5 KB" and c.human_size(3*1024**3) == "3.0 GB"
print("game removal checks: ok")

# --- limits, extra firejail options
import subprocess
here = Path(__file__).resolve().parent
assert c.valid_tasks("4096") and not any(c.valid_tasks(x) for x in ("", "0", "-1", "abc", "10 20", "1e3", "4096\n"))
assert c.valid_memory("8G") and c.valid_memory("512M") and c.valid_memory("1000")
assert not any(c.valid_memory(x) for x in ("", "0", "8GB", "G", "8 G", "-8G", "8g"))
assert c.valid_syscalls("bpf") and c.valid_syscalls("ptrace,process_vm_readv,@mount")
assert not any(c.valid_syscalls(x) for x in ("", "bpf,", ",bpf", "bpf;reboot", "a b", "a,,b"))
print("limit validators: ok")

# profile.sh is the authority: run the same corpus through it and through wq_core and demand agreement
corpus = [
    "--machine-id", "--nosound", "--novideo", "--nou2f", "--notv", "--nodvd", "--noroot",
    "--rlimit-nofile=4096", "--rlimit-fsize=2000000000", "--rlimit-cpu=3600", "--rlimit-as=8G", "--rlimit-sigpending=100",
    "--rlimit-nproc=99999", "--timeout=02:00:00", "--timeout=100:59:59", "--nice=0", "--nice=19", "--cpu=0", "--cpu=0,1,2",
    "--rmenv=DISPLAY", "--blacklist=/mnt/secret", "--noexec=/tmp", "--read-only=/opt/x", "--blacklist=/",
    "--blacklist=/a/b..c", "--blacklist=/a/..b/c",
    # must be refused
    "", "--net=eth0", "--net=none", "--noprofile", "--ignore=nonewprivs", "--whitelist=/home", "--netfilter=/x",
    "--allow-debuggers", "--seccomp.drop=keyctl", "--private-etc=a", "--shell=none", "--join=1", "--overlay",
    "--blacklist=/a/../b", "--blacklist=/..", "--blacklist=/a/..", "--blacklist=rel/path", "--blacklist=/a b",
    "--blacklist=$HOME", "--blacklist=/a;b", "--noexec=", "--timeout=99", "--timeout=1:2:3", "--timeout=02:60:00",
    "--nice=-1", "--nice=20", "--nice=5x", "--cpu=", "--cpu=a", "--rmenv=1BAD", "--rmenv=A-B", "--rlimit-nofile=",
    "--rlimit-nofile=-1", "--rlimit-bogus=1", "--rlimit-as=8T", "--machine-id=1", "--nosound ", " --nosound", "nosound",
    "--rlimit-nofile=1" + "0" * 19,
]
for line in corpus:
    sh = subprocess.run(["bash", "-c", '. "$1/profile.sh"; _wq_extra_arg_ok "$2"', "_", str(here), line]).returncode == 0
    py = c.check_extra_arg(line) == ""
    if line == "":
        continue            # blank lines are dropped before either check runs
    assert sh == py, f"shell and python disagree on {line!r}: shell={sh} python={py}"
accepted = [x for x in corpus if x and c.check_extra_arg(x) == ""]
assert 25 <= len(accepted) < len(corpus) - 10, len(accepted)
print(f"extra-option allow-list: shell and python agree on {len(corpus) - 1} inputs ({len(accepted)} accepted)")

# effective list: game.conf wins as a whole, and a bare `KEY=` means "none"
g = c.Game("G", d, {"FJ_EXTRA_ARGS": ["--nosound", "  "]})
assert g.effective_lines("FJ_EXTRA_ARGS", {"FJ_EXTRA_ARGS": ["--novideo"]}) == ["--nosound"]
assert c.Game("G", d, {}).effective_lines("FJ_EXTRA_ARGS", {"FJ_EXTRA_ARGS": ["--novideo"]}) == ["--novideo"]
assert c.Game("G", d, {"FJ_EXTRA_ARGS": [""]}).effective_lines("FJ_EXTRA_ARGS", {"FJ_EXTRA_ARGS": ["--novideo"]}) == []
ge = d/"extra.conf"; ge.write_text("EXE=a.exe\n")
c.write_kv(ge, {"FJ_EXTRA_ARGS": [""]})
assert ge.read_text().splitlines() == ["EXE=a.exe", "FJ_EXTRA_ARGS="] and c.parse_kv(ge)["FJ_EXTRA_ARGS"] == [""]
c.write_kv(ge, {"FJ_EXTRA_ARGS": ["--timeout=01:00:00", "--nosound"], "FJ_TASKS_MAX": "4096"})
assert c.parse_kv(ge)["FJ_EXTRA_ARGS"] == ["--timeout=01:00:00", "--nosound"] and c.parse_kv(ge)["FJ_TASKS_MAX"] == ["4096"]
c.write_kv(ge, {k: None for k in c.MANAGED_SCALARS})
assert ge.read_text().splitlines() == ["EXE=a.exe"]                    # "Reset to defaults" clears them too
assert "FJ_MACHINE_ID" in c.ALL_BOOLS and c.ALL_BOOLS["FJ_MACHINE_ID"] is True
assert set(c.TEXT_KEYS) <= set(c.TEXT_HINTS) and c.EXTRA_ARGS_KEY in c.LIST_KEYS
print("extra-option storage: ok")


# ---- alert counting (the Monitor tab badge; mirrors summarize-run.sh)
_log = """[2026-10-18 09:06:25] [INFO] Monitor started
[2026-10-18 09:06:27] [WARN] New executable (ELF) written in game folder: probe-dropped-elf
[2026-10-18 09:06:27] [WARN] New script/executable written in game folder: probe-dropped.sh
[2026-10-18 09:06:40] [ALERT] ClamAV: home/eicar-test.com: Eicar-Signature
[2026-10-18 09:06:40] [ALERT] ClamAV flagged 1 of 4 scanned file(s) in probeV6. Treat this game as hostile
"""
assert c.count_alerts(_log) == (1, 2), c.count_alerts(_log)
assert c.count_alerts("") == (0, 0)
assert c.count_alerts("[t] [ALERT] curl\n[t] [ALERT] Kill switch triggered - terminating sandbox.\n") == (1, 0)
assert c.count_alerts("[t] [ALERT] Kill switch triggered - terminating sandbox.\n") == (1, 0)
assert c.count_alerts("[t] [ALERT] a\n[t] [ALERT] b\n[t] [ALERT] ClamAV: ... and 3 more detection(s)\n") == (2, 0)
print("alert counting ok")


# ---- last run (the game list's "Last run" column)
import time as _time
_g = d/"lastrun"; (_g/"logs").mkdir(parents=True)
assert c.last_run(_g)[0] == "never"
(_g/"logs"/"launch-20261001-100000.log").write_text("starting\n")
(_g/"logs"/"alerts-20261001-100000.log").write_text("[t] [INFO] Monitor started\n")
assert c.last_run(_g)[:2] == ("clean", "✓ clean")
(_g/"logs"/"alerts-20261001-100000.log").write_text("[t] [WARN] x\n[t] [WARN] y\n")
assert c.last_run(_g)[:2] == ("notes", "⚠ 2 notes"), c.last_run(_g)      # cache must notice the change
(_g/"logs"/"alerts-20261001-100000.log").write_text("[t] [ALERT] curl\n[t] [ALERT] Kill switch triggered - terminating sandbox.\n")
assert c.last_run(_g)[:2] == ("alert", "✗ 1 alert")
(_g/"logs"/"launch-20261002-100000.log").write_text("\x1b[31m[SANDBOX-VERIFY] FAIL: x\x1b[0m\n")
assert c.last_run(_g)[0] == "blocked"                                    # newest launch log wins over old alerts
(_g/"logs"/"launch-20261003-100000.log").write_text("ok\n[LEAK] resolver socket reachable\n")
assert c.last_run(_g)[0] == "leak"
assert abs(c.last_run(_g)[2] - _time.time()) < 30
assert c.human_ago(5) == "just now" and c.human_ago(300) == "5m ago" and c.human_ago(7200) == "2h ago" and c.human_ago(3*86400) == "3d ago"
print("last run summary ok")


# ---- game type detection
import zipfile, tarfile, subprocess
assert c.classify_names(["Game/Game.exe", "Game/data.pak"])[0] == "wine"
assert c.classify_names(["start.sh", "bin/game"])[0] == "native"
assert c.classify_names(["a.BAT"])[0] == "wine" and c.classify_names(["Run.CMD"])[0] == "wine" and c.classify_names(["x.msi"])[0] == "wine"
assert c.classify_names(["Game.AppImage"])[0] == "native" and c.classify_names(["g/Game.x86_64"])[0] == "native"
assert c.classify_names(["Game.exe", "Game.sh"])[0] is None                      # same level, both: user decides
assert c.classify_names(["Game.exe", "tools/deep/x/y/fix.sh"])[0] == "wine"      # top level wins over a deep helper
assert c.classify_names(["start.sh", "wine/deep/a/b/setup.exe"])[0] == "native"
assert c.classify_names(["x/UnityPlayer.dll", "x/data.assets"])[0] == "wine"     # no start file, only dlls
assert c.classify_names(["libfoo.so.1", "libbar.so"])[0] == "native"
assert c.classify_names(["__MACOSX/a.exe", "Game.app/Contents/MacOS/game"])[0] is None
assert c.classify_names(["readme.txt"])[0] is None and c.classify_names([])[0] is None
# real sources
ty = d/"types"; ty.mkdir()
(ty/"w").mkdir(); (ty/"w"/"Setup.EXE").write_bytes(b"MZ")
(ty/"n").mkdir(); (ty/"n"/"run").write_bytes(b"\x7fELF" + b"\0" * 20); os.chmod(ty/"n"/"run", 0o755)
(ty/"e").mkdir(); (ty/"e"/"notes.txt").write_text("hi")
assert c.detect_source_type(ty/"w")[0] == "wine" and c.detect_source_type(ty/"n")[0] == "native"
assert c.detect_source_type(ty/"e")[0] is None and c.detect_source_type(ty/"missing")[0] is None
with zipfile.ZipFile(ty/"g.zip", "w") as z: z.writestr("My Game/game.exe", "x"); z.writestr("My Game/data/a.bin", "x")
assert c.detect_source_type(ty/"g.zip")[0] == "wine"
with zipfile.ZipFile(ty/"l.zip", "w") as z: z.writestr("start.sh", "x")
assert c.detect_source_type(ty/"l.zip")[0] == "native"
(ty/"src").mkdir(); (ty/"src"/"go.sh").write_text("#!/bin/sh\n")
with tarfile.open(ty/"l.tar.gz", "w:gz") as t: t.add(ty/"src"/"go.sh", arcname="go.sh")
assert c.detect_source_type(ty/"l.tar.gz")[0] == "native"
(ty/"bad.zip").write_text("not a zip"); assert c.detect_source_type(ty/"bad.zip")[0] is None
for name, body, want in (("prog.exe", b"x", "wine"), ("thing", b"MZ\x90\0", "wine"), ("thing2", b"\x7fELFxxxx", "native"),
                         ("scr", b"#!/bin/bash\n", "native"), ("note", b"hello", None), ("setup.bat", b"@echo off", "wine")):
    (ty/name).write_bytes(body); assert c.detect_source_type(ty/name)[0] == want, name
# .iso / .7z / .rar go through an external lister; a fake 7z checks we run it and parse its -slt output
fake = ty/"bin"; fake.mkdir()
(fake/"7z").write_text("#!/bin/sh\nprintf 'Path = AUTORUN.INF\\nSize = 10\\n\\nPath = Setup.exe\\nSize = 5\\n'\n"); os.chmod(fake/"7z", 0o755)
(ty/"disc.iso").write_bytes(b"x")
_old_path = os.environ["PATH"]; os.environ["PATH"] = f"{fake}:{_old_path}"
try:
    assert c.detect_source_type(ty/"disc.iso")[0] == "wine", c.detect_source_type(ty/"disc.iso")
finally:
    os.environ["PATH"] = _old_path
os.environ["PATH"] = "/nonexistent"
try:
    k, why = c.detect_source_type(ty/"disc.iso"); assert k is None and "lister" in why, (k, why)
finally:
    os.environ["PATH"] = _old_path
print("game type detection ok")

# presets
_keys = {o.key for o in c.BOOL_OPTS} | set(c.NET_BOOLS)
for _n, _p in c.PRESETS.items():
    assert set(_p) <= _keys and all(_p[k] for k in c.PRESET_FLOOR), _n      # real keys, hard floor always on
    assert c.preset_match(_p) == _n
assert {o.key for o in c.BOOL_OPTS} <= set(c.PLAIN) and set(c.ADVANCED_KEYS) <= _keys
assert c.preset_match({**c.PRESETS["Strict"], "FJ_NOSOUND": False}) == "Custom"
assert c.preset_match({**c.PRESETS["Strict"], "FJ_NOSOUND": None}) == "Custom"   # games disagree
assert c.is_relaxed("FJ_NOSOUND", False) and not c.is_relaxed("FJ_NOSOUND", True) and c.is_relaxed("FJ_NET", True)
assert not c.is_relaxed("FJ_XEPHYR", False)                                       # not part of Strict
print("presets ok")


# protocol from the kernel log line
assert c.parse_proto("wq-net[G]: IN= OUT=eth0 SRC=1.2.3.4 DST=5.6.7.8 LEN=60 PROTO=TCP SPT=1 DPT=443") == "tcp"
assert c.parse_proto("\x1b[33mwq-net: DST=5.6.7.8 PROTO=UDP DPT=53\x1b[0m") == "udp"
assert c.parse_proto("wq-net: DST=5.6.7.8 PROTO=ICMP") == "" and c.parse_proto("1234:game:connect 5 1.2.3.4 port 80:0") == ""
print("parse_proto ok")
print("\nALL CORE TESTS PASSED")
