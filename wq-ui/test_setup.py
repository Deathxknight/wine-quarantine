#!/usr/bin/env python3
"""Setup-file support: @prefix/ programs, installer discovery, and the shell helpers that match them."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wq_core as C  # noqa: E402

QROOT = Path(__file__).resolve().parent.parent


def touch(p: Path, data: bytes = b"MZ"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


with tempfile.TemporaryDirectory() as t:
    g = Path(t) / "Game"
    touch(g / "game" / "Setup.exe")
    touch(g / "game" / "disc" / "install_game.exe")
    touch(g / "game" / "readme.txt")
    touch(g / "game" / "gog_thing_1.0.sh")
    c = g / "prefix" / "drive_c"
    touch(c / "Program Files" / "Foo" / "foo.exe")
    touch(c / "Program Files" / "Foo" / "unins000.exe")
    touch(c / "Program Files" / "Common Files" / "x" / "helper.exe")
    touch(c / "windows" / "system32" / "notepad.exe")
    touch(c / "users" / "steamuser" / "AppData" / "Local" / "Temp" / "tmp.exe")
    touch(c / "Program Files (x86)" / "Bar" / "bin" / "bar.exe")

    assert C.find_setups(g, "wine") == ["Setup.exe", "disc/install_game.exe"], C.find_setups(g, "wine")
    assert C.find_setups(g, "native") == ["gog_thing_1.0.sh"], C.find_setups(g, "native")
    assert C.find_prefix_exes(g) == ["@prefix/drive_c/Program Files/Foo/foo.exe",
                                     "@prefix/drive_c/Program Files (x86)/Bar/bin/bar.exe"], C.find_prefix_exes(g)
    ex = C.find_exes(g, "wine")
    assert ex[-2:] == C.find_prefix_exes(g) and "Setup.exe" in ex[:-2]

    assert C.exe_inside_game(g, "@prefix/drive_c/Program Files/Foo/foo.exe")
    assert not C.exe_inside_game(g, "@prefix/drive_c/Program Files/Foo/missing.exe")
    assert not C.exe_inside_game(g, "@prefix/../game/Setup.exe") and not C.exe_inside_game(g, "@prefix/")
    assert C.exe_inside_game(g, "Setup.exe")
    # a symlink in the prefix that points out of it is refused
    (c / "evil.exe").symlink_to("/bin/sh")
    assert not C.exe_inside_game(g, "@prefix/drive_c/evil.exe")
    assert C.exe_path(g, "@prefix/drive_c/a.exe") == g / "prefix" / "drive_c" / "a.exe"
    assert C.exe_path(g, "a.exe") == g / "game" / "a.exe"

    # config.sh must agree with exe_root
    for exe in ("foo.exe", "sub/foo.exe", "@prefix/drive_c/Program Files/Foo/foo.exe"):
        out = subprocess.run(["bash", "-c", 'source "$1"/config.sh; printf "%s\\n%s" "$(wq_exe_root /g "$2")" "$(wq_exe_rel "$2")"',
                              "_", str(QROOT), exe], capture_output=True, text=True, check=True).stdout.split("\n")
        root, rel = C.exe_root(Path("/g"), exe)
        assert out == [root, rel], (exe, out, (root, rel))
print("test_setup: all checks passed")
