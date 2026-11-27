"""Headless check of EntropyTab's file-selection logic, with Qt stubbed out (PySide6 not needed)."""
import sys, types, tempfile, os, time
from pathlib import Path

class _Any:
    """Stands in for any Qt object: every attribute and call succeeds and returns another stub."""
    def __init__(self, *a, **k): pass
    def __call__(self, *a, **k): return _Any()
    def __getattr__(self, name): return _Any()
    def __bool__(self): return True
    def __iter__(self): return iter(())
    def __int__(self): return 0
    def __lt__(self, o): return False
class _Meta(type):
    def __getattr__(cls, name): return _Any()
class _Base(_Any, metaclass=_Meta):
    pass
qt = types.ModuleType("PySide6")
mods = {}
for name in ["QtWidgets", "QtCore", "QtGui"]:
    m = types.ModuleType(f"PySide6.{name}")
    m.__getattr__ = lambda n: _Base
    mods[name] = m
qt.__getattr__ = lambda n: _Base
sys.modules["PySide6"] = qt
for name, m in mods.items():
    sys.modules[f"PySide6.{name}"] = m
sys.path.insert(0, str(Path.cwd()))
import wq_entropy_tab as T
E = T.E

class FakeTab:
    """Only the state and methods the selection logic touches."""
    _reload_game_files = T.EntropyTab._reload_game_files
    _refresh_candidates = T.EntropyTab._refresh_candidates
    _set_file_label = lambda self, *a, **k: setattr(self, "label", str(a[0]) if a and a[0] else None)
    _pick_file = T.EntropyTab._pick_file
    _auto_pick = T.EntropyTab._auto_pick
    _open = T.EntropyTab._open
    def __init__(self, game):
        self.game_dir = Path(game); self.candidates = []; self.path = None; self.an = None
        self._binaries_only = True; self._user_picked = False; self.plots = []; self.label = None; self._file_full = ""
        class Box:
            def __init__(s, v): s.v = v
            def isChecked(s): return s.v
            def currentData(s): return s.v
        self.chk_prefix = Box(False); self.cmb_sort = Box("smart")
        self.btn_plot = self.status = None
        self.status = types.SimpleNamespace(setText=lambda *_: None)
        self.btn_plot = types.SimpleNamespace(setEnabled=lambda *_: None)
        self._pending_auto_plot = False
        self.isVisible = lambda: True
    def plot(self): self.plots.append(self.path)

def mk_game():
    g = Path(tempfile.mkdtemp()) / "gamedir"
    (g / "game").mkdir(parents=True)
    old = g / "game" / "old.dll"; old.write_bytes(b"MZ" + b"a" * 200)
    t = time.time()
    os.utime(old, (t - 1000, t - 1000))
    return g, old

g, old = mk_game()
t = FakeTab(g)
t._reload_game_files(auto_plot=True)
assert t.path == str(old) and t.plots == [str(old)], (t.path, t.plots)

# 1. a newer file arrives; sort change should move the auto selection to it and plot it
new = g / "game" / "new.exe"; new.write_bytes(b"MZ" + b"b" * 4000)
t._refresh_candidates()
t.cmb_sort.v = "size"
t._reload_game_files(auto_plot=True, keep_current=True)
assert t.path == str(new) and t.plots[-1] == str(new), (t.path, t.plots)

# 2. the person picks the old file: sort/prefix changes must not replace it
t._user_picked = True; t.path = str(old); t.plots.clear()
t.cmb_sort.v = "smart"
t._reload_game_files(auto_plot=True, keep_current=True)
assert t.path == str(old) and t.plots == [], (t.path, t.plots)
t.chk_prefix.v = True
t._reload_game_files(auto_plot=True, keep_current=True)
assert t.path == str(old) and t.plots == [], (t.path, t.plots)

# 3. file button with an auto-selected file: the list refreshes, the selection does not silently move
t2 = FakeTab(g); t2._reload_game_files(auto_plot=True); plotted = t2.path
newer = g / "game" / "newest.dll"; newer.write_bytes(b"MZ" + b"c" * 50)
os.utime(newer, (time.time() + 60, time.time() + 60))
t2._refresh_candidates()
assert t2.path == plotted, "file button must not change the selected path"
assert any(c.path == newer for c in t2.candidates)

# 4. Open file… on a file outside the list survives a prefix toggle
outside = Path(tempfile.mkdtemp()) / "outside.bin"; outside.write_bytes(b"\x00" * 64)
t3 = FakeTab(g); t3._user_picked = True; t3.path = str(outside)
t3._reload_game_files(auto_plot=True, keep_current=True)
assert t3.path == str(outside) and t3.plots == []
# 5. "Largest size" with the programs filter on: auto-select a program, not a bigger data file
pak_dir = Path(tempfile.mkdtemp()) / "g"; (pak_dir / "game").mkdir(parents=True)
(pak_dir / "game" / "data.pak").write_bytes(b"P" * 90000)
(pak_dir / "game" / "setup.exe").write_bytes(b"MZ" + b"e" * 100)
t5 = FakeTab(pak_dir); t5.cmb_sort.v = "size"; t5._reload_game_files(auto_plot=True)
assert t5.path.endswith("setup.exe"), t5.path
t5._binaries_only = False; t5._reload_game_files(auto_plot=True, keep_current=True)
assert t5.path.endswith("data.pak") or t5.path.endswith("setup.exe"), t5.path
print("tab logic checks passed")
