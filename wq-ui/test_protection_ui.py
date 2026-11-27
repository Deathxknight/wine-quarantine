"""Offscreen smoke test for the Protection tab: presets, relaxed markers, filter (skipped without PySide6).
   QT_QPA_PLATFORM=offscreen python3 wq-ui/test_protection_ui.py [screenshot-dir]"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    from PySide6.QtWidgets import QApplication
except ImportError:
    print("PySide6 not installed, skipping"); sys.exit(0)

T = Path(tempfile.mkdtemp())
os.environ["XDG_CONFIG_HOME"] = str(T / "cfg")
os.environ["XDG_CACHE_HOME"] = str(T / "cache")
q = T / "q"
q.mkdir()
for f in ("config.sh", "_launch-core.sh"):
    (q / f).write_text("# stub\n")
(q / "g1" / "game").mkdir(parents=True)
(q / "g1" / "game.conf").write_text("EXE=a.exe\nFJ_NOSOUND=0\n")
(q / "g2" / "game").mkdir(parents=True)
(q / "g2" / "game.conf").write_text("EXE=b.exe\nFJ_NOSOUND=1\n")

import wq_core as core  # noqa: E402
import wq_ui as ui  # noqa: E402

app = QApplication([])
settings = ui.Settings()
theme = ui.ThemeManager(app, settings)
theme.apply()
win = ui.MainWindow(settings, theme, q)
win.show()
fails = 0


def check(cond, msg):
    global fails
    print(("ok   - " if cond else "FAIL - ") + msg)
    fails += not cond


def select(*names):
    win.tree.clearSelection()
    for i in range(win.tree.topLevelItemCount()):
        it = win.tree.topLevelItem(i)
        if it.text(0) in names:
            it.setSelected(True)
    app.processEvents()


def active():
    return win.preset_group.checkedButton().text()


def box(k):
    return win.boxes[k]


shots = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if shots:
    shots.mkdir(parents=True, exist_ok=True)

select("g1")
check(win.loaded == ["g1"], "game loaded")
check(active() == "Custom", "stock defaults match no preset")
iso = next(g for g in win.groups if g.title_text == "Isolation")
adv = next(g for g in win.groups if g.title_text == "Advanced")
dev = next(g for g in win.groups if g.title_text == "Devices")
check(iso._open and not adv._open and not dev._open, "Isolation starts open, the rest collapsed")
check({b.key for b in adv.boxes} == set(core.ADVANCED_KEYS), "Advanced holds the rarely used options")

win._apply_preset("Strict")
check(active() == "Strict" and all(box(k).checkState() == (ui.Checked if v else ui.Unchecked)
                                   for k, v in core.PRESETS["Strict"].items()), "Strict ticks everything")
check(win.pending_count() > 0 and win.btn_apply.isEnabled(), "a preset is an unapplied change")
check(not any(b.property("relaxed") for g in win.groups for b in g.boxes), "nothing is marked relaxed under Strict")
check(all(g.relaxed.isHidden() for g in win.groups), "badges hidden when nothing is relaxed")

win._apply_preset("Balanced")
check(active() == "Balanced" and box("FJ_GAME_RO").checkState() == ui.Unchecked, "Balanced relaxes the game folder")
check(bool(box("FJ_GAME_RO").property("relaxed")), "relaxed box is marked")
check(iso.relaxed.text() == "1 relaxed" and "14/" not in iso.count.text(), "group badge counts relaxed boxes")
check(dev.relaxed.text() == "1 relaxed", "Devices badge shows block audio is off")

box("FJ_NOSOUND").setCheckState(ui.Checked); win._mark("FJ_NOSOUND")
check(active() == "Custom", "a manual change flips the preset to Custom")

win._apply_preset("Strict"); win._apply_preset("Balanced")
win.relaxed_only.setChecked(True)
vis = [b.key for g in win.groups for b in g.boxes if not b.isHidden()]
check(set(vis) == {"FJ_GAME_RO", "FJ_RESTRICT_NS", "FJ_NOSOUND"}, f"Relaxed only shows just those: {vis}")
check(not next(g for g in win.groups if g.title_text == "Monitoring").isVisibleTo(win), "groups with nothing relaxed hide")
win.relaxed_only.setChecked(False)
win.search.setText("webcam")
vis = [b.key for g in win.groups for b in g.boxes if not b.isHidden()]
check(vis == ["FJ_NOVIDEO"], f"search finds Block webcams: {vis}")
win.search.setText("")
check(all(not b.isHidden() for g in win.groups for b in g.boxes), "clearing the search shows everything again")

win.dirty.clear(); win.update_apply_bar()    # else switching games asks about unapplied edits (a modal dialog)
select("g1", "g2")
check(box("FJ_NOSOUND").checkState() == ui.Partial, "games that disagree show a half-ticked box")
check(bool(box("FJ_NOSOUND").property("relaxed")), "a differing box counts as relaxed")
win.dirty.clear(); win.update_apply_bar()

if shots:
    win.dirty.clear(); select("g1"); win._apply_preset("Balanced"); win.tabs.setCurrentIndex(0)
    win.resize(1280, 900); app.processEvents()
    win.grab().save(str(shots / "protection-balanced.png"))
    for g in win.groups:
        g.set_open(True)
    app.processEvents()
    win.grab().save(str(shots / "protection-all-open.png"))

shutil.rmtree(T, ignore_errors=True)
print("\nPROTECTION UI TESTS " + ("FAILED" if fails else "PASSED"))
sys.stdout.flush(); os._exit(1 if fails else 0)    # skips Qt teardown noise from the journalctl follower
