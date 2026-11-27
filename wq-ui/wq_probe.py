"""Qt-free logic for the "Test sandbox" feature: builds a throwaway native game that runs probe.sh
with a game's effective firejail profile, parses what the probe prints, keeps the last few runs
per game and diffs them. Kept separate from the Qt code so it can be tested without a display."""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path

import wq_core as core

PROBE_SRC = Path(__file__).with_name("probe.sh")
TEST_DIR = "_sandbox-test"          # leading "_": scan_games and update-launchers ignore it
RESULTS_DIR = ".sandbox-tests"      # leading ".": same
KEEP_RUNS = 5
DEFAULTS_KEY = "(defaults)"

# same text config.sh's wq_launcher_text prints for a native game (test_probe.py checks they match)
LAUNCHER_TEXT = (
    '#!/bin/bash\n'
    'D="$(dirname "$(readlink -f "$0")")"\n'
    'exec "$(dirname "$D")/wq-ui/_launch-native.sh" "$(basename "$D")"\n'
)

HOOK_KEYS = ("FJ_HOOK_PRE", "FJ_HOOK_POST")
# the probe is not a game: no ClamAV scan, and a monitor alert must not cut the report short
FORCED = {"CLAM_SCAN": "0", "YARA_SCAN": "0", "CAPA_SCAN": "0", "MONITOR_KILL": "0", "PRESCAN": "0"}   # probe.sh opens raw sockets on purpose

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ROW = re.compile(r"^\s{2}(ok|LEAK|info)\s+(.*\S)\s*$")
_SECTION = re.compile(r"^== (.+?)\s*$")
_VERIFY = re.compile(r"\[SANDBOX-VERIFY\]\s+(ok|FAIL):?\s*(.*)")
_VERIFY_TOTAL = re.compile(r"\[SANDBOX-VERIFY\]\s+(\d+) passed, (\d+) failed")
_SUMMARY = re.compile(r"^== summary:")


# profile

def effective_profile(g: core.Game | None, defaults: dict[str, list[str]]) -> dict[str, list[str]]:
    """Every profile setting that applies to `g` (None = the saved defaults only), resolved the way
    the launcher resolves it. Written out in full so the test game gets the same profile whatever
    its own runner default would have been (FJ_RESTRICT_NS differs between Wine and native)."""
    gg = g or core.Game(DEFAULTS_KEY, Path("."), {}, False)
    out: dict[str, list[str]] = {}
    for key in core.ALL_BOOLS:
        out[key] = ["1" if gg.flag(key, defaults) else "0"]
    for key, builtin in core.TEXT_KEYS.items():
        out[key] = [gg.scalar(key, defaults, builtin)]
    for key in core.LIST_KEYS:
        if key in HOOK_KEYS:                    # hooks run on the host, never copied into a test
            continue
        if key == "FJ_NET_ALLOW":               # profile.sh merges game.conf and defaults for this one
            vals = [v.strip() for v in gg.conf.get(key, []) + defaults.get(key, []) if v.strip()]
        else:
            vals = gg.effective_lines(key, defaults)
        out[key] = vals
    out.update({k: [v] for k, v in FORCED.items()})
    return out


def conf_text(profile: dict[str, list[str]]) -> str:
    lines = ["# written by wq-ui 'Test sandbox', recreated on every test", "EXE=probe.sh", "RUNNER=native"]
    for key, vals in profile.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            continue
        clean = [v for v in vals if "\n" not in v and "\r" not in v]
        for v in (clean or [""]):               # "KEY=" = "none", so the defaults file isn't consulted
            lines.append(f"{key}={v}")
    return "\n".join(lines) + "\n"


def prepare(qroot: Path, profile: dict[str, list[str]]) -> Path:
    """(Re)create <qroot>/_sandbox-test as a native game that runs probe.sh. Returns its path."""
    if not PROBE_SRC.is_file():
        raise FileNotFoundError(f"{PROBE_SRC} is missing")
    d = qroot / TEST_DIR
    if os.path.islink(d):
        raise OSError(f"{d} is a symlink, refusing to touch it")
    if d.exists():
        if not d.is_dir():
            raise OSError(f"{d} exists and is not a folder")
        shutil.rmtree(d)
    (d / "game").mkdir(parents=True)
    (d / "logs").mkdir()
    probe = d / "game" / "probe.sh"
    shutil.copyfile(PROBE_SRC, probe)
    probe.chmod(0o755)
    (d / "game.conf").write_text(conf_text(profile))
    launcher = d / "launch-quarantine.sh"
    launcher.write_text(LAUNCHER_TEXT)
    launcher.chmod(0o755)
    return d


# parsing

def parse_output(text: str) -> dict:
    """-> {rows: [{section, tag, text}], summary_seen, verify_passed, verify_failed, verify_fail_lines}"""
    rows: list[dict] = []
    section = ""
    summary_seen = False
    v_pass = v_fail = None
    v_lines: list[str] = []
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).rstrip("\r")
        if _SUMMARY.match(line):
            summary_seen = True
            section = ""
            continue
        m = _VERIFY_TOTAL.search(line)
        if m:
            v_pass, v_fail = int(m.group(1)), int(m.group(2))
            continue
        m = _VERIFY.search(line)
        if m:
            if m.group(1) == "FAIL" and m.group(2).strip() not in v_lines:     # the run summary repeats them
                v_lines.append(m.group(2).strip())
            continue
        m = _SECTION.match(line)
        if m:
            section = m.group(1)
            continue
        m = _ROW.match(line)
        if m and section:
            rows.append({"section": section, "tag": m.group(1), "text": m.group(2)})
    return {"rows": rows, "summary_seen": summary_seen, "verify_passed": v_pass,
            "verify_failed": v_fail, "verify_fail_lines": v_lines}


def counts(rows: list[dict]) -> dict[str, int]:
    c = {"LEAK": 0, "ok": 0, "info": 0}
    for r in rows:
        c[r["tag"]] = c.get(r["tag"], 0) + 1
    return c


def status(parsed: dict) -> str:
    """'blocked' = the verifier stopped the launch, 'noprobe' = the probe never ran, 'leaks', 'clean'"""
    if parsed["verify_failed"]:
        return "blocked"
    if not parsed["rows"] or not parsed["summary_seen"]:
        return "noprobe"
    return "leaks" if counts(parsed["rows"])["LEAK"] else "clean"


# comparing runs

def norm(text: str) -> str:
    """Numbers, ids and hex differ run to run (display numbers, entry counts, machine-id): fold them."""
    return re.sub(r"0x[0-9a-fA-F]+|[0-9a-f]{8}\.\.\.|\d+", "#", text)


def diff_rows(old: list[dict], new: list[dict]) -> list[dict]:
    """Rows whose verdict changed, appeared or vanished: [{kind, section, text, old, new}]."""
    def index(rows):
        d: dict[tuple[str, str], dict] = {}
        for r in rows:
            d.setdefault((r["section"], norm(r["text"])), r)
        return d
    a, b = index(old), index(new)
    out: list[dict] = []
    for k, r in b.items():
        o = a.get(k)
        if o is None:
            out.append({"kind": "new", "section": r["section"], "text": r["text"], "old": None, "new": r["tag"]})
        elif o["tag"] != r["tag"]:
            out.append({"kind": "changed", "section": r["section"], "text": r["text"], "old": o["tag"], "new": r["tag"]})
    for k, r in a.items():
        if k not in b:
            out.append({"kind": "gone", "section": r["section"], "text": r["text"], "old": r["tag"], "new": None})
    order = {"LEAK": 0, "info": 1, "ok": 2, None: 3}
    out.sort(key=lambda x: (order.get(x["new"], 3), x["section"], x["text"]))
    return out


def diff_profile(old: dict[str, list[str]], new: dict[str, list[str]]) -> list[tuple[str, str, str]]:
    """Settings that differ: [(key, old value, new value)]. FORCED keys are ignored."""
    out = []
    for k in sorted(set(old) | set(new)):
        if k in FORCED:
            continue
        a, b = "; ".join(old.get(k, [])), "; ".join(new.get(k, []))
        if a != b:
            out.append((k, a or "(none)", b or "(none)"))
    return out


# stored runs

def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name) or "game"


def results_path(qroot: Path, game_name: str) -> Path:
    return qroot / RESULTS_DIR / f"{_safe(game_name)}.json"


def load_runs(qroot: Path, game_name: str) -> list[dict]:
    try:
        data = json.loads(results_path(qroot, game_name).read_text())
        runs = data.get("runs", [])
        return [r for r in runs if isinstance(r, dict) and isinstance(r.get("rows"), list)]
    except (OSError, ValueError, AttributeError):
        return []


def save_run(qroot: Path, game_name: str, run: dict) -> list[dict]:
    """Append `run`, keep the last KEEP_RUNS, write atomically. Returns the stored list."""
    runs = (load_runs(qroot, game_name) + [run])[-KEEP_RUNS:]
    path = results_path(qroot, game_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".wq-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"runs": runs}, f, indent=1)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return runs


def make_run(parsed: dict, profile: dict[str, list[str]]) -> dict:
    return {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "status": status(parsed), "profile": profile,
            "rows": parsed["rows"], "verify_passed": parsed["verify_passed"],
            "verify_failed": parsed["verify_failed"], "verify_fail_lines": parsed["verify_fail_lines"]}


# text report

def format_report(game_name: str, run: dict, prev: dict | None) -> str:
    c = counts(run["rows"])
    out = [f"wq sandbox test: {game_name}  ({run['time']})",
           f"status: {run['status']}   {c['LEAK']} leak(s), {c['ok']} ok, {c['info']} info"]
    if run.get("verify_fail_lines"):
        out += ["", "verifier stopped the launch:"] + [f"  FAIL {l}" for l in run["verify_fail_lines"]]
    if prev:
        pd = diff_profile(prev.get("profile", {}), run.get("profile", {}))
        rd = diff_rows(prev["rows"], run["rows"])
        out += ["", f"since the previous run ({prev['time']}):"]
        out += [f"  setting {k}: {a} -> {b}" for k, a, b in pd] or ["  settings: unchanged"]
        for r in rd:
            out.append(f"  {r['kind']:7s} [{r['old'] or '-'} -> {r['new'] or '-'}] {r['section']}: {r['text']}")
        if not rd:
            out.append("  results: unchanged")
    section = None
    for r in run["rows"]:
        if r["section"] != section:
            section = r["section"]
            out += ["", f"== {section}"]
        out.append(f"  {r['tag']:5s} {r['text']}")
    return "\n".join(out) + "\n"
