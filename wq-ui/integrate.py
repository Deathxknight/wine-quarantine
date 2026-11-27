#!/usr/bin/env python3
"""Wire wq-ui into a wine-quarantine checkout.

    python3 wq-ui/integrate.py            # apply
    python3 wq-ui/integrate.py --dry-run  # show what would change
    python3 wq-ui/integrate.py --revert   # restore the backups

It edits three files, each located by anchor lines (not line numbers), and
refuses to touch anything if an anchor is missing or ambiguous:

  config.sh          appends a block that sources wq-ui/profile.sh
  _launch-core.sh    calls apply_game_profile and adds extra whitelist args
  verify-sandbox.sh  teaches the verifier which protections the profile turned
                     off on purpose (otherwise it aborts the launch), then
                     re-pins verify-sandbox.sha256 via its own --update-hash

Originals are kept as <file>.wq-orig.
"""
import argparse
import difflib
import shutil
import subprocess
import sys
from pathlib import Path

MARK = "# wq-ui integration"


def find_one(lines, pred, what):
    hits = [i for i, l in enumerate(lines) if pred(l.strip())]
    if len(hits) != 1:
        sys.exit(f"anchor problem: expected exactly one match for {what}, found {len(hits)}. "
                 "The repo has probably changed; nothing was modified.")
    return hits[0]


def patch_config(text):
    block = (
        f"\n{MARK}: per-game firejail profiles\n"
        'if [ -f "$QROOT/wq-ui/profile.sh" ]; then\n'
        '    # shellcheck source=/dev/null\n'
        '    . "$QROOT/wq-ui/profile.sh"\n'
        "fi\n"
    )
    return text.rstrip("\n") + "\n" + block


def patch_launch(text):
    lines = text.split("\n")
    i_wl = find_one(lines, lambda s: s.startswith("mapfile -t WL_ARGS"), "'mapfile -t WL_ARGS'")
    i_bl = find_one(lines, lambda s: s.startswith("mapfile -t BL_ARGS"), "'mapfile -t BL_ARGS'")
    if i_bl < i_wl:
        sys.exit("unexpected order of WL_ARGS / BL_ARGS in _launch-core.sh")
    extra = ['mapfile -t -O "${#WL_ARGS[@]}" WL_ARGS < <(profile_extra_whitelist_args)  ' + MARK]
    guard = ['WQ_LIMITS_SUPPORTED=1  ' + MARK + ': both firejail calls below use WQ_LIMIT_PREFIX',
             'apply_game_profile "$GAMEDIR"  ' + MARK]
    # both firejail launches (prefix bootstrap + monitored run) go inside the cgroup scope
    envs = [i for i, l in enumerate(lines) if l.strip().startswith("env -u DBUS_SESSION_BUS_ADDRESS")]
    if len(envs) != 2:
        sys.exit(f"anchor problem: expected 2 firejail launches in _launch-core.sh, found {len(envs)}. "
                 "The repo has probably changed; nothing was modified.")
    for i in envs:
        lines[i] = lines[i].replace("env -u", '${WQ_LIMIT_PREFIX[@]+"${WQ_LIMIT_PREFIX[@]}"} env -u', 1)
    # insert later one first so indexes stay valid
    lines[i_bl + 1:i_bl + 1] = extra
    lines[i_wl:i_wl] = guard
    return "\n".join(lines)


def patch_verify(text):
    lines = text.split("\n")

    def S(prefix):
        return lambda s: s.startswith(prefix)

    # work from the bottom of the file upwards so indexes stay valid
    edits = []

    i = find_one(lines, S('fail "\\$HOME/$entry present - real home leaked"'), "home-leak fail")
    edits.append((i, i + 2, [
        'if skipped home; then HOME_BAD=0; else',
        'fail "\\$HOME/$entry present - real home leaked"',
        'HOME_BAD=1',
        'fi']))

    i = find_one(lines, S('|| fail "non-loopback interfaces visible'), "network fail")
    edits.append((i, i + 1, [
        '|| { if [ "${QVERIFY_NET:-off}" != off ]; then '
        'pass "network enabled by profile (${QVERIFY_NET}): $NON_LO"; '
        'else fail "non-loopback interfaces visible: $NON_LO"; fi; }']))

    i = find_one(lines, S('case "$sec" in'), "seccomp case")
    edits.append((i, i + 1, [
        'if skipped seccomp; then sec=skip; fi',
        'case "$sec" in',
        'skip) pass "Seccomp check skipped by profile" ;;']))

    i = find_one(lines, S('[ "$nnp" = "1" ] && pass'), "NoNewPrivs check")
    edits.append((i, i + 1, [
        'if skipped nnp; then pass "NoNewPrivs check skipped by profile"; else',
        lines[i],
        'fi']))

    i = find_one(lines, S("for cap in CapEff CapPrm CapBnd CapAmb; do"), "capability loop")
    edits.append((i, i + 1, [
        lines[i],
        'if skipped caps; then pass "capability check skipped by profile"; break; fi']))

    i = find_one(lines, S("fail() {"), "fail() helper")
    edits.append((i, i + 1, [
        lines[i],
        '# profile-disabled protections (QVERIFY_SKIP is set outside the sandbox)',
        'skipped() { case ",${QVERIFY_SKIP:-}," in *",$1,"*) return 0 ;; esac; return 1; }']))

    for a, b, new in sorted(edits, key=lambda e: -e[0]):
        lines[a:b] = new

    # marker right after the shebang
    lines.insert(1, MARK + ": checks are relaxed only for protections the profile disabled")
    return "\n".join(lines)


TARGETS = [
    ("config.sh", patch_config),
    ("_launch-core.sh", patch_launch),
    ("verify-sandbox.sh", patch_verify),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--revert", action="store_true")
    args = ap.parse_args()
    root = args.root

    for name, _ in TARGETS:
        if not (root / name).is_file():
            sys.exit(f"{root / name} not found - run this from a wine-quarantine checkout "
                     "(or pass --root).")

    if args.revert:
        for name, _ in TARGETS:
            bak = root / (name + ".wq-orig")
            if bak.exists():
                shutil.copy2(bak, root / name)
                print(f"restored {name}")
        v = root / "verify-sandbox.sh"
        if v.exists():
            subprocess.run([str(v), "--update-hash"], check=False)
        return

    new_texts = {}
    for name, fn in TARGETS:
        old = (root / name).read_text()
        if MARK in old:
            print(f"{name}: already integrated, skipping")
            continue
        new_texts[name] = (old, fn(old))

    for name, (old, new) in new_texts.items():
        if args.dry_run:
            sys.stdout.writelines(difflib.unified_diff(
                old.splitlines(True), new.splitlines(True), f"a/{name}", f"b/{name}"))
        else:
            bak = root / (name + ".wq-orig")
            if not bak.exists():
                shutil.copy2(root / name, bak)
            (root / name).write_text(new)
            print(f"patched {name}")

    if args.dry_run:
        return

    if "verify-sandbox.sh" in new_texts:
        print("re-pinning verify-sandbox.sha256 ...")
        subprocess.run([str(root / "verify-sandbox.sh"), "--update-hash"], check=True)

    gi = root / ".gitignore"
    wanted = ["profile.defaults.conf", ".wq-netfilter", "*.wq-orig"]
    have = gi.read_text().splitlines() if gi.exists() else []
    add = [w for w in wanted if w not in have]
    if add:
        with gi.open("a") as f:
            f.write("\n" + "\n".join(add) + "\n")
        print("updated .gitignore")
    print("done.")


if __name__ == "__main__":
    main()
