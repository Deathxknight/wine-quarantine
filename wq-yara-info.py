#!/usr/bin/env python3
"""wq-yara-info.py <rules file or folder> <rule name>...

Looks up how serious each named YARA rule is, from the rule's own source:
  tier  HIGH    score >= YARA_BLOCK_SCORE (default 70), or an unscored rule from a malware/webshell/exploit folder
        MEDIUM  score >= YARA_WARN_SCORE (default 40), or an unscored rule from anywhere else (unknown = look at it)
        INFO    score below that, or an unscored rule from a packer/compiler/anti-debug/capability folder
  feed    an unscored rule from the downloaded YARAhub feed (yarahub/) gets YARA_FEED_TIER (default INFO):
          community-submitted, no score, and many are loose enough to match clean files such as PuTTY or
          Wine's own DLLs. Scored rules (signature-base) are unaffected. YARA_FEED_TIER=MEDIUM restores a WARN.
One line per rule: name TAB tier TAB score TAB description ("-" when there is none)."""
import os
import re
import sys


def _env_int(name, default):
    """An integer from the environment; empty or non-numeric values fall back to the default."""
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


BLOCK = _env_int("YARA_BLOCK_SCORE", 70)
WARN = _env_int("YARA_WARN_SCORE", 40)
HIGH_DIRS = {"malware", "webshells", "exploit_kits", "maldocs"}
INFO_DIRS = {"packers", "antidebug_antivm", "capabilities", "crypto", "utils"}
FEED_DIRS = {"yarahub"}
FEED_TIER = (os.environ.get("YARA_FEED_TIER", "").strip().upper() or "INFO")
if FEED_TIER not in ("INFO", "MEDIUM", "HIGH"):
    FEED_TIER = "INFO"
HEAD = re.compile(r"(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)")
SCORE = re.compile(r"\bscore\s*=\s*(\d+)")
DESC = re.compile(r'\bdescription\s*=\s*"((?:[^"\\]|\\.)*)"')


def rule_files(root):
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for dp, _dn, fns in os.walk(root):
        for fn in sorted(fns):
            if fn.lower().endswith((".yar", ".yara")):
                p = os.path.join(dp, fn)
                yield p, os.path.relpath(p, root)


def main():
    if len(sys.argv) < 3:
        print("usage: wq-yara-info.py <rules file or folder> <rule name>...", file=sys.stderr)
        return 2
    root, wanted = sys.argv[1], set(sys.argv[2:])
    found = {}
    for path, rel in rule_files(root):
        if len(found) == len(wanted):
            break
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if not any(n in text for n in wanted):
            continue
        heads = list(HEAD.finditer(text))
        for i, m in enumerate(heads):
            name = m.group(1)
            if name not in wanted or name in found:
                continue
            block = text[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)]
            sm, dm = SCORE.search(block), DESC.search(block)
            found[name] = (int(sm.group(1)) if sm else None, dm.group(1) if dm else "", rel)
    for name in sorted(wanted):
        score, desc, rel = found.get(name, (None, "", ""))
        parts = rel.replace("\\", "/").split("/")
        if parts[0] == "rules":          # the built ruleset keeps its sources under rules/
            parts = parts[1:]
        top = parts[0] if len(parts) > 1 else ""
        if score is not None:
            tier = "HIGH" if score >= BLOCK else "MEDIUM" if score >= WARN else "INFO"
        elif top in HIGH_DIRS:
            tier = "HIGH"
        elif top in FEED_DIRS:
            tier = FEED_TIER
        elif top in INFO_DIRS:
            tier = "INFO"
        else:
            tier = "MEDIUM"
        desc = " ".join(desc.split())[:90] or "-"
        print("%s\t%s\t%s\t%s" % (name, tier, "-" if score is None else score, desc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
