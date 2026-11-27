#!/bin/bash
# wq-yara-build.sh [--check] <dest-dir> <rules-root>...
#
# Builds the YARA ruleset used by the pre-launch scan from upstream rule checkouts
# (signature-base, Yara-Rules/rules, or your own). Nothing is bundled into this project:
# you point it at folders you cloned yourself, so each upstream's license stays with its files.
#
#   * Picks rule files from known-good folders (skips webshells, maldocs, email, mobile,
#     exploit kits, deprecated, and anything that imports modules this build may lack).
#   * Leaves out files named in yara-skip.txt / yara-skip.local.txt (rules known to flag clean files).
#   * Compiles each file alone with yarac. Files that fail are listed in SKIPPED.txt with
#     the reason, never dropped silently.
#   * Compiles all survivors into one rules.yarc, so the scan runs once instead of once
#     per rule file. If the combined build fails (for example, duplicate rule names across
#     upstreams) it says so and leaves the per-file folder in place as a fallback.
#
# --check   validate and report only; writes nothing.
#
# With no rules-root given the build also uses _yara-feeds/ when it exists (see wq-yara-update.py).
#
# Needs: yarac (package "yara"). Without it nothing is built and the prescan keeps skipping YARA.
set -u

CHECK=0
if [ "${1:-}" = "--check" ]; then CHECK=1; shift; fi
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-}"; [ -n "$DEST" ] || { echo "usage: wq-yara-build.sh [--check] <dest-dir> [rules-root...]" >&2; exit 2; }
shift
# No roots given: use the rule sets bundled under third_party/, plus anything fetched into _yara-feeds/
# (wq-yara-update.py puts the public YARAhub rules there). Bundled rules come first, so when a rule name
# exists in both, the bundled one is kept.
if [ "$#" -eq 0 ]; then
  set -- "$HERE/third_party/signature-base-yara" "$HERE/third_party/yara-rules"
  [ -d "$HERE/_yara-feeds" ] && set -- "$@" "$HERE/_yara-feeds"
fi

YARAC="${YARAC:-yarac}"
# signature-base rules (written for THOR) test external variables that yara does not define itself.
# They are defined here with empty values so those files compile instead of being skipped; the rules
# that depend on a file name or path simply do not fire.
# is__elf / is__pe / is__linux are guards used by many Linux/ELF rules. Defining them at build time
# lets those rules compile; wq-yara.sh sets is__elf=1 at scan time when it's scanning an ELF file.
YDEFS=(-d filename= -d filepath= -d extension= -d filetype= -d owner=)
command -v "$YARAC" >/dev/null 2>&1 || { echo "wq-yara-build: yarac not found (install the 'yara' package)" >&2; exit 1; }

# Folder names (any depth) we never take, plus module imports we don't build with.
SKIP_DIR_RE='/(webshells|maldocs|email|mobile_malware|mobile|exploit_kits|cve_rules|deprecated|utils|vendor|tests|scripts|misc|iocs|\.git)(/|$)'
SKIP_IMPORT_RE='import "(androguard|cuckoo|dotnet|magic)"'

WORK="$(mktemp -d 2>/dev/null)" && [ -d "$WORK" ] && [ -w "$WORK" ] || { echo "wq-yara-build: cannot create a temporary folder (TMPDIR=${TMPDIR:-unset}, /tmp full or read-only?)" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT
# yarac must be able to compile a trivial rule at all. If it cannot (for example a missing shared
# library after a partial upgrade), say that once instead of reporting every rule file as broken.
echo 'rule wq_probe { condition: true }' > "$WORK/probe.yar"
if ! PROBE_ERR="$("$YARAC" "$WORK/probe.yar" "$WORK/probe.yarc" 2>&1)"; then
  echo "wq-yara-build: yarac does not run: $(printf '%s' "$PROBE_ERR" | head -n1 | cut -c1-250)" >&2
  echo "wq-yara-build: fix the yara install first (Arch: sudo pacman -Syu, a partial upgrade can leave yara without a library it needs)" >&2
  exit 1
fi
# an old or odd yarac that rejects -d would fail every file: probe once and fall back to no externals
"$YARAC" "${YDEFS[@]}" "$WORK/probe.yar" "$WORK/probe.yarc" >/dev/null 2>&1 || YDEFS=()

GOOD=(); SKIPPED=(); declare -i NTOTAL=0
declare -A SEEN=() SKIPLIST=()
# yara-skip.txt / yara-skip.local.txt: rule files known to flag clean files. "path  # reason" per line.
for sl in "$HERE/yara-skip.txt" "$HERE/yara-skip.local.txt"; do
  [ -f "$sl" ] || continue
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    p="${line%%#*}"; p="$(printf '%s' "$p" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$p" ] || continue
    why="$(printf '%s' "$line" | sed -n 's/^[^#]*#[[:space:]]*//p')"
    SKIPLIST["$p"]="${why:-listed in yara-skip.txt}"
  done < "$sl"
done

for root in "$@"; do
  [ -d "$root" ] || { echo "wq-yara-build: not a folder: $root" >&2; exit 1; }
  while IFS= read -r f; do
    NTOTAL+=1
    rel="${f#"$root"/}"
    if [[ "/$rel" =~ $SKIP_DIR_RE ]]; then SKIPPED+=("$rel|folder not used for games"); continue; fi
    if [ -n "${SKIPLIST[$rel]+x}" ]; then SKIPPED+=("$rel|skip list: ${SKIPLIST[$rel]}"); continue; fi
    # index files only "include" other files by relative path; the rules themselves are picked up directly
    case "$(basename "$f")" in index.yar|index.yara|index_*.yar|index_*.yara|*_index.yar|*_index.yara|*-index.yar|*-index.yara) SKIPPED+=("$rel|index file (includes other rules)"); continue ;; esac
    if grep -qE "$SKIP_IMPORT_RE" "$f"; then SKIPPED+=("$rel|imports a module this build may lack"); continue; fi
    if ! "$YARAC" "${YDEFS[@]}" "$f" "$WORK/one.yarc" >"$WORK/err.txt" 2>&1; then
      reason="$(head -n1 "$WORK/err.txt" | tr -d '\r')"
      SKIPPED+=("$rel|does not compile: ${reason:-unknown error}")
      continue
    fi
    # yarac refuses one combined ruleset with a rule name defined twice (the upstreams overlap a lot).
    # The first file to define a name is kept; a later file that repeats one is skipped and listed.
    dup=""
    while IFS= read -r n; do
      if [ -n "${SEEN[$n]+x}" ]; then dup="$n (first defined in ${SEEN[$n]})"; break; fi
    done < <(grep -oE '^(private |global )*rule [A-Za-z0-9_]+' "$f" | awk '{print $NF}')
    if [ -n "$dup" ]; then SKIPPED+=("$rel|duplicate rule name $dup"); continue; fi
    while IFS= read -r n; do SEEN[$n]="$rel"; done < <(grep -oE '^(private |global )*rule [A-Za-z0-9_]+' "$f" | awk '{print $NF}')
    GOOD+=("$f")
  done < <(find "$root" -type f \( -name '*.yar' -o -name '*.yara' \) | sort)
done

echo "wq-yara-build: $NTOTAL rule files found, ${#GOOD[@]} usable, ${#SKIPPED[@]} skipped"

if [ "$CHECK" = 1 ]; then
  for s in "${SKIPPED[@]+"${SKIPPED[@]}"}"; do echo "  skip: ${s%%|*} - ${s#*|}"; done
  exit 0
fi

if [ "${#GOOD[@]}" -eq 0 ]; then
  # say why: how many files there were and what they were skipped for
  if [ "$NTOTAL" -eq 0 ]; then
    echo "wq-yara-build: nothing usable, no .yar files found under: $* (is third_party/ empty or incomplete?)" >&2
  else
    cats="$(for s in "${SKIPPED[@]}"; do r="${s#*|}"; echo "${r%%:*}"; done | sort | uniq -c | sort -rn | head -n3 | awk '{c=$1; $1=""; printf "%s x%s;", $0, c}')"
    first="$(for s in "${SKIPPED[@]}"; do case "${s#*|}" in "does not compile"*) echo "${s#*|}"; break ;; esac; done | cut -c1-200)"
    echo "wq-yara-build: nothing usable, $NTOTAL rule file(s) found, all skipped:$cats ${first:+first compile error: $first}" >&2
  fi
  exit 1
fi

mkdir -p "$DEST"
# Rebuild from scratch so removed upstream files don't linger.
rm -rf "$DEST/rules" "$DEST/rules.yarc" "$DEST/SKIPPED.txt"
mkdir -p "$DEST/rules"
for f in "${GOOD[@]}"; do
  # keep the folder layout, so relative includes and folder-based names still make sense
  for root in "$@"; do
    case "$f" in "$root"/*) rel="${f#"$root"/}"; mkdir -p "$DEST/rules/$(dirname "$rel")"; cp "$f" "$DEST/rules/$rel"; break ;; esac
  done
done

{
  echo "# Rule files left out of this build, and why. Nothing here is scanned."
  echo "# Built $(date -u +%Y-%m-%dT%H:%M:%SZ) from: $*"
  for s in "${SKIPPED[@]+"${SKIPPED[@]}"}"; do echo "${s%%|*}: ${s#*|}"; done
} > "$DEST/SKIPPED.txt"

mapfile -t ALL < <(find "$DEST/rules" -type f \( -name '*.yar' -o -name '*.yara' \) | sort)
if "$YARAC" "${YDEFS[@]}" "${ALL[@]}" "$DEST/rules.yarc" >"$WORK/combined.txt" 2>&1; then
  echo "wq-yara-build: compiled to $DEST/rules.yarc (single scan per launch)"
else
  rm -f "$DEST/rules.yarc"
  echo "wq-yara-build: combined compile failed, falling back to per-file scanning:" >&2
  # warnings are harmless; show the errors (the real reason), or the last lines if none are tagged
  if grep -qi 'error' "$WORK/combined.txt"; then grep -i 'error' "$WORK/combined.txt" | head -n5 | sed 's/^/  /' >&2
  else tail -n3 "$WORK/combined.txt" | sed 's/^/  /' >&2; fi
fi
echo "wq-yara-build: details in $DEST/SKIPPED.txt"
