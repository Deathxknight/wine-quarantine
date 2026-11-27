#!/bin/bash
# wq-yara.sh <GameName> [--when prelaunch|run|manual] [--full] [--alertlog FILE]
# wq-yara.sh --check | --build
#
# YARA scan of a quarantined game with the bundled rule sets (third_party/signature-base-yara and
# third_party/yara-rules). Used by wq-prescan.sh (before launch) and after every run, next to the
# ClamAV scan. What gets scanned:
#   prelaunch   game/ (files changed since the last scan, see below)
#   run         game/ plus prefix/ (home/ for native games): what the run created or changed
#   manual      the same as run, always a full scan
# Like ClamAV, scans are incremental. A full scan is done when there is no stamp yet, when the
# ruleset is newer than the stamp, after a match (until a clean full scan), or every
# YARA_FULL_EVERY_DAYS days.
#
# The ruleset is built once by wq-yara-build.sh into $YARA_RULES (default $QROOT/_yara-build) the
# first time it is needed, and again when the bundled rules or the installed yara version change.
#
# Exit: 0 clean (or disabled, or cannot run after a run), 1 matches at YARA_LEVEL=ALERT, 2 usage error,
# 3 the scan is switched on but cannot run (yara or the ruleset is missing, or yara failed) in prelaunch
# mode: wq-prescan.sh refuses the launch then. Untick "YARA scan" in wq-ui (YARA_SCAN=0) to run without it.
# After a run (or by hand) the same problems are only a warning, there is nothing left to stop.
#
# Before each scan it also fetches the public YARAhub rules (wq-yara-update.py, once a day, never blocks the scan);
# YARA_FEEDS_UPDATE=0 switches that off.
# Settings (config.sh / config.local.sh): YARA_RULES (folder from wq-yara-build.sh, or one rule file)
# YARA_LEVEL (AUTO|WARN|ALERT, default AUTO: see below) YARA_AUTOBUILD (1) YARA_FULL_EVERY_DAYS (7)
# YARA_MAX_FILESIZE_MB (200) YARA_TIMEOUT (300 seconds) YARA_SANDBOX (1) YARA_EXCLUDE_REGEX
# Per game, game.conf: YARA_SCAN=0|1 (the "YARA scan" checkbox in wq-ui).
#
# YARA_LEVEL=AUTO sorts every match by how serious its rule is (wq-yara-info.py: the rule's own score, or its
# folder when it has none): HIGH (score >= YARA_BLOCK_SCORE, default 70, or an unscored malware/webshell/exploit
# rule) is an ALERT and exit 1, so wq-prescan.sh refuses the launch; MEDIUM (score >= YARA_WARN_SCORE, 40) is a
# WARN; the rest (packer/compiler/file-type rules like IsPE64) is one INFO line. YARA_LEVEL=WARN or ALERT treats
# every match alike, as before.
# yara only reads files and never executes them, but it still parses untrusted data, so it runs
# inside a firejail with no network when firejail is installed (YARA_SANDBOX=0 to disable).
set -u
QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck source=config.sh
source "$QROOT/config.sh" || { echo "wq-yara: cannot load $QROOT/config.sh" >&2; exit 2; }
# shellcheck source=lib-firejail.sh
source "$QROOT/lib-firejail.sh" || { echo "wq-yara: cannot load $QROOT/lib-firejail.sh" >&2; exit 2; }

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

DEFAULT_RULES="$QROOT/_yara-build"
YARA_RULES="${YARA_RULES:-$DEFAULT_RULES}"
YARA_LEVEL="${YARA_LEVEL:-AUTO}"
YARA_AUTOBUILD="${YARA_AUTOBUILD:-1}"
YARA_FULL_EVERY_DAYS="${YARA_FULL_EVERY_DAYS:-7}"
YARA_MAX_FILESIZE_MB="${YARA_MAX_FILESIZE_MB:-200}"
YARA_TIMEOUT="${YARA_TIMEOUT:-300}"
YARA_SANDBOX="${YARA_SANDBOX:-1}"
# Default: Wine's registry files are plain text, and PE-oriented rules (Surtr's "Burn\\" string, for one) hit them on
# clean prefixes. The registry is checked by reg-diff.sh instead. Set YARA_EXCLUDE_REGEX="" to scan them anyway.
YARA_EXCLUDE_REGEX="${YARA_EXCLUDE_REGEX-/prefix/(system|user|userdef)\.reg(\.old)?$}"
YARA_BIN="${YARA_BIN:-yara}"
YARAC_BIN="${YARAC:-yarac}"
GAMEDIR=""; BUILD_FAILED=""

conf_get() {   # game.conf, then profile.defaults.conf (when profile.sh is loaded), then the default
  if declare -F _wq_get >/dev/null 2>&1; then
    _wq_get "$GAMEDIR" "$1" "$2"
  else
    read_game_conf "$GAMEDIR" "$1" 2>/dev/null || printf '%s' "$2"
  fi
}

yara_version() { "$YARA_BIN" --version 2>/dev/null | head -n1; }

# Is the ruleset at $YARA_RULES usable as it stands? (a file, or a folder with rules.yarc / rule files)
rules_present() {
  if [ -f "$YARA_RULES" ]; then return 0; fi
  [ -d "$YARA_RULES" ] || return 1
  [ -f "$YARA_RULES/rules.yarc" ] && return 0
  [ -n "$(find "$YARA_RULES" -type f \( -name '*.yar' -o -name '*.yara' \) -print -quit 2>/dev/null)" ]
}

# Only the default folder is ours to (re)build; a YARA_RULES the user pointed elsewhere is left alone.
rules_stale() {
  [ "$YARA_RULES" = "$DEFAULT_RULES" ] || return 1
  local mark="$YARA_RULES/.built"
  [ -f "$mark" ] || return 0
  [ -n "$(find "$QROOT/third_party/signature-base-yara" "$QROOT/third_party/yara-rules" -type f -newer "$mark" -print -quit 2>/dev/null)" ] && return 0
  # rules fetched by wq-yara-update.py (only rule files count, so a "last checked" stamp does not force a rebuild)
  [ -n "$(find "$QROOT/_yara-feeds" -type f \( -name '*.yar' -o -name '*.yara' \) -newer "$mark" -print -quit 2>/dev/null)" ] && return 0
  [ -n "$(find "$QROOT" -maxdepth 1 -name 'yara-skip*.txt' -newer "$mark" -print -quit 2>/dev/null)" ] && return 0
  [ "$(sed -n 2p "$mark" 2>/dev/null)" = "$(yara_version)" ] || return 0
  return 1
}

build_rules() {   # prints the build summary on success; on failure the reason goes to $RAWLOG
  local out rc r
  if ! command -v "$YARAC_BIN" >/dev/null 2>&1; then echo "yarac not found" >> "${RAWLOG:-/dev/null}"; return 1; fi
  if [ ! -x "$QROOT/wq-yara-build.sh" ]; then echo "$QROOT/wq-yara-build.sh is missing or not executable (chmod +x it)" >> "${RAWLOG:-/dev/null}"; return 1; fi
  for r in signature-base-yara yara-rules; do
    if [ ! -d "$QROOT/third_party/$r" ]; then echo "$QROOT/third_party/$r is missing: copy third_party/ from the project" >> "${RAWLOG:-/dev/null}"; return 1; fi
  done
  out="$(YARAC="$YARAC_BIN" "$QROOT/wq-yara-build.sh" "$DEFAULT_RULES" 2>&1)"; rc=$?
  printf '%s\n' "$out" >> "${RAWLOG:-/dev/null}" 2>/dev/null
  [ "$rc" -eq 0 ] || return 1
  { date -u +%Y-%m-%dT%H:%M:%SZ; yara_version; } > "$DEFAULT_RULES/.built" 2>>"${RAWLOG:-/dev/null}" || return 1
  printf '%s' "$(printf '%s\n' "$out" | head -n1)"
  return 0
}

# the last meaningful line the failed build left in the raw log
build_fail_reason() { grep -v '^[[:space:]]*$' "$RAWLOG" 2>/dev/null | tail -n1 | cut -c1-300; }

if [ "${1:-}" = "--check" ] || [ "${1:-}" = "--build" ]; then
  MODE="$1"; RAWLOG=/dev/stderr
  if ! command -v "$YARA_BIN" >/dev/null 2>&1; then
    echo "YARA: $YARA_BIN not found. Install the yara package."; exit 0
  fi
  echo "YARA: $(command -v "$YARA_BIN") ($(yara_version))"
  command -v "$YARAC_BIN" >/dev/null 2>&1 && echo "yarac: $(command -v "$YARAC_BIN")" || echo "yarac: not found (needed to build the bundled rules)"
  if [ "$MODE" = "--build" ] || { ! rules_present; } || rules_stale; then
    if [ "$YARA_RULES" = "$DEFAULT_RULES" ] && [ "$YARA_AUTOBUILD" = 1 ] || [ "$MODE" = "--build" ]; then
      YARA_RULES="$DEFAULT_RULES"
      summary="$(build_rules)" && echo "build: $summary" || echo "build: failed (see messages above or run wq-yara-build.sh by hand)"
    fi
  fi
  if rules_present; then
    if [ -f "$YARA_RULES/rules.yarc" ]; then echo "rules: $YARA_RULES/rules.yarc (compiled)"; else echo "rules: $YARA_RULES"; fi
    [ -f "$YARA_RULES/SKIPPED.txt" ] && echo "left out at build time: $(grep -c '^[^#].*: ' "$YARA_RULES/SKIPPED.txt" 2>/dev/null || echo 0) rule file(s), see $YARA_RULES/SKIPPED.txt"
  else
    echo "rules: none at $YARA_RULES"
  fi
  command -v firejail >/dev/null 2>&1 && echo "sandbox: firejail available (YARA_SANDBOX=$YARA_SANDBOX)" || echo "sandbox: firejail missing, yara would run unsandboxed"
  exit 0
fi

WHEN=manual; FULL=0; ALERTLOG=""; GAMENAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --when)     WHEN="${2:-}"; shift 2 || { echo "wq-yara: --when needs a value" >&2; exit 2; } ;;
    --full)     FULL=1; shift ;;
    --alertlog) ALERTLOG="${2:-}"; shift 2 || { echo "wq-yara: --alertlog needs a value" >&2; exit 2; } ;;
    -*)         echo "wq-yara: unknown option $1" >&2; exit 2 ;;
    *)          [ -z "$GAMENAME" ] && GAMENAME="${1%/}" || { echo "wq-yara: more than one game name" >&2; exit 2; }; shift ;;
  esac
done
case "$WHEN" in prelaunch|run|manual) ;; *) echo "wq-yara: --when must be prelaunch, run or manual" >&2; exit 2 ;; esac
case "$GAMENAME" in
  ""|*/*|.|..) echo "usage: wq-yara.sh <GameName> [--when prelaunch|run|manual] [--full] [--alertlog FILE] | --check | --build" >&2; exit 2 ;;
esac
GAMEDIR="$QROOT/$GAMENAME"
[ -d "$GAMEDIR/game" ] || { echo "wq-yara: no such game: $GAMENAME" >&2; exit 2; }
GAMEDIR="$(readlink -f "$GAMEDIR")"
LOGDIR="$GAMEDIR/logs"; mkdir -p "$LOGDIR"

[ "${YARA_SCAN:-1}" != 0 ] && [ "$(conf_get YARA_SCAN 1)" != 0 ] || exit 0
[ "$WHEN" != manual ] || FULL=1
case "$YARA_LEVEL" in AUTO|WARN|ALERT) ;; *) YARA_LEVEL=AUTO ;; esac

TS_FILE="$(date +%Y%m%d-%H%M%S)"
[ -n "$ALERTLOG" ] || ALERTLOG="$LOGDIR/alerts-$TS_FILE-yara.log"
RAWLOG="$LOGDIR/yara-$TS_FILE.log"

log() {
  local level="$1" msg ts; msg="$(wq_clean_text "$2")"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts] [$level] $msg" >> "$ALERTLOG"
  case "$level" in
    ALERT) printf '%b[ALERT] %s%b\n' "$RED" "$msg" "$NC" ;;
    WARN)  printf '%b[WARN]  %s%b\n' "$YEL" "$msg" "$NC" ;;
    INFO)  printf '%b[INFO]  %s%b\n' "$GRN" "$msg" "$NC" ;;
  esac
}

# cannot_run <reason>: before a launch a ticked-but-unusable scan refuses the launch, otherwise it is a warning
cannot_run() {
  if [ "$WHEN" = prelaunch ]; then
    log ALERT "YARA scan is switched on but cannot run: $1. Fix that, or untick 'YARA scan' in wq-ui (YARA_SCAN=0)."
    exit 3
  fi
  log WARN "YARA scan skipped: $1"
  exit 0
}

find "$LOGDIR" -maxdepth 1 -type f -name 'yara-*.log' -mtime +"${LOG_RETENTION_DAYS:-30}" -delete 2>/dev/null || true

# is yara usable?
if ! command -v "$YARA_BIN" >/dev/null 2>&1; then
  cannot_run "$YARA_BIN is not installed (Arch: sudo pacman -S yara)"
fi

# installed is not the same as working: a missing shared library (partial upgrade) breaks every run
if ! YVER_ERR="$("$YARA_BIN" --version 2>&1 >/dev/null)" || ! "$YARA_BIN" --version >/dev/null 2>&1; then
  cannot_run "yara is installed but does not run: $(printf '%s' "${YVER_ERR:-no output}" | head -n1 | cut -c1-200) (Arch: sudo pacman -Syu to finish a partial upgrade, then check: yara --version)"
fi
if command -v "$YARAC_BIN" >/dev/null 2>&1 && ! YC_ERR="$("$YARAC_BIN" -v 2>&1 >/dev/null)" ; then
  cannot_run "yarac is installed but does not run: $(printf '%s' "${YC_ERR:-no output}" | head -n1 | cut -c1-200) (Arch: sudo pacman -Syu, then check: yarac --version)"
fi

# fresh YARAhub rules: wq-yara-update.py fetches at most once a day (it returns at once when the rules are
# recent), the build below then picks up the new files. A failure (offline, abuse.ch down) never stops the
# scan: it is logged, and not retried for 6 hours so an offline machine is not slowed at every launch.
if [ "${YARA_FEEDS_UPDATE:-1}" = 1 ] && [ "$YARA_RULES" = "$DEFAULT_RULES" ] && [ -f "$QROOT/wq-yara-update.py" ] \
   && command -v python3 >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
  FAILMARK="$QROOT/_yara-feeds/.update-failed"
  UPD_SIG="$(cksum < "$QROOT/wq-yara-update.py" 2>/dev/null)"   # a new version of the updater is tried at once
  if [ -z "$(find "$FAILMARK" -mmin -360 -print -quit 2>/dev/null)" ] || [ "$(cat "$FAILMARK" 2>/dev/null)" != "$UPD_SIG" ]; then
    mkdir -p "$QROOT/_yara-feeds" 2>/dev/null
    UPD_OUT="$(timeout 120 python3 "$QROOT/wq-yara-update.py" 2>&1)"; UPD_RC=$?
    printf '%s\n' "$UPD_OUT" >> "$RAWLOG"
    if [ "$UPD_RC" -eq 0 ]; then
      rm -f "$FAILMARK"
      printf '%s' "$UPD_OUT" | grep -q 'updated ' && log INFO "YARA: new YARAhub rules fetched ($(printf '%s' "$UPD_OUT" | grep -m1 'rule files usable' | sed 's/^[^:]*: //'))"
    else
      printf '%s' "$UPD_SIG" > "$FAILMARK" 2>/dev/null
      log WARN "YARA: could not update the YARAhub rules (scanning with the rules already built): $(printf '%s' "$UPD_OUT" | grep -v '^[[:space:]]*$' | tail -n1 | cut -c1-200)"
    fi
  fi
fi

# the ruleset: build the bundled one on first use, and again when it went stale
if [ "$YARA_AUTOBUILD" = 1 ] && [ "$YARA_RULES" = "$DEFAULT_RULES" ] && { ! rules_present || rules_stale; }; then
  if command -v "$YARAC_BIN" >/dev/null 2>&1; then
    printf '%bwq: building the YARA ruleset from third_party/ (first run, and after rule or yara updates) ...%b\n' "$GRN" "$NC"
    if SUMMARY="$(build_rules)"; then
      log INFO "YARA: ruleset built ($SUMMARY)"
    else
      log WARN "YARA: building the bundled ruleset failed: $(build_fail_reason) [full output: $(basename "$RAWLOG")]"
      BUILD_FAILED=1
    fi
  else
    cannot_run "yarac is not installed, so the bundled rules cannot be built (Arch: sudo pacman -S yara)"
  fi
fi
if ! rules_present; then
  cannot_run "no ruleset at $YARA_RULES${BUILD_FAILED:+ (the build failed: $(build_fail_reason))}. Run ./wq-yara.sh --build to see why"
fi

# what to scan
TARGETS=("$GAMEDIR/game")
IS_NATIVE=0
[ "$(read_game_conf "$GAMEDIR" RUNNER 2>/dev/null || true)" = "native" ] && IS_NATIVE=1
if [ "$WHEN" != prelaunch ]; then
  if [ "$IS_NATIVE" = 1 ]; then TARGETS+=("$GAMEDIR/home"); else TARGETS+=("$GAMEDIR/prefix"); fi
fi

STAMP="$GAMEDIR/.yara-stamp"; FULLSTAMP="$GAMEDIR/.yara-fullstamp"; HITMARK="$GAMEDIR/.yara-infected"
RULEMARK="$YARA_RULES"; [ -f "$YARA_RULES/rules.yarc" ] && RULEMARK="$YARA_RULES/rules.yarc"
MODE_DESC="full"
if [ "$FULL" -ne 1 ]; then
  if [ ! -f "$STAMP" ] || [ ! -f "$FULLSTAMP" ] || [ -e "$HITMARK" ] || [ "$RULEMARK" -nt "$STAMP" ] \
     || [ -n "$(find "$FULLSTAMP" -mtime +"$YARA_FULL_EVERY_DAYS" 2>/dev/null)" ]; then
    FULL=1
  else
    MODE_DESC="changed since last scan"
  fi
fi

BASELINE="$GAMEDIR/.clam-baseline"   # set by the first-run bootstrap, shared with the ClamAV scan
SKIP_RUNTIME=""; [ -f "$BASELINE" ] && SKIP_RUNTIME=1

LIST="$LOGDIR/.yara-list.$$"
NEWSTAMP="$GAMEDIR/.yara-stamp.new.$$"
STAGED=""
trap 'rm -f "$LIST" "$LIST.f" "$NEWSTAMP"; [ -n "$STAGED" ] && rm -rf "$STAGED"' EXIT
touch "$NEWSTAMP"    # taken before the scan, so files written during it are caught next time

: > "$LIST"
SIZEARGS=(! -size "+${YARA_MAX_FILESIZE_MB}M")
for t in "${TARGETS[@]}"; do
  [ -d "$t" ] || continue
  if [ "$FULL" -eq 1 ]; then
    if [ -n "$SKIP_RUNTIME" ] && [ "$t" = "$GAMEDIR/prefix" ]; then
      find "$t" -xdev -type f "${SIZEARGS[@]}" ! -path $'*\n*' \( ! -path "$t/drive_c/windows/*" -o -cnewer "$BASELINE" \) -print >> "$LIST" 2>/dev/null
      MODE_DESC="full, unchanged Wine runtime skipped"
    else
      find "$t" -xdev -type f "${SIZEARGS[@]}" ! -path $'*\n*' -print >> "$LIST" 2>/dev/null
    fi
  else
    if [ -n "$SKIP_RUNTIME" ] && [ "$t" = "$GAMEDIR/prefix" ]; then
      # same rule as the full scan: after the bootstrap every runtime file is newer than the stamp
      find "$t" -xdev -type f "${SIZEARGS[@]}" -cnewer "$STAMP" ! -path $'*\n*' \( ! -path "$t/drive_c/windows/*" -o -cnewer "$BASELINE" \) -print >> "$LIST" 2>/dev/null
      MODE_DESC="changed since last scan, unchanged Wine runtime skipped"
    else
      find "$t" -xdev -type f "${SIZEARGS[@]}" -cnewer "$STAMP" ! -path $'*\n*' -print >> "$LIST" 2>/dev/null
    fi
  fi
done
# a path with a newline cannot go into the list file. Say so: a game could otherwise hide a file
# from the scan just by naming it that way.
NSKIP=0
for t in "${TARGETS[@]}"; do
  [ -d "$t" ] || continue
  NSKIP=$((NSKIP + $(find "$t" -xdev -type f -path $'*\n*' -printf 'x' 2>/dev/null | wc -c)))
done
[ "$NSKIP" -gt 0 ] && log WARN "YARA: $NSKIP file(s) with a newline in their path cannot be scanned and were skipped. That is not normal for a game."
if [ -n "$YARA_EXCLUDE_REGEX" ]; then
  grep -Ev -- "$YARA_EXCLUDE_REGEX" "$LIST" > "$LIST.f" 2>/dev/null; mv -f "$LIST.f" "$LIST"
fi
NFILES="$(wc -l < "$LIST")"
if [ "$NFILES" -eq 0 ]; then
  log INFO "YARA: nothing new to scan ($MODE_DESC)"
  mv -f "$NEWSTAMP" "$STAMP"
  [ "$FULL" -eq 1 ] && { touch "$FULLSTAMP"; rm -f "$HITMARK"; }
  exit 0
fi
printf '%bYARA: scanning %s file(s) (%s) in %s ...%b\n' "$BOLD" "$NFILES" "$MODE_DESC" "$(wq_clean_text "$GAMENAME")" "$NC"

# the scan, in a no-network firejail when available. The jail must see the game, the list and the
# rules; --private (empty $HOME) is only used when none of them lives under $HOME.
SBX=()
if [ "$YARA_SANDBOX" = 1 ] && command -v firejail >/dev/null 2>&1; then
  # hardened helper jail (lib-firejail.sh): no network or control sockets, home / launcher / other
  # drives read-only, default seccomp, no new namespaces. Nothing needs hiding from the scanner any
  # more (it cannot send what it reads anywhere), so the rules and the game are visible wherever they are.
  if wq_helper_jail --ro "$GAMEDIR"; then
    SBX=("${WQ_HJAIL[@]}")
  else
    log WARN "hardened jail unavailable: yara runs without a sandbox this time (YARA_SANDBOX=0 hides this message)"
  fi
elif [ "$YARA_SANDBOX" = 1 ]; then
  log WARN "firejail not found: yara runs without a sandbox (YARA_SANDBOX=0 hides this message)"
fi

# Rules from outside the project (e.g. YARA_RULES=/tmp/x.yar) are not visible inside the jail: it has
# its own private /tmp, and a rules folder under $HOME may be hidden too. Copy them into the game's
# logs folder, which the jail can always see, and scan that copy. The project's own rules
# ($QROOT, e.g. the bundled _yara-build) are visible as they are and are not copied.
SCANRULES="$YARA_RULES"
if [ "${#SBX[@]}" -gt 0 ]; then
  _rr="$(readlink -f "$YARA_RULES" 2>/dev/null || printf '%s' "$YARA_RULES")"
  case "$_rr/" in
    "$QROOT"/*) ;;
    *)
      STAGED="$LOGDIR/.yara-rules.$$"
      rm -rf "$STAGED"; mkdir -p "$STAGED"
      if [ -d "$_rr" ]; then
        # -L: a symlink in the folder may point somewhere the jail cannot see either
        cp -rL -- "$_rr/." "$STAGED/" 2>/dev/null
      else
        cp -L -- "$_rr" "$STAGED/" 2>/dev/null
      fi
      if [ -d "$_rr" ] && [ -n "$(ls -A "$STAGED" 2>/dev/null)" ]; then
        SCANRULES="$STAGED"
      elif [ -f "$_rr" ] && [ -f "$STAGED/$(basename "$_rr")" ]; then
        SCANRULES="$STAGED/$(basename "$_rr")"
      else
        cannot_run "could not copy the rules from $YARA_RULES into $LOGDIR for the sandboxed scan"
      fi
      ;;
  esac
fi

# compiled ruleset (one pass), else every rule file in the folder, else the single file
RULEARGS=(); YFLAG=()
if [ -d "$SCANRULES" ] && [ -f "$SCANRULES/rules.yarc" ]; then
  RULEARGS=("$SCANRULES/rules.yarc"); YFLAG=(-C)
  log INFO "YARA: compiled ruleset, $(grep -c '^[^#].*: ' "$SCANRULES/SKIPPED.txt" 2>/dev/null || echo 0) rule file(s) left out at build time (see SKIPPED.txt)"
elif [ -d "$SCANRULES" ]; then
  mapfile -t RULEARGS < <(find "$SCANRULES" -type f \( -name '*.yar' -o -name '*.yara' \) | sort)
  YFLAG=(-d filename= -d filepath= -d extension= -d filetype= -d owner=)   # same externals as the build
else
  RULEARGS=("$SCANRULES")
  YFLAG=(-d filename= -d filepath= -d extension= -d filetype= -d owner=)
fi

ERRF="$RAWLOG.stderr"
: > "$RAWLOG"; : > "$ERRF"
HITS=0; FATAL=0; TIMEDOUT=0; SHOWN=0
HITFILES=(); HITRULES=()
# yara-ignore.txt / yara-ignore.local.txt: rule NAMES to leave out of the verdict (one per line, "name  # why").
# The raw yara output still lists them; they just do not count or warn. The local file survives project updates.
declare -A YIGNORE=(); NIGNORED=0
for _il in "$QROOT/yara-ignore.txt" "$QROOT/yara-ignore.local.txt"; do
  [ -f "$_il" ] || continue
  while IFS= read -r _l; do
    _l="${_l%$'\r'}"; _l="${_l%%#*}"; _l="$(printf '%s' "$_l" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -n "$_l" ] && YIGNORE["$_l"]=1
  done < "$_il"
done
for rf in "${RULEARGS[@]}"; do
  RCF="$RAWLOG.rc"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '%s\n' "$line" >> "$RAWLOG"
    rule="${line%% *}"; path="${line#* }"
    if [ -n "${YIGNORE[$rule]+x}" ]; then NIGNORED=$((NIGNORED + 1)); continue; fi
    HITS=$((HITS + 1))
    HITFILES+=("$path"); HITRULES+=("$rule")
    if [ "$YARA_LEVEL" != AUTO ] && [ "$SHOWN" -lt 20 ]; then
      SHOWN=$((SHOWN + 1))
      log "$YARA_LEVEL" "YARA: $rule matched ${path#"$GAMEDIR"/}"
    fi
  done < <(timeout "$YARA_TIMEOUT" "${SBX[@]+"${SBX[@]}"}" "$YARA_BIN" -w -r "${YFLAG[@]+"${YFLAG[@]}"}" --scan-list "$rf" "$LIST" 2>>"$ERRF"; echo "$?" > "$RCF")
  RC="$(cat "$RCF" 2>/dev/null)"; rm -f "$RCF"
  if [ "$RC" = 124 ]; then TIMEDOUT=1
  elif [ "${RC:-0}" != 0 ]; then
    # yara reports a file it could not open as "error scanning <file>": that file is skipped, the scan
    # still counts. Anything else (rules from another yara version, unreadable ruleset) did not scan.
    grep -qvE '^(error scanning |$)' "$ERRF" && FATAL=1
  fi
done
cat "$ERRF" >> "$RAWLOG" 2>/dev/null; rm -f "$ERRF"

if [ "$TIMEDOUT" -eq 1 ]; then
  log WARN "YARA scan did not finish within ${YARA_TIMEOUT}s (YARA_TIMEOUT) [output: $(basename "$RAWLOG")]"
  exit 0   # no stamp update: the same files are tried again next time
elif [ "$FATAL" -eq 1 ]; then
  ERR="$(grep -vE '^(error scanning |$)' "$RAWLOG" | grep -vE '^[A-Za-z0-9_]+ /' | head -n1)"
  # compiled rules from another yara version: rebuild the default set next time
  [ "$YARA_RULES" = "$DEFAULT_RULES" ] && rm -f "$DEFAULT_RULES/.built"
  if [ "$HITS" -eq 0 ]; then cannot_run "yara did not complete: ${ERR:-yara exited with an error} [output: $(basename "$RAWLOG")]"; fi
  log WARN "YARA scan reported errors: ${ERR:-yara exited with an error} [output: $(basename "$RAWLOG")]"
fi

[ "$NIGNORED" -gt 0 ] && log INFO "YARA: $NIGNORED match(es) left out because the rule is listed in yara-ignore*.txt (still in $(basename "$RAWLOG"))"
if [ "$HITS" -gt 0 ] && [ "$YARA_LEVEL" = AUTO ]; then
  declare -A TIER=() SCORE=() DESC=()
  mapfile -t UNIQR < <(printf '%s\n' "${HITRULES[@]}" | sort -u)
  if command -v python3 >/dev/null 2>&1 && [ -f "$QROOT/wq-yara-info.py" ]; then
    while IFS=$'\t' read -r _n _t _s _d; do TIER[$_n]="$_t"; SCORE[$_n]="$_s"; DESC[$_n]="$_d"; done \
      < <(python3 "$QROOT/wq-yara-info.py" "$YARA_RULES" "${UNIQR[@]}" 2>/dev/null)
  fi
  NHIGH=0; NMED=0; NINFO=0; SHOWN=0; INFONAMES=()
  for i in "${!HITRULES[@]}"; do
    _r="${HITRULES[$i]}"; _t="${TIER[$_r]:-MEDIUM}"; _sc="${SCORE[$_r]:--}"; _ds="${DESC[$_r]:--}"
    _detail=""; [ "$_sc" != "-" ] && _detail="score $_sc"
    [ "$_ds" != "-" ] && _detail="${_detail:+$_detail: }$_ds"
    case "$_t" in
      HIGH)   NHIGH=$((NHIGH + 1)); _lv=ALERT ;;
      INFO)   NINFO=$((NINFO + 1)); INFONAMES+=("$_r"); continue ;;
      *)      NMED=$((NMED + 1)); _lv=WARN ;;
    esac
    if [ "$SHOWN" -lt 20 ]; then
      SHOWN=$((SHOWN + 1))
      log "$_lv" "YARA: $([ "$_t" = HIGH ] && echo 'high-risk rule ')$_r${_detail:+ ($_detail)} matched ${HITFILES[$i]#"$GAMEDIR"/}"
    fi
  done
  [ $((NHIGH + NMED)) -gt "$SHOWN" ] && log WARN "YARA: ... and $((NHIGH + NMED - SHOWN)) more match(es), see $RAWLOG"
  if [ "$NINFO" -gt 0 ]; then
    log INFO "YARA: $NINFO informational match(es), no action needed: $(printf '%s\n' "${INFONAMES[@]}" | sort -u | head -n 6 | paste -sd, -)"
  fi
  if [ "$NHIGH" -gt 0 ]; then _lv=ALERT; elif [ "$NMED" -gt 0 ]; then _lv=WARN; else _lv=INFO; fi
  log "$_lv" "YARA: $NFILES file(s) scanned: $NHIGH high-risk, $NMED suspicious, $NINFO informational match(es) in $GAMENAME. Rules fire on suspicious patterns too, so look before you trust or condemn. [output: $(basename "$RAWLOG")]"
  mv -f "$NEWSTAMP" "$STAMP"
  if [ $((NHIGH + NMED)) -gt 0 ]; then
    touch "$HITMARK"   # rescan everything until a full scan comes back clean
  elif [ "$FULL" -eq 1 ]; then
    touch "$FULLSTAMP"; rm -f "$HITMARK"
  fi
  [ "$NHIGH" -gt 0 ] && exit 1
  exit 0
fi

if [ "$HITS" -gt 0 ]; then
  UNIQ="$(printf '%s\n' "${HITFILES[@]}" | sort -u | wc -l)"
  [ "$HITS" -gt "$SHOWN" ] && log "$YARA_LEVEL" "YARA: ... and $((HITS - SHOWN)) more match(es), see $RAWLOG"
  log "$YARA_LEVEL" "YARA: $HITS rule match(es) in $UNIQ of $NFILES scanned file(s) in $GAMENAME. Rules fire on suspicious patterns too, so look before you trust or condemn. [output: $(basename "$RAWLOG")]"
  mv -f "$NEWSTAMP" "$STAMP"
  touch "$HITMARK"   # rescan everything until a full scan comes back clean
  [ "$YARA_LEVEL" = ALERT ] && exit 1
  exit 0
fi

log INFO "YARA: $NFILES file(s) scanned, no matches ($MODE_DESC) [output: $(basename "$RAWLOG")]"
mv -f "$NEWSTAMP" "$STAMP"
[ "$FULL" -eq 1 ] && { touch "$FULLSTAMP"; rm -f "$HITMARK"; }
exit 0
