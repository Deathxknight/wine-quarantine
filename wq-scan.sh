#!/bin/bash
# wq-scan.sh <GameName> [--when add|run|manual] [--full] [--alertlog FILE]
# wq-scan.sh --check
#
# ClamAV scan of a quarantined game. What gets scanned:
#     game/                      always
#     prefix/  (Windows games)   the Wine prefix: dropped DLLs, payloads in drive_c, ...
#     home/    (native games)    the game's private home
#
#   --when add      right after a game was added: scans game/ (the prefix does not exist yet)
#   --when run      after a run: only files changed since the last scan (a full scan every
#                   CLAM_FULL_EVERY_DAYS, so new signatures also hit old files)
#   --when manual   (default) full scan of everything
#   --full          force a full scan (only matters with --when run)
#   --alertlog F    append findings to F in the monitor's format, so they show up as
#                   ALERT lines in the run summary and the Monitor tab. Without it a
#                   logs/alerts-<time>-scan.log is written.
#   --baseline      treat everything currently in prefix/ as pristine Wine runtime (full scans then skip
#                   drive_c/windows files that were not changed after this moment), then exit
#   --check         print whether ClamAV and its database are usable, then exit
#
# Exit: 0 clean (or skipped: ClamAV/database missing, disabled), 1 detections, 2 usage error.
# Missing ClamAV never blocks a launch, it is reported and the scan is skipped.
#
# Settings (config.sh / config.local.sh): CLAM_SCAN_ON_ADD CLAM_SCAN_AFTER_RUN CLAM_FULL_EVERY_DAYS
# CLAM_STALE_DAYS CLAM_MAX_FILESIZE CLAM_SANDBOX CLAM_USE_DAEMON CLAM_DB_DIR CLAM_BIN CLAM_EXCLUDE_REGEX.
# Per game, game.conf: CLAM_SCAN=0|1 overrides CLAM_SCAN_AFTER_RUN (and 0 also skips the scan after Add).
# CLAM_SCAN_WINE_RUNTIME=1 also scans the Wine runtime files created by the first-run bootstrap (slow).
#
# clamscan only reads files and never executes them. It still parses untrusted archives and
# documents, so by default it runs inside a firejail with no network (CLAM_SANDBOX=0 to disable).

set -u
QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck source=config.sh
source "$QROOT/config.sh" || { echo "wq-scan: cannot load $QROOT/config.sh" >&2; exit 2; }
# shellcheck source=lib-firejail.sh
source "$QROOT/lib-firejail.sh" || { echo "wq-scan: cannot load $QROOT/lib-firejail.sh" >&2; exit 2; }

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

# conf_get KEY DEFAULT: game.conf, then profile.defaults.conf (when profile.sh is loaded), then DEFAULT
conf_get() {
  if declare -F _wq_get >/dev/null 2>&1; then
    _wq_get "$GAMEDIR" "$1" "$2"
  else
    read_game_conf "$GAMEDIR" "$1" 2>/dev/null || printf '%s' "$2"
  fi
}

# ClamAV discovery
find_db_dir() {
  local d
  # an explicit CLAM_DB_DIR is the only place looked at; system folders are tried only without one
  if [ -n "${CLAM_DB_DIR:-}" ]; then set -- "$CLAM_DB_DIR"; else set -- /var/lib/clamav /var/clamav /usr/local/share/clamav /usr/share/clamav; fi
  for d in "$@"; do
    [ -n "$d" ] && [ -d "$d" ] || continue
    if compgen -G "$d/*.c[vl]d" >/dev/null; then echo "$d"; return 0; fi
  done
  return 1
}

# prints "<binary>" or nothing
find_scanner() {
  if [ -n "$CLAM_BIN" ]; then [ -x "$CLAM_BIN" ] && echo "$CLAM_BIN"; return 0; fi
  if [ "$CLAM_USE_DAEMON" = 1 ]; then command -v clamdscan 2>/dev/null; else command -v clamscan 2>/dev/null; fi
}

db_age_days() {   # newest signature file age in days (integer), empty if unknown
  local d="$1" newest now
  newest="$(find "$d" -maxdepth 1 -name '*.c[vl]d' -printf '%T@\n' 2>/dev/null | sort -n | tail -n1)"
  [ -n "$newest" ] || return 1
  now="$(date +%s)"
  echo $(( (now - ${newest%.*}) / 86400 ))
}

if [ "${1:-}" = "--check" ]; then
  SC="$(find_scanner || true)"
  if [ -z "$SC" ]; then
    echo "ClamAV: $([ "$CLAM_USE_DAEMON" = 1 ] && echo clamdscan || echo clamscan) not found. Install the clamav package."; exit 0
  fi
  echo "ClamAV: $SC ($("$SC" --version 2>/dev/null | head -n1))"
  if [ "$CLAM_USE_DAEMON" = 1 ]; then echo "mode: clamd (CLAM_USE_DAEMON=1), database is clamd's own"; exit 0; fi
  if DB="$(find_db_dir)"; then
    echo "database: $DB ($(db_age_days "$DB" || echo '?') day(s) old)"
  else
    echo "database: none found. Run: sudo freshclam"
  fi
  command -v firejail >/dev/null 2>&1 && echo "sandbox: firejail available (CLAM_SANDBOX=$CLAM_SANDBOX)" || echo "sandbox: firejail missing, clamscan would run unsandboxed"
  exit 0
fi

# arguments
WHEN=manual; FULL=0; ALERTLOG=""; GAMENAME=""; SETBASE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --when)     WHEN="${2:-}"; shift 2 || { echo "wq-scan: --when needs a value" >&2; exit 2; } ;;
    --full)     FULL=1; shift ;;
    --baseline) SETBASE=1; shift ;;
    --alertlog) ALERTLOG="${2:-}"; shift 2 || { echo "wq-scan: --alertlog needs a value" >&2; exit 2; } ;;
    -*)         echo "wq-scan: unknown option $1" >&2; exit 2 ;;
    *)          [ -z "$GAMENAME" ] && GAMENAME="${1%/}" || { echo "wq-scan: more than one game name" >&2; exit 2; }; shift ;;
  esac
done
case "$WHEN" in add|run|manual) ;; *) echo "wq-scan: --when must be add, run or manual" >&2; exit 2 ;; esac
case "$GAMENAME" in
  ""|*/*|.|..) echo "usage: wq-scan.sh <GameName> [--when add|run|manual] [--full] [--alertlog FILE] | --check" >&2; exit 2 ;;
esac
GAMEDIR="$QROOT/$GAMENAME"
[ -d "$GAMEDIR/game" ] || { echo "wq-scan: no such game: $GAMENAME" >&2; exit 2; }
GAMEDIR="$(readlink -f "$GAMEDIR")"
LOGDIR="$GAMEDIR/logs"; mkdir -p "$LOGDIR"

if [ "$SETBASE" -eq 1 ]; then
  touch "$GAMEDIR/.clam-baseline"
  echo "wq-scan: baseline set for $GAMENAME. Full scans now skip the unchanged Wine runtime in prefix/drive_c/windows."
  exit 0
fi

# enabled?
case "$WHEN" in
  add) [ "$CLAM_SCAN_ON_ADD" = 1 ] || exit 0
       [ "$(conf_get CLAM_SCAN '')" != 0 ] || exit 0 ;;
  run)
    PERGAME="$(conf_get CLAM_SCAN '')"
    case "$PERGAME" in
      0) exit 0 ;;
      1) ;;
      *) [ "$CLAM_SCAN_AFTER_RUN" = 1 ] || exit 0 ;;
    esac ;;
esac

# logging
TS_FILE="$(date +%Y%m%d-%H%M%S)"
[ -n "$ALERTLOG" ] || ALERTLOG="$LOGDIR/alerts-$TS_FILE-scan.log"
RAWLOG="$LOGDIR/clamscan-$TS_FILE.log"

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

find "$LOGDIR" -maxdepth 1 -type f -name 'clamscan-*.log' -mtime +"${LOG_RETENTION_DAYS:-30}" -delete 2>/dev/null || true

# is ClamAV usable?
SCANNER="$(find_scanner || true)"
if [ -z "$SCANNER" ]; then
  log WARN "ClamAV scan skipped: $([ "$CLAM_USE_DAEMON" = 1 ] && echo clamdscan || echo clamscan) is not installed (install the clamav package, then run: sudo freshclam)"
  exit 0
fi

DB=""
if [ "$CLAM_USE_DAEMON" != 1 ]; then
  if ! DB="$(find_db_dir)"; then
    log WARN "ClamAV scan skipped: no signature database found. Run: sudo freshclam   (or set CLAM_DB_DIR)"
    exit 0
  fi
  AGE="$(db_age_days "$DB" || true)"
  if [ -n "$AGE" ] && [ "$AGE" -gt "$CLAM_STALE_DAYS" ]; then
    log WARN "ClamAV database is $AGE day(s) old (limit $CLAM_STALE_DAYS). Run: sudo freshclam"
  fi
fi

# what to scan
TARGETS=("$GAMEDIR/game")
if [ "$WHEN" != add ]; then
  if [ "$(read_game_conf "$GAMEDIR" RUNNER 2>/dev/null || true)" = "native" ]; then
    TARGETS+=("$GAMEDIR/home")
  else
    TARGETS+=("$GAMEDIR/prefix")
  fi
fi

STAMP="$GAMEDIR/.clam-stamp"; FULLSTAMP="$GAMEDIR/.clam-fullstamp"
MODE_DESC="full"
if [ "$WHEN" != run ]; then
  FULL=1
elif [ "$FULL" -ne 1 ]; then
  if [ ! -f "$STAMP" ] || [ ! -f "$FULLSTAMP" ] || [ -n "$(find "$FULLSTAMP" -mtime +"$CLAM_FULL_EVERY_DAYS" 2>/dev/null)" ]; then
    FULL=1
  else
    MODE_DESC="changed since last scan"
  fi
fi

BASELINE="$GAMEDIR/.clam-baseline"
SKIP_RUNTIME=""
if [ "${CLAM_SCAN_WINE_RUNTIME:-0}" != 1 ] && [ -f "$BASELINE" ]; then SKIP_RUNTIME=1; fi
IS_NATIVE=0
[ "$(read_game_conf "$GAMEDIR" RUNNER 2>/dev/null || true)" = "native" ] && IS_NATIVE=1

LIST="$LOGDIR/.clam-list.$$"
NEWSTAMP="$GAMEDIR/.clam-stamp.new.$$"
trap 'rm -f "$LIST" "$LIST.f" "$NEWSTAMP"' EXIT
touch "$NEWSTAMP"    # taken before the scan, so files written during it are caught next time

: > "$LIST"
for t in "${TARGETS[@]}"; do
  [ -d "$t" ] || continue
  if [ "$FULL" -eq 1 ]; then
    if [ -n "$SKIP_RUNTIME" ] && [ "$t" = "$GAMEDIR/prefix" ]; then
      # Wine's own runtime from the bootstrap is not scanned; anything newer than the baseline is
      find "$t" -xdev -type f ! -path $'*\n*' \( ! -path "$t/drive_c/windows/*" -o -cnewer "$BASELINE" \) -print >> "$LIST" 2>/dev/null
      MODE_DESC="full, unchanged Wine runtime skipped"
    else
      find "$t" -xdev -type f ! -path $'*\n*' -print >> "$LIST" 2>/dev/null
    fi
  else
    if [ -n "$SKIP_RUNTIME" ] && [ "$t" = "$GAMEDIR/prefix" ]; then
      # Incremental scan: the bootstrap wrote Wine's runtime after the last scan stamp, so without this
      # every file of a fresh prefix counts as "changed". Skip drive_c/windows unless changed after the baseline.
      find "$t" -xdev -type f -cnewer "$STAMP" ! -path $'*\n*' \( ! -path "$t/drive_c/windows/*" -o -cnewer "$BASELINE" \) -print >> "$LIST" 2>/dev/null
      MODE_DESC="changed since last scan, unchanged Wine runtime skipped"
    else
      find "$t" -xdev -type f -cnewer "$STAMP" ! -path $'*\n*' -print >> "$LIST" 2>/dev/null
    fi
  fi
done
# --file-list is one path per line, so a path with a newline in it cannot be passed on. Say so: a
# game could otherwise hide a file from the scan just by naming it that way.
NSKIP=0
for t in "${TARGETS[@]}"; do
  [ -d "$t" ] || continue
  NSKIP=$((NSKIP + $(find "$t" -xdev -type f -path $'*\n*' -printf 'x' 2>/dev/null | wc -c)))
done
if [ "$NSKIP" -gt 0 ]; then
  log WARN "ClamAV: $NSKIP file(s) with a newline in their path cannot be scanned and were skipped. That is not normal for a game."
fi
if [ -n "$CLAM_EXCLUDE_REGEX" ]; then
  grep -Ev -- "$CLAM_EXCLUDE_REGEX" "$LIST" > "$LIST.f" 2>/dev/null; mv -f "$LIST.f" "$LIST"
fi
NFILES="$(wc -l < "$LIST")"

if [ "$NFILES" -eq 0 ]; then
  log INFO "ClamAV: nothing new to scan ($MODE_DESC)"
  mv -f "$NEWSTAMP" "$STAMP"
  exit 0
fi

printf '%bClamAV: scanning %s file(s) (%s) in %s ... this can take a while%b\n' "$BOLD" "$NFILES" "$MODE_DESC" "$(wq_clean_text "$GAMENAME")" "$NC"

# run clamscan
CMD=(); SBX=()
if [ "$CLAM_USE_DAEMON" = 1 ]; then
  CMD=("$SCANNER" --fdpass --infected --file-list="$LIST")
else
  if [ "$CLAM_SANDBOX" = 1 ]; then
    if command -v firejail >/dev/null 2>&1; then
      # hardened helper jail (lib-firejail.sh): no network or control sockets, home / launcher / other
      # drives read-only, default seccomp, no new namespaces. The signature database is read from
      # where it is, so there is no longer a reason to leave the home folder visible.
      if wq_helper_jail --ro "$GAMEDIR"; then
        SBX=("${WQ_HJAIL[@]}")
      else
        log WARN "hardened jail unavailable: clamscan runs without a sandbox this time (CLAM_SANDBOX=0 hides this message)"
      fi
    else
      log WARN "firejail not found: clamscan runs without a sandbox (CLAM_SANDBOX=0 hides this message)"
    fi
  fi
  # CLAM_EXTRA_ARGS: word-split on purpose. Default also reports password-protected archives (they cannot
  # be looked inside) and potentially unwanted programs. Set CLAM_EXTRA_ARGS="" in config.local.sh to turn off.
  # shellcheck disable=SC2206
  XARGS=(${CLAM_EXTRA_ARGS---alert-encrypted-archive=yes --detect-pua=yes})
  CMD=("${SBX[@]+"${SBX[@]}"}" "$SCANNER" --infected --database="$DB" --max-filesize="$CLAM_MAX_FILESIZE" "${XARGS[@]+"${XARGS[@]}"}" --file-list="$LIST")
fi

"${CMD[@]}" > "$RAWLOG" 2>&1
RC=$?

# results
# PUA.* (unwanted programs) and Heuristics.Encrypted.* (cannot be scanned) are worth a line but are not malware verdicts
SOFTRE=': (PUA\.|Heuristics\.Encrypted\.)[^ ]* FOUND$'
mapfile -t FOUND < <(grep ' FOUND$' "$RAWLOG" 2>/dev/null | grep -Ev -- "$SOFTRE")
mapfile -t SOFT < <(grep -E -- "$SOFTRE" "$RAWLOG" 2>/dev/null)
NFOUND="${#FOUND[@]}"
SHOWN=0
for line in "${SOFT[@]+"${SOFT[@]}"}"; do
  [ "$SHOWN" -ge 20 ] && break
  f="${line%: *}"; sig="${line##*: }"; sig="${sig% FOUND}"
  case "$sig" in
    Heuristics.Encrypted.*) log WARN "ClamAV: ${f#"$GAMEDIR"/} is password-protected, its contents were not scanned ($sig)" ;;
    *)                      log WARN "ClamAV: ${f#"$GAMEDIR"/}: $sig (potentially unwanted program)" ;;
  esac
  SHOWN=$((SHOWN + 1))
done
SCANNED="$(sed -n 's/^Scanned files: *//p' "$RAWLOG" | head -n1)"
SCANNED="${SCANNED:-$NFILES}"

if [ "$NFOUND" -gt 0 ]; then
  SHOWN=0
  for line in "${FOUND[@]}"; do
    [ "$SHOWN" -ge 50 ] && break
    f="${line%: *}"; sig="${line##*: }"; sig="${sig% FOUND}"   # the signature name is after the LAST ": "
    log ALERT "ClamAV: ${f#"$GAMEDIR"/}: $sig"
    SHOWN=$((SHOWN + 1))
  done
  [ "$NFOUND" -gt "$SHOWN" ] && log ALERT "ClamAV: ... and $((NFOUND - SHOWN)) more detection(s), see $RAWLOG"
  log ALERT "ClamAV flagged $NFOUND of $SCANNED scanned file(s) in $GAMENAME. Treat this game as hostile unless you know why. [output: $(basename "$RAWLOG")]"
  [ "$RC" -ge 2 ] && log WARN "clamscan also reported errors, see $RAWLOG"
  touch "$GAMEDIR/.clam-infected"   # wq-prescan.sh rescans in full until a clean full scan clears this
  mv -f "$NEWSTAMP" "$STAMP"
  [ "$FULL" -eq 1 ] && [ "$WHEN" != add ] && touch "$FULLSTAMP"   # an add-scan skips prefix/home, so it is not a full baseline
  exit 1
fi

# exit 1 with only PUA / encrypted-archive lines is a finished scan, not a failure
if [ "$RC" -ne 0 ] && { [ "$RC" -ne 1 ] || [ "${#SOFT[@]}" -eq 0 ]; }; then
  ERR="$(grep -iE 'error|cannot|can.t|denied|not found|no supported' "$RAWLOG" | head -n2 | tr '\n' ' ')"
  [ -n "$ERR" ] || ERR="exit code $RC"
  log WARN "ClamAV scan did not complete: $ERR [output: $(basename "$RAWLOG")]"
  [ "$CLAM_SANDBOX" = 1 ] && [ "${#SBX[@]}" -gt 0 ] && log WARN "If firejail is what failed, set CLAM_SANDBOX=0 in config.local.sh"
  exit 0     # no stamp update: the next scan covers these files again
fi

log INFO "ClamAV: $SCANNED file(s) scanned, none flagged ($MODE_DESC) [output: $(basename "$RAWLOG")]"
# an existing prefix that just passed a full scan including the runtime becomes the baseline
if [ "$FULL" -eq 1 ] && [ "$WHEN" != add ] && [ "$IS_NATIVE" -eq 0 ] && [ -z "$SKIP_RUNTIME" ] \
   && [ -d "$GAMEDIR/prefix" ] && [ ! -f "$BASELINE" ]; then
  touch -r "$NEWSTAMP" "$BASELINE"
fi
mv -f "$NEWSTAMP" "$STAMP"
[ "$FULL" -eq 1 ] && rm -f "$GAMEDIR/.clam-infected"
[ "$FULL" -eq 1 ] && [ "$WHEN" != add ] && touch "$FULLSTAMP"   # an add-scan skips prefix/home, so it is not a full baseline
exit 0
