#!/bin/bash
# wq-prescan.sh <GameName> [--alertlog FILE]
#
# Runs before the sandbox starts and decides whether the game may launch.
#   1. ClamAV on whatever changed since the last scan (wq-scan.sh does the work)
#   2. ClamAV signature database too old: refuse (PRESCAN_DB_BLOCK_DAYS, default 14)
#   3. wq-prescan.py: packed code, injection imports, disguised programs, nasty shell lines, and (wq_indicators.py)
#      stealer / C2 / ransomware / dropper strings in ASCII and UTF-16, plus odd PE layouts.
#      Each kind of finding has points; the launch is refused at PRESCAN_BLOCK_SCORE (default 5)
#   4. YARA with the bundled rule sets (wq-yara.sh), when yara is installed
#
# Exit: 0 = go ahead (warnings are logged), 1 = launch refused.
#
# Switches (config.local.sh, or game.conf for the per-game ones):
#   PRESCAN=0               game.conf / wq-ui "Pre-launch scan": skip this whole script for the game
#   PRESCAN_ALLOW=1         game.conf or env WQ_PRESCAN_ALLOW=1: log everything but never refuse
#   PRESCAN_BLOCK_SCORE=5   PRESCAN_DB_BLOCK_DAYS=14   PRESCAN_TIME_CAP=60
#   YARA_SCAN=0 / CAPA_SCAN=0   game.conf / wq-ui "YARA scan" and "capa behaviour scan": skip that check for the game
#   YARA_RULES=/path/to/rules.yar-or-dir (default: built from third_party/)   YARA_LEVEL=WARN|ALERT (ALERT refuses the launch)

set -u
[ "${WQ_PRESCAN:-1}" != 0 ] || exit 0   # global off switch (the other test scripts use it)
QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck source=config.sh
source "$QROOT/config.sh" || { echo "wq-prescan: cannot load $QROOT/config.sh" >&2; exit 2; }
# shellcheck source=lib-firejail.sh
source "$QROOT/lib-firejail.sh" || { echo "wq-prescan: cannot load $QROOT/lib-firejail.sh" >&2; exit 2; }

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'

GAMENAME=""; ALERTLOG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --alertlog) ALERTLOG="${2:-}"; shift 2 || { echo "wq-prescan: --alertlog needs a value" >&2; exit 2; } ;;
    -*)         echo "wq-prescan: unknown option $1" >&2; exit 2 ;;
    *)          [ -z "$GAMENAME" ] && GAMENAME="${1%/}" || { echo "wq-prescan: more than one game name" >&2; exit 2; }; shift ;;
  esac
done
case "$GAMENAME" in ""|*/*|.|..) echo "usage: wq-prescan.sh <GameName> [--alertlog FILE]" >&2; exit 2 ;; esac
GAMEDIR="$QROOT/$GAMENAME"
[ -d "$GAMEDIR/game" ] || { echo "wq-prescan: no such game: $GAMENAME" >&2; exit 2; }
GAMEDIR="$(readlink -f "$GAMEDIR")"
LOGDIR="$GAMEDIR/logs"; mkdir -p "$LOGDIR"
[ -n "$ALERTLOG" ] || ALERTLOG="$LOGDIR/alerts-$(date +%Y%m%d-%H%M%S)-prescan.log"

conf_get() {   # game.conf, then profile.defaults.conf (when profile.sh is loaded), then the default
  if declare -F _wq_get >/dev/null 2>&1; then
    _wq_get "$GAMEDIR" "$1" "$2"
  else
    read_game_conf "$GAMEDIR" "$1" 2>/dev/null || printf '%s' "$2"
  fi
}

[ "$(conf_get PRESCAN 1)" != 0 ] || exit 0

log() {
  local level="$1" msg; msg="$(wq_clean_text "$2")"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$ALERTLOG"
  case "$level" in
    ALERT) printf '%b[ALERT] %s%b\n' "$RED" "$msg" "$NC" ;;
    WARN)  printf '%b[WARN]  %s%b\n' "$YEL" "$msg" "$NC" ;;
    INFO)  printf '%b[INFO]  %s%b\n' "$GRN" "$msg" "$NC" ;;
  esac
}

ALLOW=0
if [ "${WQ_PRESCAN_ALLOW:-0}" = 1 ] || [ "$(conf_get PRESCAN_ALLOW 0)" = 1 ]; then ALLOW=1; fi
BLOCK_SCORE="${PRESCAN_BLOCK_SCORE:-5}"
DB_BLOCK_DAYS="${PRESCAN_DB_BLOCK_DAYS:-14}"
REASONS=()

echo "wq: pre-launch scan of $GAMENAME ..."

source "$QROOT/lib-runtime.sh" || { echo "wq-prescan: cannot load $QROOT/lib-runtime.sh" >&2; exit 2; }

# 1. ClamAV (wq-scan.sh respects CLAM_SCAN=0 / CLAM_SCAN_AFTER_RUN=0 and skips itself)
if [ -x "$QROOT/wq-scan.sh" ]; then
  # after a detection the incremental scan would skip the same file next time, so rescan everything
  # until a full scan comes back clean (wq-scan.sh keeps .clam-infected until then)
  FULLARG=(); [ -e "$GAMEDIR/.clam-infected" ] && FULLARG=(--full)
  "$QROOT/wq-scan.sh" "$GAMENAME" --when run "${FULLARG[@]+"${FULLARG[@]}"}" --alertlog "$ALERTLOG"
  [ $? -eq 1 ] && REASONS+=("ClamAV flagged files in the game folder")
fi

# 2. signature database age. Same lookup as wq-scan.sh, so both agree on which database is used.
if [ "${CLAM_USE_DAEMON:-0}" != 1 ] && { [ -n "${CLAM_BIN:-}" ] || command -v clamscan >/dev/null 2>&1; }; then
  # an explicit CLAM_DB_DIR is the only place looked at (same rule as wq-scan.sh)
  if [ -n "${CLAM_DB_DIR:-}" ]; then PDBDIRS=("$CLAM_DB_DIR"); else PDBDIRS=(/var/lib/clamav /var/clamav /usr/local/share/clamav /usr/share/clamav); fi
  for d in "${PDBDIRS[@]}"; do
    [ -n "$d" ] && [ -d "$d" ] && compgen -G "$d/*.c[vl]d" >/dev/null || continue
    newest="$(find "$d" -maxdepth 1 -name '*.c[vl]d' -printf '%T@\n' 2>/dev/null | sort -n | tail -n1)"
    if [ -n "$newest" ]; then
      age=$(( ($(date +%s) - ${newest%.*}) / 86400 ))
      if [ "$age" -gt "$DB_BLOCK_DAYS" ]; then
        log ALERT "ClamAV signatures are $age day(s) old (limit $DB_BLOCK_DAYS). Run: sudo freshclam"
        REASONS+=("virus signatures are $age days old: run 'sudo freshclam' (Arch: sudo systemctl enable --now clamav-freshclam.service)")
      fi
    fi
    break
  done
fi

# capa (behaviour rules, third_party/capa-rules) runs inside wq-prescan.py when the capa program is installed
# Switched on but not installed: the launch is refused (untick "capa behaviour scan" or set CAPA_SCAN=0).
if [ "${CAPA_SCAN:-1}" = 0 ] || [ "$(conf_get CAPA_SCAN 1)" = 0 ]; then
  export PRESCAN_CAPA=0
elif [ "${PRESCAN_CAPA:-auto}" != 0 ]; then
  if [ -n "${PRESCAN_CAPA_BIN:-}" ]; then CAPA_OK=0; [ -x "$PRESCAN_CAPA_BIN" ] && CAPA_OK=1
  else CAPA_OK=0; command -v capa >/dev/null 2>&1 && CAPA_OK=1; fi
  if [ "$CAPA_OK" -eq 0 ]; then
    log ALERT "capa scan is switched on but capa is not installed (Arch: yay -S capa-bin, or pipx install flare-capa). Install it, or untick 'capa behaviour scan' in wq-ui (CAPA_SCAN=0)."
    REASONS+=("capa scan is switched on but capa is not installed (install it, or untick 'capa behaviour scan')")
  fi
fi

# 3. static heuristics
START="${WQ_RUN_EXE:-$(read_game_conf "$GAMEDIR" EXE 2>/dev/null || true)}"   # a one-time setup run is the file to check
if command -v python3 >/dev/null 2>&1 && [ -f "$QROOT/wq-prescan.py" ]; then
  SCORE=0; KINDS=""
  # wq-prescan.py parses files the game controls, and runs capa and Detect It Easy on them. Those are big
  # parsers (vivisect, dnfile, pefile ...): a bug in one is code execution as you, so the whole thing runs in
  # the helper jail (lib-firejail.sh): no network, no sockets, home and launcher read-only. PRESCAN_SANDBOX=0
  # turns that off. If the jail cannot be set up, the external analyzers are switched off instead of running
  # them on the host; the built-in checks still run.
  PSJ=()
  if [ "${PRESCAN_SANDBOX:-1}" = 1 ]; then
    if wq_helper_jail --ro "$GAMEDIR"; then
      PSJ=("${WQ_HJAIL[@]}")
    else
      log WARN "Pre-launch: the hardened jail is unavailable, so the external analyzers are skipped this time (they would parse the game's files on your host)"
      export PRESCAN_CAPA=0 PRESCAN_DIE=0
    fi
  fi
  # The checker's output goes to a file, not straight into the loop: a process substitution hides its exit
  # status, and a checker that crashed or hung used to look exactly like a clean game (no SCORE line = score 0).
  # Now no SCORE line, a non-zero exit or the wall-clock limit below refuses the launch.
  PS_OUT="$(mktemp)"; PS_RC=0; GOT_SCORE=0; PS_ERR=""
  PS_TIMEOUT=()
  command -v timeout >/dev/null 2>&1 && PS_TIMEOUT=(timeout --kill-after=10 "${PRESCAN_HARD_TIMEOUT:-300}")
  PRESCAN_TIME_CAP="${PRESCAN_TIME_CAP:-60}" XDG_CACHE_HOME=/tmp/.wq-cache PYTHONDONTWRITEBYTECODE=1 \
    "${PSJ[@]+"${PSJ[@]}"}" "${PS_TIMEOUT[@]+"${PS_TIMEOUT[@]}"}" python3 "$QROOT/wq-prescan.py" "$GAMEDIR" --start "$START" \
    >"$PS_OUT" 2>/dev/null || PS_RC=$?
  while IFS=$'\t' read -r tag a b c; do
    case "$tag" in
      FINDING) log WARN "Pre-launch: $c (+$b)" ;;
      INFO)    case "$a" in *"NO result"*) log WARN "Pre-launch: $a" ;; *) log INFO "Pre-launch: $a" ;; esac ;;
      SCORE)   SCORE="$a"; KINDS="$b"; GOT_SCORE=1 ;;
      ERROR)   PS_ERR="$a" ;;
    esac
  done < "$PS_OUT"
  rm -f "$PS_OUT"
  if [ "$PS_RC" -ne 0 ] || [ "$GOT_SCORE" -ne 1 ]; then
    case "$PS_RC" in 124|137) PS_WHY="timed out after ${PRESCAN_HARD_TIMEOUT:-300}s" ;; *) PS_WHY="exit $PS_RC${PS_ERR:+, $PS_ERR}" ;; esac
    [ "$GOT_SCORE" -eq 1 ] || PS_WHY="$PS_WHY, no result"
    log ALERT "Pre-launch static checks did not finish ($PS_WHY): the game folder was NOT checked. A damaged or hostile file can cause this."
    REASONS+=("the static checks did not finish ($PS_WHY), so nothing is known about the executables")
  fi
  # points the last run saved (system32 changes it scored with MONITOR_SYS32_SCORE=1), counted once per kind
  read -r RUN_PTS RUN_KINDS < <(runtime_run_score "$GAMEDIR/logs/.run-score")
  if [ "${RUN_PTS:-0}" -gt 0 ] 2>/dev/null; then
    SCORE=$(( ${SCORE:-0} + RUN_PTS ))
    KINDS="${KINDS:+$KINDS,}last run: $RUN_KINDS"
    log WARN "Last run scored +$RUN_PTS ($RUN_KINDS). Review $GAMEDIR/logs/alerts-*.log, then delete logs/.run-score to clear it"
  fi
  if [ "$SCORE" -ge "$BLOCK_SCORE" ] 2>/dev/null; then
    log ALERT "Pre-launch risk score $SCORE (limit $BLOCK_SCORE): $KINDS"
    REASONS+=("risk score $SCORE from: $KINDS")
  elif [ "$SCORE" -gt 0 ] 2>/dev/null; then
    log INFO "Pre-launch risk score $SCORE (launch is refused at $BLOCK_SCORE): $KINDS"
  else
    log INFO "Pre-launch checks: nothing suspicious in the executables"
  fi
else
  log WARN "Pre-launch checks skipped: python3 or wq-prescan.py missing"
fi

# 4. YARA with the bundled rule sets (wq-yara.sh builds the ruleset on first use and does the scan;
#    "YARA scan" in wq-ui / YARA_SCAN=0 in game.conf skips it). High-risk rule matches refuse the launch, medium ones
#    are warnings, informational ones are one INFO line (YARA_LEVEL=AUTO, see wq-yara.sh).
if [ -x "$QROOT/wq-yara.sh" ]; then
  "$QROOT/wq-yara.sh" "$GAMENAME" --when prelaunch --alertlog "$ALERTLOG"
  yrc=$?
  [ "$yrc" -eq 1 ] && REASONS+=("YARA rule match(es) in the game folder")
  [ "$yrc" -eq 3 ] && REASONS+=("YARA scan is switched on but cannot run (see the log; install yara, or untick 'YARA scan')")
fi

# verdict
if [ "${#REASONS[@]}" -eq 0 ]; then
  exit 0
fi
if [ "$ALLOW" = 1 ]; then
  log WARN "Launch would have been refused (${REASONS[*]}) but PRESCAN_ALLOW=1 is set"
  exit 0
fi
for r in "${REASONS[@]}"; do printf '%bwq: refusing to launch: %s%b\n' "$RED" "$(wq_clean_text "$r")" "$NC"; done
log ALERT "Launch refused by the pre-launch scan. To run it anyway: tick off 'Pre-launch scan' in wq-ui, or set PRESCAN_ALLOW=1 in game.conf"
exit 1
