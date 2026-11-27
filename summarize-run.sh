#!/bin/bash
# summarize-run.sh <GAMEDIR> <ALERTLOG> [GAME_EXIT_CODE]
[ $# -ge 2 ] && [ -n "$1" ] && [ -n "$2" ] || { echo "usage: summarize-run.sh <GAMEDIR> <ALERTLOG> [GAME_EXIT_CODE]" >&2; exit 2; }
GAMEDIR="$1"
ALERTLOG="$2"
# shellcheck source=lib-clean.sh
. "$(dirname "$(readlink -f "$0")")/lib-clean.sh" || exit 2
GAME_RC="${3:-0}"   # optional: exit code of the sandboxed process
case "$GAME_RC" in ''|*[!0-9]*) GAME_RC=0 ;; esac

# leaks reported from INSIDE the jail (reachability tests, native preflight).
# these land in the launch log, not the monitor's alert log, so look there too.
LEAKS=""
LAUNCHLOG_LATEST=$(ls -t "$GAMEDIR/logs"/launch-*.log 2>/dev/null | head -n1)
[ -n "$LAUNCHLOG_LATEST" ] && LEAKS=$(grep -E '\[LEAK\]|SANDBOX LEAK' "$LAUNCHLOG_LATEST" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | wq_clean_stream | sort -u)
LEAK_COUNT=0
[ -n "$LEAKS" ] && LEAK_COUNT=$(printf '%s\n' "$LEAKS" | grep -c '^')

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

ALERTS=$(grep "\[ALERT\]" "$ALERTLOG" 2>/dev/null | wq_clean_stream || true)
WARNS=$(grep "\[WARN\]" "$ALERTLOG" 2>/dev/null | wq_clean_stream || true)
# monitor.sh writes "N known-runtime component(s) written to system32 (suppressed)" when it ends
RUNTIME_INFO=$(grep "known-runtime component" "$ALERTLOG" 2>/dev/null || true)

count_lines() { if [ -n "$1" ]; then printf '%s\n' "$1" | grep -c '^'; else echo 0; fi; }
WARN_COUNT=$(count_lines "$WARNS")
RUNTIME_COUNT=0
[ -n "$RUNTIME_INFO" ] && RUNTIME_COUNT=$(printf '%s\n' "$RUNTIME_INFO" | sed -n 's/.*\] \([0-9][0-9]*\) known-runtime component.*/\1/p' | awk '{n += $1} END {print n + 0}')

# One finding is one alert. These ALERT lines only describe another alert (the kill switch firing
# because of one, ClamAV's totals line after its per-file lines), so they are listed but not counted.
ALERT_COUNT=0
if [ -n "$ALERTS" ]; then
  ALERT_COUNT=$(printf '%s\n' "$ALERTS" | grep -Evc 'Kill switch triggered|ClamAV flagged [0-9]+ of|ClamAV: \.\.\. and [0-9]+ more|No terminal emulator found' || true)
  [ "$ALERT_COUNT" -gt 0 ] || ALERT_COUNT=1
fi

# The preflight failed and the game never ran. This is decided from the launch log, not from the
# exit code: firejail does not always pass a child's non-zero exit status back, so a launch that
# the verifier aborted was being reported as "game exited with code 0" and a CLEAN verdict.
# The ABORT line is printed by the preflight itself, just before it exits without starting the game.
BLOCKED=0; BLOCK_WHY=""
if [ -n "$LAUNCHLOG_LATEST" ]; then
  # the last alternative is firejail refusing its own command line: the game never ran in a jail
  if sed 's/\x1b\[[0-9;]*m//g' "$LAUNCHLOG_LATEST" 2>/dev/null | grep -qE 'SANDBOX-VERIFY\] ABORT|wq: aborting launch|^Error: .*(mutually exclusive|too many arguments|invalid .*option|unrecognized option)'; then
    BLOCKED=1
    BLOCK_WHY=$(sed 's/\x1b\[[0-9;]*m//g' "$LAUNCHLOG_LATEST" 2>/dev/null | grep -E 'SANDBOX-VERIFY\] FAIL|wq: SANDBOX LEAK|wq: refusing to launch|wq:   |^Error: ' | wq_clean_stream | sort -u)
  fi
fi

# find newest regdiff log for this run, if any
LATEST_REGDIFF=$(ls -t "$GAMEDIR/logs"/regdiff-*.log 2>/dev/null | head -n1)

# home diff and ClamAV name their log in the alert log, so only this run's files are listed
logref() {   # logref <prefix>  -> path of the newest <prefix>-YYYYMMDD-HHMMSS.log named in $ALERTLOG
  local n; n=$(grep -o "$1-[0-9]\{8\}-[0-9]\{6\}\.log" "$ALERTLOG" 2>/dev/null | tail -n1)
  [ -n "$n" ] && [ -f "$GAMEDIR/logs/$n" ] && printf '%s' "$GAMEDIR/logs/$n"
}
LATEST_HOMEDIFF=$(logref homediff)
LATEST_CLAM=$(logref clamscan)
CLAM_NOTE=$(grep -E 'ClamAV' "$ALERTLOG" 2>/dev/null | grep -vE '\[ALERT\]' | sed 's/^\[[^]]*\] \[[A-Z]*\] //; s/ \[output: [^]]*\]$//' | tail -n1 | wq_clean_stream)

echo
echo -e "${BOLD}========================================${NC}"
printf '%b Quarantine Run Summary: %s%b\n' "$BOLD" "$(wq_clean_text "$(basename "$GAMEDIR")")" "$NC"
echo -e "${BOLD}========================================${NC}"
echo

if [ "$LEAK_COUNT" -gt 0 ]; then
  echo -e "${RED}${BOLD}VERDICT: SANDBOX LEAK${NC} — the jail exposed $LEAK_COUNT thing(s) to the game."
elif [ "$BLOCKED" -eq 1 ]; then
  echo -e "${RED}${BOLD}VERDICT: LAUNCH BLOCKED${NC} — a preflight check failed, the game never ran."
elif [ "$ALERT_COUNT" -eq 0 ] && [ "$WARN_COUNT" -eq 0 ]; then
  echo -e "${GRN}${BOLD}VERDICT: CLEAN${NC} — no suspicious activity detected."
elif [ "$ALERT_COUNT" -eq 0 ]; then
  echo -e "${YEL}${BOLD}VERDICT: OK, minor notes${NC} — no alerts, $WARN_COUNT informational warning(s)."
else
  echo -e "${RED}${BOLD}VERDICT: REVIEW NEEDED${NC} — $ALERT_COUNT alert(s) flagged."
fi
echo

if [ "$LEAK_COUNT" -gt 0 ]; then
  echo -e "${RED}--- Sandbox leaks ---${NC}"
  printf '%s\n' "$LEAKS" | sed 's/^/  /'
  echo
fi

if [ "$BLOCKED" -eq 1 ] && [ -n "$BLOCK_WHY" ]; then
  echo -e "${RED}--- Why it was blocked ---${NC}"
  printf '%s\n' "$BLOCK_WHY" | sed 's/^/  /'
  echo
fi

if [ "$ALERT_COUNT" -gt 0 ]; then
  echo -e "${RED}--- Alerts ---${NC}"
  printf '%s\n' "$ALERTS" | sed 's/^/  /'
  echo
fi

if [ "$WARN_COUNT" -gt 0 ]; then
  echo -e "${YEL}--- Warnings (informational) ---${NC}"
  printf '%s\n' "$WARNS" | sed 's/^/  /'
  echo
fi

if [ "$RUNTIME_COUNT" -gt 0 ]; then
  echo -e "${GRN}--- Runtime setup (Proton/DXVK, expected) ---${NC}"
  echo "  $RUNTIME_COUNT known Wine/DXVK component(s) written to system32 (not listed individually)"
  echo
fi

if [ -n "$LATEST_REGDIFF" ]; then
  echo -e "${BOLD}--- Registry diff ---${NC}"
  printf '  Full diff: %s\n' "$(wq_clean_text "$LATEST_REGDIFF")"
  echo
fi

if [ -n "$LATEST_HOMEDIFF" ]; then
  echo -e "${BOLD}--- Home diff ---${NC}"
  printf '  Full diff: %s\n' "$(wq_clean_text "$LATEST_HOMEDIFF")"
  echo
fi

if [ -n "$CLAM_NOTE" ] || [ -n "$LATEST_CLAM" ]; then
  echo -e "${BOLD}--- ClamAV ---${NC}"
  [ -n "$CLAM_NOTE" ] && printf '  %s\n' "$CLAM_NOTE"
  [ -n "$LATEST_CLAM" ] && printf '  Scanner output: %s\n' "$(wq_clean_text "$LATEST_CLAM")"
  echo
fi

# what the YARA, capa and pre-launch heuristics looked at (their ALERT/WARN findings are listed above)
STATIC_NOTES=$(grep -E '\[INFO\] +(YARA:|Pre-launch)' "$ALERTLOG" 2>/dev/null | grep -v 'compiled ruleset' \
  | sed 's/^\[[^]]*\] \[[A-Z]*\] *//; s/ \[output: [^]]*\]$//' | wq_clean_stream | awk '!seen[$0]++' || true)
if [ -n "$STATIC_NOTES" ]; then
  echo -e "${BOLD}--- Static scans (YARA, capa, pre-launch checks) ---${NC}"
  printf '%s\n' "$STATIC_NOTES" | sed 's/^/  /'
  echo
fi

echo -e "${BOLD}--- Files ---${NC}"
printf '  Full alert log: %s\n' "$(wq_clean_text "$ALERTLOG")"
echo
echo -e "${BOLD}========================================${NC}"
echo
