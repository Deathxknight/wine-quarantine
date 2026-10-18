#!/bin/bash
# summarize-run.sh <GAMEDIR> <ALERTLOG>
GAMEDIR="$1"
ALERTLOG="$2"
GAME_RC="${3:-0}"   # optional: exit code of the sandboxed process
case "$GAME_RC" in ''|*[!0-9]*) GAME_RC=0 ;; esac

# leaks reported from INSIDE the jail (reachability tests, native preflight).
# these land in the launch log, not the monitor's alert log, so look there too.
LEAKS=""
LAUNCHLOG_LATEST=$(ls -t "$GAMEDIR/logs"/launch-*.log 2>/dev/null | head -n1)
[ -n "$LAUNCHLOG_LATEST" ] && LEAKS=$(grep -E '\[LEAK\]|SANDBOX LEAK' "$LAUNCHLOG_LATEST" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | sort -u)
LEAK_COUNT=0
[ -n "$LEAKS" ] && LEAK_COUNT=$(printf '%s\n' "$LEAKS" | grep -c '^')

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

ALERTS=$(grep "\[ALERT\]" "$ALERTLOG" 2>/dev/null || true)
WARNS=$(grep "\[WARN\]" "$ALERTLOG" 2>/dev/null || true)
RUNTIME_INFO=$(grep "Runtime component installed" "$ALERTLOG" 2>/dev/null || true)

count_lines() { [ -n "$1" ] && printf '%s\n' "$1" | grep -c '^' || echo 0; }
WARN_COUNT=$(count_lines "$WARNS")
RUNTIME_COUNT=$(count_lines "$RUNTIME_INFO")

# One finding is one alert. These ALERT lines only describe another alert (the kill switch firing
# because of one, ClamAV's totals line after its per-file lines), so they are listed but not counted.
ALERT_COUNT=0
if [ -n "$ALERTS" ]; then
  ALERT_COUNT=$(printf '%s\n' "$ALERTS" | grep -Evc 'Kill switch triggered|ClamAV flagged [0-9]+ of|ClamAV: \.\.\. and [0-9]+ more|No terminal emulator found' || true)
  [ "$ALERT_COUNT" -gt 0 ] || ALERT_COUNT=1
fi

# the preflight failed and the game never ran: exit 90/91 (verify-sandbox.sh) or 97 (native), and the
# launch log says so. The marker matters because a game may use those exit codes itself.
BLOCKED=0; BLOCK_WHY=""
if [ -n "$LAUNCHLOG_LATEST" ]; then
  case "$GAME_RC" in
    90|91|97)
      BLOCK_WHY=$(sed 's/\x1b\[[0-9;]*m//g' "$LAUNCHLOG_LATEST" 2>/dev/null | grep -E 'SANDBOX-VERIFY\] FAIL|wq: SANDBOX LEAK' | sort -u)
      grep -qE 'SANDBOX-VERIFY\] (FAIL|ABORT)|wq: aborting launch' "$LAUNCHLOG_LATEST" 2>/dev/null && BLOCKED=1 ;;
  esac
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
CLAM_NOTE=$(grep -E 'ClamAV' "$ALERTLOG" 2>/dev/null | grep -vE '\[ALERT\]' | sed 's/^\[[^]]*\] \[[A-Z]*\] //; s/ \[output: [^]]*\]$//' | tail -n1)

echo
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD} Quarantine Run Summary: $(basename "$GAMEDIR")${NC}"
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
  echo "$ALERTS" | sed 's/^/  /'
  echo
fi

if [ "$WARN_COUNT" -gt 0 ]; then
  echo -e "${YEL}--- Warnings (informational) ---${NC}"
  echo "$WARNS" | sed 's/^/  /'
  echo
fi

if [ "$RUNTIME_COUNT" -gt 0 ]; then
  echo -e "${GRN}--- Runtime setup (Proton/DXVK, expected) ---${NC}"
  echo "  $RUNTIME_COUNT component(s) installed silently — see full log for names"
  echo
fi

if [ -n "$LATEST_REGDIFF" ]; then
  echo -e "${BOLD}--- Registry diff ---${NC}"
  echo "  Full diff: $LATEST_REGDIFF"
  echo
fi

if [ -n "$LATEST_HOMEDIFF" ]; then
  echo -e "${BOLD}--- Home diff ---${NC}"
  echo "  Full diff: $LATEST_HOMEDIFF"
  echo
fi

if [ -n "$CLAM_NOTE" ] || [ -n "$LATEST_CLAM" ]; then
  echo -e "${BOLD}--- ClamAV ---${NC}"
  [ -n "$CLAM_NOTE" ] && echo "  $CLAM_NOTE"
  [ -n "$LATEST_CLAM" ] && echo "  Scanner output: $LATEST_CLAM"
  echo
fi

echo -e "${BOLD}--- Files ---${NC}"
echo "  Full alert log: $ALERTLOG"
echo
echo -e "${BOLD}========================================${NC}"
echo
