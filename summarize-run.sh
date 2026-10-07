#!/bin/bash
# summarize-run.sh <GAMEDIR> <ALERTLOG>
GAMEDIR="$1"
ALERTLOG="$2"

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'

ALERTS=$(grep "\[ALERT\]" "$ALERTLOG" 2>/dev/null)
WARNS=$(grep "\[WARN\]" "$ALERTLOG" 2>/dev/null)
RUNTIME_INFO=$(grep "Runtime component installed" "$ALERTLOG" 2>/dev/null)

ALERT_COUNT=$(echo -n "$ALERTS" | grep -c "^" 2>/dev/null || echo 0)
WARN_COUNT=$(echo -n "$WARNS" | grep -c "^" 2>/dev/null || echo 0)
RUNTIME_COUNT=$(echo -n "$RUNTIME_INFO" | grep -c "^" 2>/dev/null || echo 0)
[ -z "$ALERTS" ] && ALERT_COUNT=0
[ -z "$WARNS" ] && WARN_COUNT=0
[ -z "$RUNTIME_INFO" ] && RUNTIME_COUNT=0

# find newest regdiff log for this run, if any
LATEST_REGDIFF=$(ls -t "$GAMEDIR/logs"/regdiff-*.log 2>/dev/null | head -n1)

echo
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD} Quarantine Run Summary: $(basename "$GAMEDIR")${NC}"
echo -e "${BOLD}========================================${NC}"
echo

if [ "$ALERT_COUNT" -eq 0 ] && [ "$WARN_COUNT" -eq 0 ]; then
  echo -e "${GRN}${BOLD}VERDICT: CLEAN${NC} — no suspicious activity detected."
elif [ "$ALERT_COUNT" -eq 0 ]; then
  echo -e "${YEL}${BOLD}VERDICT: OK, minor notes${NC} — no alerts, $WARN_COUNT informational warning(s)."
else
  echo -e "${RED}${BOLD}VERDICT: REVIEW NEEDED${NC} — $ALERT_COUNT alert(s) flagged."
fi
echo

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

echo -e "${BOLD}--- Files ---${NC}"
echo "  Full alert log: $ALERTLOG"
echo
echo -e "${BOLD}========================================${NC}"
echo
