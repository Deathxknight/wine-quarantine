#!/bin/bash
# reg-diff.sh snapshot <GAMEDIR>   -- take a pre-run snapshot
# reg-diff.sh compare <GAMEDIR> <ALERTLOG>  -- diff against snapshot , log results

MODE="$1"
GAMEDIR="$2"
SNAPDIR="$GAMEDIR/.reg-snapshot"
PREFIX="$GAMEDIR/prefix"
REGFILES="system.reg user.reg userdef.reg"

PERSIST_PATHS='Run|RunOnce|RunServices|Image File Execution Options|AppInit_DLLs|Winlogon|Classes\\\\CLSID|Services|Browser Helper Objects|Policies\\\\Explorer\\\\Run|BootExecute'

case "$MODE" in
  snapshot)
    mkdir -p "$SNAPDIR"
    for f in $REGFILES; do
      if [ -f "$PREFIX/$f" ]; then
        cp -f "$PREFIX/$f" "$SNAPDIR/$f.before"
      fi
    done
    exit 0
    ;;

  compare)
    ALERTLOG="$3"
    DIFFLOG="$GAMEDIR/logs/regdiff-$(date +%Y%m%d-%H%M%S).log"
    RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
    log() {
      local level="$1" msg="$2"
      local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
      echo "[$ts] [$level] $msg" >> "$ALERTLOG"
      case "$level" in
        ALERT) echo -e "${RED}[$ts] [ALERT] $msg${NC}" ;;
        WARN)  echo -e "${YEL}[$ts] [WARN]  $msg${NC}" ;;
        INFO)  echo -e "${GRN}[$ts] [INFO]  $msg${NC}" ;;
      esac
    }

    FOUND_ANYTHING=0
    for f in $REGFILES; do
      BEFORE="$SNAPDIR/$f.before"
      AFTER="$PREFIX/$f"
      [ -f "$BEFORE" ] || continue
      [ -f "$AFTER" ] || continue

      DIFF=$(diff "$BEFORE" "$AFTER")
      [ -z "$DIFF" ] && continue

      FOUND_ANYTHING=1
      {
        echo "=== $f ==="
        echo "$DIFF"
        echo
      } >> "$DIFFLOG"

      # Count the diff shape
      ADDED=$(echo "$DIFF"   | grep -c '^> ' || true)
      REMOVED=$(echo "$DIFF" | grep -c '^< ' || true)
      CHANGED=$(echo "$DIFF" | grep -c '^[<>] ' || true)

      # Persistence keys
      PERSIST_HITS=$(echo "$DIFF" \
        | grep -A1 -iE "^> \[.*\\\\($PERSIST_PATHS)" \
        | grep -E '^\> ".*"=')
      if [ -n "$PERSIST_HITS" ]; then
        log ALERT "Persistence key written in $f: $PERSIST_HITS"
        continue
      fi

      # system32
      if echo "$DIFF" | grep -qiE '^< \[.*\\\\(Image File Execution Options|Winlogon|Services|AppInit_DLLs|BootExecute)'; then
        log ALERT "Security-relevant key removed in $f — see $DIFFLOG"
        continue
      fi

      log INFO "Registry changed in $f (+$ADDED / -$REMOVED) — see $DIFFLOG"
    done

    [ "$FOUND_ANYTHING" -eq 0 ] && log INFO "Registry unchanged vs pre-run snapshot"


    for f in $REGFILES; do
      if [ -f "$PREFIX/$f" ]; then
        cp -f "$PREFIX/$f" "$SNAPDIR/$f.before"
      fi
    done
    exit 0
    ;;

  *)
    echo "usage: reg-diff.sh {snapshot|compare} <GAMEDIR> [ALERTLOG]"
    exit 1
    ;;
esac
