#!/bin/bash
# reg-diff.sh snapshot <GAMEDIR>   -- take a pre-run snapshot
# reg-diff.sh compare <GAMEDIR> <ALERTLOG>  -- diff against snapshot , log results

MODE="$1"
GAMEDIR="$2"
SNAPDIR="$GAMEDIR/.reg-snapshot"
PREFIX="$GAMEDIR/prefix"
REGFILES="system.reg user.reg userdef.reg"

# Wine writes a registry as
#   [Software\\Microsoft\\Windows\\CurrentVersion\\Run] 1699999999
#   #time=1da0123456789ab
#   "Name"="C:\\path\\game.exe"
# (key paths have DOUBLED backslashes, and every key header is followed by a #time line, so the
# first value is the second line after the header, not the first). A plain diff cannot say which
# key a changed value line belongs to, so both files are flattened to "key<TAB>value" lines first.
BS='\\\\'    # ERE for two literal backslashes
PERSIST_NAMES='Run|RunOnce|RunServices|RunServicesOnce|Image File Execution Options|AppInit_DLLs|Winlogon|ShellServiceObjectDelayLoad|SharedTaskScheduler|AppCertDlls|SilentProcessExit|KnownDLLs|Browser Helper Objects'
# a key path segment, not a substring: Software\\Foo\\Runtime must not count as ...\\Run
PERSIST_RE="(^|$BS)($PERSIST_NAMES)($BS|\$)"
# value names that hijack loading or startup wherever they sit (empty ones are just Wine's defaults)
PERSIST_VALUE_RE='^"(AppInit_DLLs|Userinit|BootExecute)"='
SERVICE_KEY_RE="${BS}CurrentControlSet${BS}Services${BS}[^\\\\]+\$"
REMOVED_KEY_RE="(^|$BS)(Image File Execution Options|Winlogon|AppInit_DLLs|BootExecute)($BS|\$)|${BS}CurrentControlSet${BS}Services\$"

flatten_reg() {   # K<TAB>key  /  V<TAB>key<TAB>value (continuation lines joined)
  awk '
    function flush() { if (cur != "") { print "V\t" key "\t" cur; cur = "" } }
    /^\[/ { flush(); k = $0; sub(/^\[/, "", k); sub(/\] [0-9]+[ \t\r]*$/, "", k); key = k; print "K\t" key; next }
    /^[ \t]+[^ \t]/ { if (cur != "") { sub(/^[ \t]+/, ""); sub(/\r$/, ""); cur = cur $0 } next }
    /^[#;]/ || /^[ \t\r]*$/ || /^WINE REGISTRY/ { flush(); next }
    { flush(); sub(/\r$/, ""); cur = $0 }
    END { flush() }
  ' "$1"
}

# persist_hits <added-entries-file>: autostart / hijack entries among the newly added ones
persist_hits() {
  RE="$PERSIST_RE" VRE="$PERSIST_VALUE_RE" SRE="$SERVICE_KEY_RE" awk -F'\t' '
    $1 != "V" { next }
    { key = tolower($2); val = tolower($3) }
    key ~ tolower(ENVIRON["RE"])                                   { print $2 "\t" $3; next }
    val ~ tolower(ENVIRON["VRE"]) && val !~ /=""$/                 { print $2 "\t" $3; next }
    key ~ tolower(ENVIRON["SRE"]) && val ~ /^"imagepath"=/ && val !~ /system32/ { print $2 "\t" $3 }
  ' "$1"
}

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

      # Persistence: compare what each key holds, so a value added to a key that already
      # existed is caught too, not only a brand new key
      TMP="$(mktemp -d)"
      flatten_reg "$BEFORE" | sort -u > "$TMP/before"
      flatten_reg "$AFTER"  | sort -u > "$TMP/after"
      comm -13 "$TMP/before" "$TMP/after" > "$TMP/added"
      comm -23 "$TMP/before" "$TMP/after" > "$TMP/removed"
      persist_hits "$TMP/added" > "$TMP/hits"
      NHITS=$(grep -c '' "$TMP/hits")
      if [ "$NHITS" -gt 0 ]; then
        head -n 5 "$TMP/hits" | while IFS=$'\t' read -r hk hv; do
          hk="${hk//[[:cntrl:]]/}"; hv="${hv//[[:cntrl:]]/}"
          log ALERT "Persistence key written in $f: [${hk:0:160}] ${hv:0:160}"
        done
        [ "$NHITS" -gt 5 ] && log WARN "$((NHITS - 5)) more persistence entries in $f - see $DIFFLOG"
        { echo "--- persistence entries in $f ---"; cat "$TMP/hits"; echo; } >> "$DIFFLOG"
        rm -rf "$TMP"
        continue
      fi

      # security-relevant keys that disappeared
      if awk -F'\t' '$1 == "K" { print $2 }' "$TMP/removed" | grep -qiE "$REMOVED_KEY_RE"; then
        rm -rf "$TMP"
        log ALERT "Security-relevant key removed in $f — see $DIFFLOG"
        continue
      fi
      rm -rf "$TMP"

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
