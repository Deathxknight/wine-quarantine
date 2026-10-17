#!/bin/bash
# home-diff.sh snapshot <GAMEDIR>                 -- take a pre-run snapshot
# home-diff.sh compare  <GAMEDIR> <ALERTLOG>      -- diff against it, log the results
#
# The native-game counterpart of reg-diff.sh. A Windows game that wants to persist writes a
# registry key; a Linux one writes a startup file. This snapshots those places in the
# game's effective $HOME (WQ_MONITOR_HOME, default <game>/home) plus the list of executable
# files under game/, and reports what changed. It catches what the live monitor can miss
# (inotify queue overflow, a write racing the jail setup, a rename over an existing file).
#
# Like reg-diff.sh, compare accepts the new state as the next baseline.

MODE="${1:-}"
GAMEDIR="${2:-}"
[ -n "$MODE" ] && [ -n "$GAMEDIR" ] || { echo "usage: home-diff.sh {snapshot|compare} <GAMEDIR> [ALERTLOG]"; exit 1; }
GAMEDIR="$(readlink -f "$GAMEDIR")"
SNAPDIR="$GAMEDIR/.home-snapshot"
HOME_DIR="${WQ_MONITOR_HOME:-$GAMEDIR/home}"
HOME_DIR="${HOME_DIR%/}"

# single files in the home that run code at login/session start
RC_FILES=(.bashrc .bash_profile .bash_login .bash_logout .profile .zshrc .zshenv .zprofile .zlogin
          .xprofile .xinitrc .xsession .xsessionrc .pam_environment .config/fish/config.fish)
# directories where any file is persistence or a PATH/launcher hijack
PERSIST_DIRS=(.config/autostart .config/systemd/user .local/share/systemd/user .config/environment.d
              .local/bin .local/share/applications .ssh)
# the ones that are worth an ALERT (the rest are WARN)
ALERT_PREFIXES=(.config/autostart .config/systemd/user .local/share/systemd/user .config/environment.d .local/bin .ssh)

take() {   # take <outdir>
  local out="$1" f d
  mkdir -p "$out"
  {
    for f in "${RC_FILES[@]}"; do
      [ -f "$HOME_DIR/$f" ] && printf '%s  %s\n' "$(sha256sum "$HOME_DIR/$f" 2>/dev/null | cut -d' ' -f1)" "$f"
    done
    for d in "${PERSIST_DIRS[@]}"; do
      [ -d "$HOME_DIR/$d" ] || continue
      find "$HOME_DIR/$d" -type f -print0 2>/dev/null | sort -z | while IFS= read -r -d '' f; do
        printf '%s  %s\n' "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" "${f#"$HOME_DIR"/}"
      done
    done
  } > "$out/home.sums"
  # every file under game/ with an exec bit, or an ELF-ish name; path only, so a game updating
  # an existing binary is not noise but a newly appearing one is
  if [ -d "$GAMEDIR/game" ]; then
    find "$GAMEDIR/game" -type f \( -perm /111 -o -iname '*.so' -o -iname '*.so.*' \) -printf '%P\n' 2>/dev/null | LC_ALL=C sort > "$out/game-exec.list"
  else
    : > "$out/game-exec.list"
  fi
}

case "$MODE" in
  snapshot)
    take "$SNAPDIR"
    exit 0
    ;;

  compare)
    ALERTLOG="${3:?usage: home-diff.sh compare <GAMEDIR> <ALERTLOG>}"
    DIFFLOG="$GAMEDIR/logs/homediff-$(date +%Y%m%d-%H%M%S).log"
    mkdir -p "$GAMEDIR/logs"
    find "$GAMEDIR/logs" -maxdepth 1 -type f -name 'homediff-*.log' -mtime +"${LOG_RETENTION_DAYS:-30}" -delete 2>/dev/null || true
    RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
    NOTE=""
    [ "${WQ_MONITOR_PRIVATE:-1}" = 1 ] || NOTE=" (home is NOT hidden: this may be another program, not the game)"
    log() {
      local level="$1" msg="${2//[[:cntrl:]]/}" ts
      ts=$(date '+%Y-%m-%d %H:%M:%S')
      echo "[$ts] [$level] $msg" >> "$ALERTLOG"
      case "$level" in
        ALERT) echo -e "${RED}[$ts] [ALERT] $msg${NC}" ;;
        WARN)  echo -e "${YEL}[$ts] [WARN]  $msg${NC}" ;;
        INFO)  echo -e "${GRN}[$ts] [INFO]  $msg${NC}" ;;
      esac
    }

    if [ ! -f "$SNAPDIR/home.sums" ]; then
      log INFO "Home diff: no pre-run snapshot, nothing to compare"
      take "$SNAPDIR"
      exit 0
    fi

    NOW="$(mktemp -d)"; trap 'rm -rf "$NOW"' EXIT
    take "$NOW"

    is_alert_path() { local p; for p in "${ALERT_PREFIXES[@]}"; do case "$1" in "$p"/*) return 0 ;; esac; done; return 1; }

    # name -> hash maps
    declare -A BEFORE AFTER
    while read -r h name; do [ -n "$name" ] && BEFORE[$name]="$h"; done < "$SNAPDIR/home.sums"
    while read -r h name; do [ -n "$name" ] && AFTER[$name]="$h";  done < "$NOW/home.sums"

    FOUND=0
    for name in "${!AFTER[@]}"; do
      if [ -z "${BEFORE[$name]:-}" ]; then kind="created"
      elif [ "${BEFORE[$name]}" != "${AFTER[$name]}" ]; then kind="modified"
      else continue; fi
      # firejail copies the skeleton .zshrc/.bashrc into a private home when the jail starts, or
      # creates an empty one. That is the sandbox, not the game.
      if [ "$kind" = created ] && [[ "$name" != */* ]] && [ -f "$HOME_DIR/$name" ] && \
         { [ ! -s "$HOME_DIR/$name" ] || { [ -f "/etc/skel/$name" ] && cmp -s "$HOME_DIR/$name" "/etc/skel/$name"; }; }; then
        log INFO "Home diff: ~/$name appeared but is empty or the stock skeleton file (firejail does this), ignored"
        continue
      fi
      FOUND=1
      echo "$kind  ~/$name" >> "$DIFFLOG"
      case "$name" in
        .config/*|.local/*|.ssh/*) if is_alert_path "$name"; then lvl=ALERT; else lvl=WARN; fi ;;
        *) lvl=ALERT ;;     # one of RC_FILES
      esac
      log "$lvl" "Home diff: $kind ~/$name$NOTE"
    done
    for name in "${!BEFORE[@]}"; do
      [ -n "${AFTER[$name]:-}" ] && continue
      FOUND=1
      echo "removed  ~/$name" >> "$DIFFLOG"
      log WARN "Home diff: removed ~/$name"
    done

    # new executables / libraries under game/
    NEWEXEC="$(LC_ALL=C comm -13 "$SNAPDIR/game-exec.list" "$NOW/game-exec.list")"
    if [ -n "$NEWEXEC" ]; then
      FOUND=1
      N=$(printf '%s\n' "$NEWEXEC" | grep -c '^')
      { echo "new executables under game/:"; printf '%s\n' "$NEWEXEC" | sed 's/^/  /'; } >> "$DIFFLOG"
      log WARN "Home diff: $N new executable/library file(s) under game/ (first: $(printf '%s\n' "$NEWEXEC" | head -n1)) - see $DIFFLOG"
    fi

    [ "$FOUND" -eq 0 ] && log INFO "Home unchanged vs pre-run snapshot (startup files, autostart, units, ~/.local/bin, ~/.ssh)"
    [ -f "$DIFFLOG" ] && log INFO "Home diff: details in $(basename "$DIFFLOG")"

    # accept the new state as the next baseline (same behaviour as reg-diff.sh)
    rm -rf "$SNAPDIR"; mkdir -p "$SNAPDIR"; cp -a "$NOW"/. "$SNAPDIR"/
    exit 0
    ;;

  *)
    echo "usage: home-diff.sh {snapshot|compare} <GAMEDIR> [ALERTLOG]"
    exit 1
    ;;
esac
