#!/bin/bash
# Paths are autodetected where possible. To override anything, create
# config.local.sh next to this file (it is gitignored) or export the
# variable before running.

QROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
[ -f "$QROOT/config.local.sh" ] && . "$QROOT/config.local.sh"

detect_steam_root() {
  local c
  for c in "$HOME/.local/share/Steam" "$HOME/.steam/steam"; do
    [ -d "$c/compatibilitytools.d" ] && { readlink -f "$c"; return 0; }
  done
  return 1
}

detect_umu() {
  local c
  c="$(command -v umu-run 2>/dev/null || true)"
  [ -n "$c" ] && { readlink -f "$c"; return 0; }
  c="$HOME/.local/share/lutris/runtime/umu/umu-run"
  [ -x "$c" ] && { echo "$c"; return 0; }
  return 1
}

UMU_DATA="${UMU_DATA:-$QROOT/_umu-data}"
STEAM_ROOT="${STEAM_ROOT:-$(detect_steam_root || true)}"
LUTRIS_UMU="${LUTRIS_UMU:-$(detect_umu || true)}"

declare -p PROTON_SEARCH_DIRS >/dev/null 2>&1 || PROTON_SEARCH_DIRS=( "$STEAM_ROOT/compatibilitytools.d" )
PROTON_PREFERRED="${PROTON_PREFERRED:-}"

REQUIRED_BINS=(firejail inotifywait python3)
ALERT_TERMINAL="${ALERT_TERMINAL:-}"

POLL_INTERVAL="${POLL_INTERVAL:-5}"
LOG_FLUSH_INTERVAL="${LOG_FLUSH_INTERVAL:-2}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-30}"

# HOME_BLACKLIST is relative to $HOME, BLACKLIST_PATHS takes absolute paths
declare -p HOME_BLACKLIST >/dev/null 2>&1 || HOME_BLACKLIST=()
declare -p BLACKLIST_PATHS >/dev/null 2>&1 || BLACKLIST_PATHS=()

: "${SECCOMP_DROP:=add_key,request_key,keyctl,init_module,finit_module,delete_module,kexec_load,kexec_file_load,reboot,swapon,swapoff,acct,quotactl,open_by_handle_at,perf_event_open,userfaultfd,io_uring_setup,io_uring_enter,io_uring_register}"

declare -p QUARANTINE_FIREJAIL_ARGS >/dev/null 2>&1 || QUARANTINE_FIREJAIL_ARGS=(
  --noprofile
  --net=none
  --private
  --private-tmp
  --nonewprivs
  --caps.drop=all
  --nodbus
  "--seccomp.drop=$SECCOMP_DROP"
)

# what to expose read-only for the umu-run install; system installs
# (/usr, /bin, ...) are already visible inside firejail
UMU_RO_PATH=""
if [ -n "$LUTRIS_UMU" ]; then
  case "$LUTRIS_UMU" in
    /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*) ;;
    */umu/umu-run) UMU_RO_PATH="$(dirname "$(dirname "$LUTRIS_UMU")")" ;;
    *)             UMU_RO_PATH="$LUTRIS_UMU" ;;
  esac
fi

declare -p QUARANTINE_RO_PATHS >/dev/null 2>&1 || QUARANTINE_RO_PATHS=(
  "$UMU_RO_PATH"
  "$STEAM_ROOT"
)

declare -p QUARANTINE_STEAM_CONFIG_PATHS >/dev/null 2>&1 || QUARANTINE_STEAM_CONFIG_PATHS=()

check_deps() {
  local missing=() b
  for b in "${REQUIRED_BINS[@]}"; do
    command -v "$b" >/dev/null 2>&1 || missing+=("$b")
  done
  if [ -z "$LUTRIS_UMU" ]; then
    missing+=("umu-run not found (set LUTRIS_UMU)")
  elif [ ! -x "$LUTRIS_UMU" ]; then
    missing+=("$LUTRIS_UMU  (umu-run, not executable)")
  fi
  if [ -z "$STEAM_ROOT" ]; then
    missing+=("Steam root not found (set STEAM_ROOT)")
  elif [ ! -d "$STEAM_ROOT" ]; then
    missing+=("$STEAM_ROOT  (Steam root, not a directory)")
  fi
  [ -d "$QROOT" ] || missing+=("$QROOT  (quarantine root, not a directory)")
  if [ "${#missing[@]}" -gt 0 ]; then
    {
      echo "ERROR: sandbox dependencies missing or misconfigured:"
      printf '  - %s\n' "${missing[@]}"
      echo
      echo "Set the paths in $QROOT/config.local.sh"
    } >&2
    return 1
  fi
  return 0
}

detect_parent_terminal() {
  local pid=$$ comm
  while [ -n "$pid" ] && [ "$pid" -gt 1 ]; do
    comm="$(cat "/proc/$pid/comm" 2>/dev/null)"
    case "$comm" in
      konsole)          echo konsole;        return 0 ;;
      kitty)            echo kitty;          return 0 ;;
      alacritty)        echo alacritty;      return 0 ;;
      foot)             echo foot;           return 0 ;;
      wezterm*)         echo wezterm;        return 0 ;;
      ghostty)          echo ghostty;        return 0 ;;
      xfce4-terminal)   echo xfce4-terminal; return 0 ;;
      xterm)            echo xterm;          return 0 ;;
    esac
    pid="$(awk '{ sub(/^[^)]*\) /,""); print $2 }' "/proc/$pid/stat" 2>/dev/null)"
  done
  return 1
}

detect_terminal() {
  if [ -n "$ALERT_TERMINAL" ]; then
    command -v "$ALERT_TERMINAL" >/dev/null 2>&1 && { echo "$ALERT_TERMINAL"; return 0; }
  fi
  local pt
  if pt="$(detect_parent_terminal)" && command -v "$pt" >/dev/null 2>&1; then
    echo "$pt"; return 0
  fi
  local t
  for t in kitty alacritty foot wezterm ghostty xterm \
           x-terminal-emulator gnome-terminal konsole xfce4-terminal; do
    command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
  done
  return 1
}

find_proton() {
  local gamedir="${1:-}"
  if [ -n "$gamedir" ] && [ -f "$gamedir/proton.path" ]; then
    local p; p="$(head -n1 "$gamedir/proton.path" | tr -d '[:space:]')"
    if [ -n "$p" ] && [ -f "$p/toolmanifest.vdf" ]; then
      readlink -f "$p"; return 0
    fi
  fi
  if [ -n "$PROTON_PREFERRED" ] && [ -f "$PROTON_PREFERRED/toolmanifest.vdf" ]; then
    readlink -f "$PROTON_PREFERRED"; return 0
  fi
  local d cand
  for d in "${PROTON_SEARCH_DIRS[@]}"; do
    [ -d "$d" ] || continue
    for cand in "$d"/*/toolmanifest.vdf; do
      [ -f "$cand" ] || continue
      readlink -f "$(dirname "$cand")"; return 0
    done
  done
  return 1
}

find_wineserver() {
  local protonpath="$1"
  local c
  for c in "$protonpath/files/bin/wineserver" "$protonpath/dist/bin/wineserver"; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  command -v wineserver 2>/dev/null && return 0
  return 1
}

# game.conf is plain KEY=value lines. It is read as data, never sourced.
read_game_conf() {
  local conf="$1/game.conf" want="$2" k v
  [ -f "$conf" ] || return 1
  while IFS='=' read -r k v || [ -n "$k" ]; do
    if [ "$k" = "$want" ]; then
      printf '%s' "${v%$'\r'}"
      return 0
    fi
  done < "$conf"
  return 1
}

# exe path must be relative to game/ and stay inside it
valid_exe_rel() {
  case "$1" in
    ""|/*|..|../*|*/..|*/../*|*$'\n'*|*$'\r'*) return 1 ;;
  esac
  return 0
}

build_blacklist_args() {
  local h; h="${HOME:?HOME not set}"
  local p full
  for p in "${HOME_BLACKLIST[@]}"; do
    full="$h/$p"
    [ -e "$full" ] || continue
    printf -- '--blacklist=%s\n' "$(readlink -f "$full")"
  done
  for p in "${BLACKLIST_PATHS[@]}"; do
    [ -e "$p" ] || continue
    printf -- '--blacklist=%s\n' "$(readlink -f "$p")"
  done
}

# only game/ and prefix/ are writable. game.conf, logs and the registry
# snapshots stay outside the sandbox.
build_whitelist_args() {
  local gamedir="$1" umudata="$2"
  local qroot; qroot="$(readlink -f "$QROOT")"
  local p f sub

  for sub in game prefix; do
    [ -d "$gamedir/$sub" ] || continue
    printf -- '--whitelist=%s\n' "$(readlink -f "$gamedir/$sub")"
    printf -- '--read-write=%s\n' "$(readlink -f "$gamedir/$sub")"
  done

  if [ -d "$umudata" ]; then
    printf -- '--whitelist=%s\n' "$(readlink -f "$umudata")"
    printf -- '--read-write=%s\n' "$(readlink -f "$umudata")"
  fi

  for f in verify-sandbox.sh verify-sandbox.sha256 _umu-run-wrapper; do
    [ -f "$qroot/$f" ] || continue
    printf -- '--whitelist=%s\n' "$qroot/$f"
    printf -- '--read-only=%s\n' "$qroot/$f"
  done

  for p in "${QUARANTINE_RO_PATHS[@]}"; do
    [ -e "$p" ] || continue
    printf -- '--whitelist=%s\n' "$(readlink -f "$p")"
    printf -- '--read-only=%s\n' "$(readlink -f "$p")"
  done

  for p in "${QUARANTINE_STEAM_CONFIG_PATHS[@]}"; do
    [ -e "$p" ] || continue
    printf -- '--whitelist=%s\n' "$(readlink -f "$p")"
    printf -- '--read-only=%s\n' "$(readlink -f "$p")"
  done
}

# term_run <terminal> <title> <class|""> <cmd> [args...]
# xterm needs -T / -class / -e; everything else keeps the old --title style.
term_run() {
  local term="$1" title="$2" class="$3"; shift 3
  case "$(basename "$term")" in
    xterm|uxterm) "$term" -T "$title" ${class:+-class "$class"} -e "$@" ;;
    konsole)      "$term" -p "tabtitle=$title" -e "$@" ;;
    *)            "$term" --title "$title" ${class:+--class "$class"} "$@" ;;
  esac
}
