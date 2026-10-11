#!/bin/bash

# Usage:
#   ./update-launchers.sh                  dry-run
#   ./update-launchers.sh --apply          write changes
#   ./update-launchers.sh <GameName>       one game, dry-run
#   ./update-launchers.sh --apply <Game>   one game, apply

set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. "$QROOT/config.sh"

TEMPLATE="$QROOT/launcher-template.sh.in"
UMU_DATA="$QROOT/_umu-data"

APPLY=0
TARGET=""
for arg in "$@"; do
  case "$arg" in
    --apply|-a) APPLY=1 ;;
    -*) echo "Unknown flag: $arg" >&2; exit 1 ;;
    *)  TARGET="$arg" ;;
  esac
done

[ -f "$TEMPLATE" ] || { echo "Error: template not found: $TEMPLATE" >&2; exit 1; }

extract_quoted() {
  local file="$1" key="$2"
  grep -m1 -E "^${key}=\"" "$file" 2>/dev/null \
    | sed -E "s/^${key}=\"(.*)\"$/\1/"
}

esc() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }

derive_exe_info() {
  local gamedir="$1"
  local gamedir_full="$gamedir/game"

  [ -d "$gamedir_full" ] || return 1

  local exe
  exe=$(find "$gamedir_full" \
      -type d \( \
        -iname '_Redist' -o \
        -iname '_CommonRedist' -o \
        -iname 'Redist' -o \
        -iname 'DirectX' -o \
        -iname 'dotNetFx*' -o \
        -iname 'oalinst*' \
      \) -prune -o \
      -type f -iname '*.exe' \
        -not -iname 'unins*' \
        -not -iname '*vcredist*' \
        -not -iname 'dxsetup*' \
        -not -iname '*crashhandler*' \
        -not -iname '*crashpad*' \
        -not -iname '*selector*' \
        -not -iname '*setup*' \
        -not -iname '*launcher*' \
        -not -iname '*config*' \
        -not -iname 'oalinst*' \
        -not -iname '*redist*' \
        -print 2>/dev/null | sort | head -1)

  [ -n "$exe" ] || return 1

  printf '%s|./%s' "$(dirname "$exe")" "$(basename "$exe")"
}

first_protonpath() {
  local cand
  for cand in "$STEAM_ROOT"/compatibilitytools.d/*/toolmanifest.vdf; do
    [ -e "$cand" ] || continue
    dirname "$cand"
    return 0
  done
  return 1
}

render() {
  local out="$1" gamename="$2" gamedir="$3" exedir="$4" exename="$5" protonpath="$6"

  sed \
    -e "s|@@GAMENAME@@|$(esc "$gamename")|g" \
    -e "s|@@GAMEDIR@@|$(esc "$gamedir")|g" \
    -e "s|@@EXEDIR@@|$(esc "$exedir")|g" \
    -e "s|@@EXENAME@@|$(esc "$exename")|g" \
    -e "s|@@PROTONPATH@@|$(esc "$protonpath")|g" \
    -e "s|@@UMU_DATA@@|$(esc "$UMU_DATA")|g" \
    -e "s|@@QROOT@@|$(esc "$QROOT")|g" \
    "$TEMPLATE" > "$out"

  grep -qE '@@[A-Za-z0-9_]+@@' "$out" && return 1
  return 0
}

regenerate_one() {
  local gamedir="$1"
  local gamename; gamename="$(basename "$gamedir")"
  local launcher="$gamedir/launch-quarantine.sh"

  # If the launcher already has a working EXE_REL_PATH, keep it. Otherwise
  # derive one - a hand-edit could have picked a different exe than the
  # find filter would.
  local existing_exe existing_dir
  existing_exe="$(extract_quoted "$launcher" EXE_REL_PATH 2>/dev/null || true)"
  existing_dir="$(extract_quoted "$launcher" EXEDIR 2>/dev/null || true)"

  local info exedir exename
  if [ -n "$existing_exe" ] && [ "$existing_exe" != "CHANGE_ME.exe" ] \
     && [ -n "$existing_dir" ] && [ -f "$existing_dir/$existing_exe" ]; then
    exedir="$existing_dir"
    exename="$existing_exe"
  else
    if ! info=$(derive_exe_info "$gamedir"); then
      printf '  %-20s ERROR: no exe found under %s/game\n' "$gamename" "$gamedir"
      return 1
    fi
    exedir="${info%|*}"
    exename="${info#*|}"
  fi

  local protonpath
  protonpath=$(extract_quoted "$launcher" PROTONPATH 2>/dev/null || true)
  if [ -z "$protonpath" ]; then
    protonpath=$(first_protonpath || true)
  fi
  [ -z "$protonpath" ] && protonpath="$STEAM_ROOT/compatibilitytools.d/GE-Proton11-6-x86_64"

  local tmp; tmp=$(mktemp)
  if ! render "$tmp" "$gamename" "$gamedir" "$exedir" "$exename" "$protonpath"; then
    printf '  %-20s ERROR: unsubstituted placeholders\n' "$gamename"
    grep -nE '@@[A-Za-z0-9_]+@@' "$tmp" | sed 's/^/      /'
    rm -f "$tmp"; return 1
  fi

  if [ -f "$launcher" ] && cmp -s "$tmp" "$launcher"; then
    rm -f "$tmp"
    printf '  %-20s up to date (exe=%s)\n' "$gamename" "$exename"
    return 0
  fi

  printf '  %-20s CHANGES:\n' "$gamename"
  [ -f "$launcher" ] && { diff -u "$launcher" "$tmp" | sed 's/^/      /' || true; }
  printf '      exe would be: %s\n' "$exename"

  if [ "$APPLY" -eq 1 ]; then
    cp "$tmp" "$launcher.new"
    mv "$launcher.new" "$launcher"
    chmod +x "$launcher"
    printf '      -> written\n'
  else
    printf '      (dry-run)\n'
  fi
  rm -f "$tmp"
}

echo "Template: $TEMPLATE"
echo "Mode:     $([ "$APPLY" -eq 1 ] && echo APPLY || echo DRY-RUN)"
echo

if [ -n "$TARGET" ]; then
  gamedir="$QROOT/$TARGET"
  [ -d "$gamedir" ] || { echo "Error: no such game: $gamedir" >&2; exit 1; }
  regenerate_one "$gamedir"
else
  n=0
  for d in "$QROOT"/*/; do
    g="${d%/}"
    case "$(basename "$g")" in _umu-cache|_umu-data|_sandbox_probe) continue ;; esac
    [ -d "$g/game" ] || continue
    regenerate_one "$g" || true
    n=$((n+1))
  done
  echo
  echo "Processed $n game(s)."
fi

[ "$APPLY" -eq 0 ] && echo && echo "Dry-run complete. Use --apply to write."
