#!/bin/bash
# Regression test for _umu-run-wrapper's Xephyr virtual-desktop branch. A stand-in umu-run rejects a
# program path that is not a file, as the real one does. The old wrapper passed the bare name
# "explorer" and failed every Windows game launched with Xephyr on.
#   bash wq-ui/test_umu_wrapper.sh
set -u
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }

mkdir -p "$T/prefix/drive_c/windows/system32"; : > "$T/prefix/drive_c/windows/system32/explorer.exe"; : > "$T/game.exe"
cat > "$T/umu.py" <<'PY'
import sys, os
if not os.path.isfile(sys.argv[1]):
    print(f"Error: '{sys.argv[1]}' does not exist", file=sys.stderr); sys.exit(1)
print("UMU RAN:", " ".join(sys.argv[1:]))
print("ENV xalia=%s fixes=%s" % (os.environ.get("PROTON_USE_XALIA"), os.environ.get("PROTONFIXES_DISABLE")))
PY
chmod +x "$T/umu.py"

run() { ( cd "$T" && env WINEPREFIX="$T/prefix" LUTRIS_UMU="$T/umu.py" "$@" bash "$SRC/_umu-run-wrapper" game.exe 2>&1 ); }

out="$(run WQ_XEPHYR_SIZE=800x600)"
[[ "$out" == *"explorer.exe /desktop=wq,800x600 game.exe"* ]] && ok || bad "Xephyr: game not started with virtual desktop" "$out"

out="$(run WQ_XEPHYR_SIZE=800x600 WQ_WINE_DESKTOP=0)"
[[ "$out" == *"UMU RAN: game.exe"* ]] && ok || bad "WQ_WINE_DESKTOP=0 turns the desktop off" "$out"

out="$(run env)"
[[ "$out" == *"UMU RAN: game.exe"* && "$out" != *"virtual desktop"* ]] && ok || bad "Xephyr off: plain launch" "$out"

rm -f "$T/prefix/drive_c/windows/system32/explorer.exe"
out="$(run WQ_XEPHYR_SIZE=800x600)"
[[ "$out" == *"UMU RAN: game.exe"* && "$out" == *"not found in the prefix"* ]] && ok || bad "missing explorer.exe falls back" "$out"

out="$(run env)"
[[ "$out" == *"ENV xalia=0 fixes=1"* ]] && ok || bad "Xalia and ProtonFixes are off by default" "$out"
out="$(run WQ_XALIA=1 WQ_PROTONFIXES=1)"
[[ "$out" == *"ENV xalia=None fixes=None"* ]] && ok || bad "WQ_XALIA=1 / WQ_PROTONFIXES=1 turn them back on" "$out"

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
