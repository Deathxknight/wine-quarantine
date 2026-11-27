#!/usr/bin/env bash
# Tests for lib-runtime.sh: builds an allow-list from a fake Proton tree and classifies writes.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib-runtime.sh
source "$HERE/lib-runtime.sh"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fails=0
ok()   { echo "ok:   $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }
eq()   { [ "$2" = "$3" ] && ok "$1" || fail "$1 (want '$2', got '$3')"; }

P="$T/GE-Proton-test"
mkdir -p "$P/files/lib/wine/i386-windows" "$P/files/lib64/wine" "$P/dist/lib"
printf 'proton ddraw build\n'      > "$P/files/lib/wine/i386-windows/ddraw.dll"
printf 'dxvk d3d11 build\n'        > "$P/files/lib64/wine/d3d11.dll"
printf 'readme, not a binary\n'    > "$P/files/README.txt"          # ignored: not a binary
printf 'dist copy of a helper\n'   > "$P/dist/lib/Helper.EXE"       # upper-case name: matched lower-cased
printf 'a hypothetical runtime\n'  > "$P/dist/lib/wine_extra.sys"

L="$T/allow.txt"
runtime_build_allowlist "$P" "$L"; rc=$?
eq "build exits 0 for a real tree" 0 "$rc"
eq "list has one line per binary (text files and folders skipped)" 4 "$(wc -l < "$L")"
grep -q '  helper.exe$' "$L" && ok "names are lower-cased" || fail "names are lower-cased"
grep -q '  readme.txt$' "$L" && fail "README wrongly listed" || ok "README not listed"

# write-side files, as the prefix would hold them
PFX="$T/prefix/drive_c/windows/syswow64"; mkdir -p "$PFX"
cp "$P/files/lib/wine/i386-windows/ddraw.dll" "$PFX/ddraw.dll"         # same name, same bytes
printf 'edited by someone\n' > "$PFX/d3d11.dll"                          # listed name, other bytes
printf 'payload\n' > "$PFX/evil.dll"                                     # not in Proton at all
cp "$P/files/lib64/wine/d3d11.dll" "$T/d3d11_src"                        # keep a real copy for a deleted-file check

eq "same name and content is MATCH" MATCH "$(runtime_classify "$PFX/ddraw.dll" "$L")"
eq "listed name with other content is MODIFIED" MODIFIED "$(runtime_classify "$PFX/d3d11.dll" "$L")"
eq "name not in Proton is UNKNOWN" UNKNOWN "$(runtime_classify "$PFX/evil.dll" "$L")"
eq "file already gone is UNKNOWN" UNKNOWN "$(runtime_classify "$PFX/gone.dll" "$L")"
eq "no list means NOLIST" NOLIST "$(runtime_classify "$PFX/ddraw.dll" "$T/missing.txt")"

# a bad Proton path must not leave a half-written list behind
rm -f "$T/bad.txt"
runtime_build_allowlist "$T/nope" "$T/bad.txt"; rc=$?
[ "$rc" -ne 0 ] && [ ! -e "$T/bad.txt" ] && ok "missing Proton dir: non-zero, no list" || fail "missing Proton dir handling"

# a Proton folder with no binaries also fails cleanly
mkdir -p "$T/empty/files"
runtime_build_allowlist "$T/empty" "$T/empty.txt"; rc=$?
[ "$rc" -ne 0 ] && [ ! -e "$T/empty.txt" ] && ok "empty Proton dir: non-zero, no list" || fail "empty Proton dir handling"

# names with spaces and regex characters
printf 'x' > "$PFX/my lib+1.dll"
runtime_build_allowlist "$P" "$L"    # rebuild does not see PFX; add the odd name to the list by hand
printf '%s  %s\n' "$(sha256sum "$PFX/my lib+1.dll" | cut -d' ' -f1)" "my lib+1.dll" >> "$L"
eq "name with spaces and '+' is matched literally" MATCH "$(runtime_classify "$PFX/my lib+1.dll" "$L")"

# run score: each kind once, unknown or non-numeric lines ignored
RS="$T/run-score"; : > "$RS"
eq "no run-score file gives 0" "0 " "$(runtime_run_score "$T/none")"
printf 'sys32_unlisted 5\nsys32_unlisted 5\n' > "$RS"
eq "a kind written twice counts once" "5 sys32_unlisted" "$(runtime_run_score "$RS")"
printf 'sys32_unlisted 5\nother 3\nbad x\n' > "$RS"
eq "kinds add up, bad lines skipped" "8 sys32_unlisted,other" "$(runtime_run_score "$RS")"

echo
if [ "$fails" -eq 0 ]; then echo "all runtime tests passed"; else echo "$fails test(s) failed"; exit 1; fi
