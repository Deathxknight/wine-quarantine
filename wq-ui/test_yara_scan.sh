#!/bin/bash
# Tests wq-yara.sh (the YARA scan before launch and after a run) and its hook in wq-prescan.sh.
# The real yara/yarac are NOT needed: stubs print the output shapes the script reads
# ("rule path" lines; a file containing EVIL matches rule EvilRule).
#   bash wq-ui/test_yara_scan.sh
set -u
unset WQ_PRESCAN WQ_PRESCAN_ALLOW
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
eq()   { [ "$2" = "$3" ] && ok || fail "$1" "expected [$2] got [$3]"; }
has()  { grep -qE -- "$2" <<< "$3" && ok || fail "$1" "no match for /$2/ in: $(head -c 400 <<< "$3")"; }
hasnt(){ grep -qE -- "$2" <<< "$3" && fail "$1" "unexpected match /$2/ in: $(head -c 300 <<< "$3")" || ok; }

Q="$T/q"; mkdir -p "$Q"; . "$(dirname "$(readlink -f "$0")")/test_lib.sh"; wq_copy_src "$SRC" "$Q"

ST="$T/bin"; mkdir -p "$ST"
cat > "$ST/yara" << 'EOS'
#!/bin/bash
[ "${1:-}" = "--version" ] && { echo "4.5.0-stub"; exit 0; }
echo "$*" >> "$(dirname "$0")/yara-args.log"
list="${@: -1}"; rules="${@: -2:1}"
if grep -q BADRULES "$rules" 2>/dev/null; then echo "error: rules were compiled with a different version of YARA" >&2; exit 1; fi
while IFS= read -r f; do
  [ -f "$f" ] || continue
  grep -q EVIL "$f" 2>/dev/null && echo "EvilRule $f"
  case "$f" in *unreadable*) echo "error scanning $f: could not open file" >&2; rcx=1 ;; esac
done < "$list"
exit "${rcx:-0}"
EOS
cat > "$ST/yarac" << 'EOS'
#!/bin/bash
[ "${1:-}" = "-v" ] && { echo "4.5.0-stub"; exit 0; }
out="${@: -1}"; echo "$*" >> "$(dirname "$0")/yarac-args.log"; : > "$out"
EOS
chmod +x "$ST/yara" "$ST/yarac"

RULES="$T/rules"; mkdir -p "$RULES"; echo 'rule EvilRule { condition: true }' > "$RULES/evil.yar"
mkgame() { rm -rf "${Q:?}/$1"; mkdir -p "$Q/$1/game" "$Q/$1/logs" "$Q/$1/prefix"; printf 'EXE=a.exe\n' > "$Q/$1/game.conf"; }
# yy <game> <args...>: run wq-yara.sh with the stub tools on PATH and our rules, ANSI stripped
yy() { local g="$1"; shift
  env PATH="$ST:$PATH" YARA_RULES="$RULES" YARA_SANDBOX=0 "${YENV[@]+"${YENV[@]}"}" "$Q/wq-yara.sh" "$g" "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  return "${PIPESTATUS[0]}"; }
YENV=()

# 1. yara switched on but not installed: before a launch that is an ALERT and exit 3 (the prescan refuses)
mkgame nl; echo hello > "$Q/nl/game/a.exe"
out="$(env PATH="/usr/bin:/bin" YARA_BIN=/nonexistent/yara YARA_RULES="$RULES" "$Q/wq-yara.sh" nl --when prelaunch 2>&1)"; rc=$?
has "no yara: ALERT, cannot run" '\[ALERT\] +YARA scan is switched on but cannot run: .*not installed' "$out"; eq "no yara: exit 3" 3 "$rc"
out="$(env PATH="/usr/bin:/bin" YARA_BIN=/nonexistent/yara YARA_RULES="$RULES" "$Q/wq-yara.sh" nl --when run 2>&1)"; rc=$?
has "no yara after a run: only a warning" 'YARA scan skipped: .*not installed' "$out"; eq "no yara after a run: exit 0" 0 "$rc"
out="$(env PATH="/usr/bin:/bin" YARA_BIN=/nonexistent/yara YARA_SCAN=0 YARA_RULES="$RULES" "$Q/wq-yara.sh" nl --when prelaunch 2>&1)"; rc=$?
eq "no yara but unticked: silent, exit 0" "0:" "$rc:$out"

# 2. clean game
mkgame clean; echo hello > "$Q/clean/game/a.exe"
out="$(yy clean --when prelaunch)"; rc=$?
has "clean: no matches line" 'YARA: 1 file\(s\) scanned, no matches' "$out"; eq "clean: exit" 0 "$rc"
[ -f "$Q/clean/.yara-stamp" ] && ok || fail "clean: stamp written"

# 3. second run: nothing changed, nothing scanned
out="$(yy clean --when prelaunch)"
has "incremental: nothing new" 'nothing new to scan' "$out"

# 4. a match is a WARN by default and does not refuse
mkgame hit; echo EVIL > "$Q/hit/game/a.exe"
out="$(yy hit --when prelaunch)"; rc=$?
has "hit: WARN with rule and relative path" '\[WARN\] +YARA: EvilRule matched game/a.exe' "$out"; eq "hit: WARN level exits 0" 0 "$rc"
[ -e "$Q/hit/.yara-infected" ] && ok || fail "hit: infected marker set"
grep -q 'EvilRule' "$Q/hit/logs/"alerts-*-yara.log 2>/dev/null && ok || fail "hit: written to the alert log"
# the marker forces a full rescan next time, so the match does not vanish after one launch
out="$(yy hit --when prelaunch)"
has "hit: still reported on the next launch" 'EvilRule matched' "$out"

# 5. YARA_LEVEL=ALERT: ALERT line and exit 1
YENV=(YARA_LEVEL=ALERT); out="$(yy hit --when prelaunch)"; rc=$?; YENV=()
has "hit ALERT: ALERT line" '\[ALERT\] +YARA: EvilRule matched' "$out"; eq "hit ALERT: exit 1" 1 "$rc"

# 6. a clean full scan clears the marker
echo hello > "$Q/hit/game/a.exe"
out="$(yy hit --when manual)"; rc=$?
has "cleared: no matches" 'no matches' "$out"; [ -e "$Q/hit/.yara-infected" ] && fail "cleared: marker removed" || ok

# 7. per-game switch (the "YARA scan" checkbox)
mkgame off; echo EVIL > "$Q/off/game/a.exe"; echo 'YARA_SCAN=0' >> "$Q/off/game.conf"
out="$(yy off --when prelaunch)"; rc=$?; eq "YARA_SCAN=0: silent" "" "$out"; eq "YARA_SCAN=0: exit" 0 "$rc"

# 8. after a run: files the run created in prefix/ are scanned too
mkgame run; echo hello > "$Q/run/game/a.exe"; yy run --when prelaunch >/dev/null; sleep 1
echo EVIL > "$Q/run/prefix/dropped.dll"
out="$(yy run --when run)"
has "run: dropped file in prefix/ matched" 'EvilRule matched prefix/dropped.dll' "$out"

# 9. a file yara cannot open is skipped, the scan still counts; rules it cannot load are reported
mkgame unr; echo x > "$Q/unr/game/unreadable.bin"
out="$(yy unr --when prelaunch)"; has "unreadable file: scan still counts" 'no matches' "$out"
echo 'BADRULES' > "$T/badrules.yar"
mkgame bad; echo x > "$Q/bad/game/a.exe"
out="$(env PATH="$ST:$PATH" YARA_RULES="$T/badrules.yar" YARA_SANDBOX=0 "$Q/wq-yara.sh" bad --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
has "bad rules: cannot run" 'cannot run: yara did not complete' "$out"
[ -f "$Q/bad/.yara-stamp" ] && fail "bad rules: stamp must not advance" || ok

# 10. the bundled ruleset is built on first use (stub yarac), and reused afterwards
mkdir -p "$Q/third_party/signature-base-yara" "$Q/third_party/yara-rules"
echo 'rule EvilRule { condition: true }' > "$Q/third_party/signature-base-yara/evil.yar"
mkgame auto; echo EVIL > "$Q/auto/game/a.exe"
out="$(env PATH="$ST:$PATH" YARA_SANDBOX=0 "$Q/wq-yara.sh" auto --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
has "autobuild: announced" 'building the YARA ruleset' "$out"
[ -f "$Q/_yara-build/rules.yarc" ] && [ -f "$Q/_yara-build/.built" ] && ok || fail "autobuild: rules.yarc and .built written"
has "autobuild: scan uses it" 'EvilRule matched' "$out"
grep -q -- '-C' "$ST/yara-args.log" && ok || fail "autobuild: compiled rules loaded with -C"
out="$(env PATH="$ST:$PATH" YARA_SANDBOX=0 "$Q/wq-yara.sh" auto --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
hasnt "autobuild: not rebuilt when current" 'building the YARA ruleset' "$out"
# a changed bundled rule makes the build stale
sleep 1; echo 'rule Other { condition: true }' > "$Q/third_party/yara-rules/other.yar"
out="$(env PATH="$ST:$PATH" YARA_SANDBOX=0 "$Q/wq-yara.sh" auto --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
has "autobuild: rebuilt after the rules changed" 'building the YARA ruleset' "$out"
# without yarac the scan is skipped with a reason
rm -rf "$Q/_yara-build"; mkdir -p "$T/noyarac"; ln -s "$ST/yara" "$T/noyarac/yara"
out="$(env PATH="$T/noyarac:/usr/bin:/bin" YARA_SANDBOX=0 "$Q/wq-yara.sh" auto --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
has "no yarac: skipped with a reason" 'yarac is not installed' "$out"

# a build that cannot work says why, in the log line and in the refusal
rm -rf "$Q/_yara-build"; mv "$Q/third_party" "$Q/third_party.off"; mkgame nb; echo x > "$Q/nb/game/a.exe"
out="$(env PATH="$ST:$PATH" YARA_SANDBOX=0 "$Q/wq-yara.sh" nb --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"; rc=$?
has "build failure: reason shown" 'building the bundled ruleset failed: .*third_party/signature-base-yara is missing' "$out"
has "build failure: refusal names it" 'cannot run: no ruleset .*the build failed: .*third_party' "$out"
mv "$Q/third_party.off" "$Q/third_party"

# a yara that is installed but cannot start (missing shared library) is named as such, not "no matches"
mkdir -p "$T/brokenbin"
printf '#!/bin/bash\necho "yara: error while loading shared libraries: libcrypto.so.4: cannot open shared object file" >&2; exit 127\n' > "$T/brokenbin/yara"
chmod +x "$T/brokenbin/yara"; cp "$ST/yarac" "$T/brokenbin/yarac"
mkgame bk; echo x > "$Q/bk/game/a.exe"
out="$(env PATH="$T/brokenbin:$PATH" YARA_RULES="$RULES" YARA_SANDBOX=0 "$Q/wq-yara.sh" bk --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"; rc=$?
has "broken yara: named" 'yara is installed but does not run: .*libcrypto.so.4' "$out"
rc="$(env PATH="$T/brokenbin:$PATH" YARA_RULES="$RULES" YARA_SANDBOX=0 "$Q/wq-yara.sh" bk --when prelaunch >/dev/null 2>&1; echo $?)"; eq "broken yara: exit 3" 3 "$rc"
printf '#!/bin/bash\necho "yarac: error while loading shared libraries: libcrypto.so.4" >&2; exit 127\n' > "$T/brokenbin/yarac"
cp "$ST/yara" "$T/brokenbin/yara"
out="$(env PATH="$T/brokenbin:$PATH" YARA_RULES="$RULES" YARA_SANDBOX=0 "$Q/wq-yara.sh" bk --when prelaunch 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
has "broken yarac: named" 'yarac is installed but does not run: .*libcrypto.so.4' "$out"

# 11. wq-prescan.sh: YARA_LEVEL=ALERT refuses the launch, WARN does not
pre() { local g="$1"; shift
  env PATH="$ST:$PATH" CLAM_SCAN=0 CLAM_BIN=/nonexistent PRESCAN_CAPA=0 PRESCAN_DIE=0 YARA_RULES="$RULES" YARA_SANDBOX=0 "$@" \
    "$Q/wq-prescan.sh" "$g" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  return "${PIPESTATUS[0]}"; }
mkgame pre; echo EVIL > "$Q/pre/game/a.exe"
out="$(pre pre)"; rc=$?; has "prescan: YARA match logged" 'YARA: EvilRule matched' "$out"; eq "prescan: WARN level goes ahead" 0 "$rc"
mkgame pre2; echo EVIL > "$Q/pre2/game/a.exe"
out="$(pre pre2 YARA_LEVEL=ALERT)"; rc=$?; eq "prescan: ALERT level refuses" 1 "$rc"; has "prescan: reason shown" 'refusing to launch: YARA rule match' "$out"
mkgame pre3; echo EVIL > "$Q/pre3/game/a.exe"; echo YARA_SCAN=0 >> "$Q/pre3/game.conf"
out="$(pre pre3 YARA_LEVEL=ALERT)"; rc=$?; eq "prescan: YARA_SCAN=0 not refused" 0 "$rc"; hasnt "prescan: YARA_SCAN=0 silent" 'YARA' "$out"

# 12. capa switch: CAPA_SCAN=0 reaches wq-prescan.py as PRESCAN_CAPA=0, and a missing capa is said so
cat > "$ST/capa" << 'EOS'
#!/bin/bash
echo "$*" >> "$(dirname "$0")/capa-args.log"; echo '{"rules":{}}'
EOS
chmod +x "$ST/capa"
mkgame cp; printf 'MZ' > "$Q/cp/game/a.exe"; echo CAPA_SCAN=0 >> "$Q/cp/game.conf"; rm -f "$ST/capa-args.log"
env PATH="$ST:$PATH" CLAM_SCAN=0 CLAM_BIN=/nonexistent YARA_SCAN=0 "$Q/wq-prescan.sh" cp >/dev/null 2>&1
[ -f "$ST/capa-args.log" ] && fail "CAPA_SCAN=0: capa must not run" || ok
mkgame cp2; printf 'MZ' > "$Q/cp2/game/a.exe"
out="$(env PATH="/usr/bin:/bin" CLAM_SCAN=0 CLAM_BIN=/nonexistent "$Q/wq-prescan.sh" cp2 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
has "capa missing: ALERT" 'capa scan is switched on but capa is not installed' "$out"
has "capa missing: launch refused" 'refusing to launch: capa scan is switched on' "$out"
out="$(env PATH="/usr/bin:/bin" CLAM_SCAN=0 CLAM_BIN=/nonexistent YARA_SCAN=0 CAPA_SCAN=0 "$Q/wq-prescan.sh" cp2 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
hasnt "capa missing but unticked: not refused" 'capa' "$out"
# yara missing in the prescan: refused
mkgame ym; echo hello > "$Q/ym/game/a.exe"
out="$(env PATH="/usr/bin:/bin" CLAM_SCAN=0 CLAM_BIN=/nonexistent PRESCAN_CAPA=0 "$Q/wq-prescan.sh" ym 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"; rc=$?
has "yara missing: prescan refuses" 'refusing to launch: YARA scan is switched on but cannot run' "$out"

# 13. sandbox + rules outside the project: the jail has a private /tmp, so rules there must be copied
# into the game's logs folder first. The stub firejail hides $FJ_HIDE the way --private-tmp hides /tmp
# and fails like yara does when the rules file cannot be opened.
FJB="$T/fjbin"; mkdir -p "$FJB"; cp "$ST/yara" "$ST/yarac" "$FJB/"
cat > "$FJB/firejail" << 'EOS'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in --*) shift ;; *) break ;; esac; done
for a in "$@"; do case "$a" in "$FJ_HIDE"/*) echo "error: could not open file: $a" >&2; exit 1 ;; esac; done
exec "$@"
EOS
chmod +x "$FJB/firejail"
HID="$T/hidden"; mkdir -p "$HID"
fj() { local g="$1"; shift
  env PATH="$FJB:$PATH" FJ_HIDE="$HID" YARA_SANDBOX=1 "$@" "$Q/wq-yara.sh" "$g" --when manual 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  return "${PIPESTATUS[0]}"; }
mkgame fj1; echo EVIL > "$Q/fj1/game/a.exe"
echo 'rule EvilRule { condition: true }' > "$HID/one.yar"
out="$(fj fj1 YARA_RULES="$HID/one.yar")"; rc=$?
hasnt "sandbox: rules file outside the project is found" 'could not open|skipped' "$out"
has   "sandbox: rules file outside the project matches" 'EvilRule matched' "$out"
eq    "sandbox: exit 0" 0 "$rc"
mkdir -p "$HID/dir"; cp "$HID/one.yar" "$HID/dir/a.yar"
mkgame fj2; echo EVIL > "$Q/fj2/game/a.exe"
out="$(fj fj2 YARA_RULES="$HID/dir")"
has   "sandbox: rules folder outside the project matches" 'EvilRule matched' "$out"
[ -z "$(find "$Q/fj1/logs" "$Q/fj2/logs" -maxdepth 1 -name '.yara-rules.*' 2>/dev/null)" ] && ok || fail "sandbox: staged rules copy is removed afterwards"
# rules inside the project are used where they are (no copy)
mkgame fj3; echo EVIL > "$Q/fj3/game/a.exe"; mkdir -p "$Q/myrules"; cp "$HID/one.yar" "$Q/myrules/a.yar"
out="$(fj fj3 YARA_RULES="$Q/myrules")"
has   "sandbox: rules inside the project still work" 'EvilRule matched' "$out"

# 14. YARA_LEVEL=AUTO sorts matches by severity: HIGH alerts and refuses, MEDIUM warns, INFO is one quiet line
TB="$T/bin2"; mkdir -p "$TB"; cp "$ST/yarac" "$TB/"
cat > "$TB/yara" << 'EOS'
#!/bin/bash
[ "${1:-}" = "--version" ] && { echo "4.5.0-stub"; exit 0; }
list="${@: -1}"; rules="${@: -2:1}"
names=$(grep -ohE '^rule [A-Za-z_]+' "$rules" 2>/dev/null | cut -d' ' -f2)
while IFS= read -r f; do [ -f "$f" ] && grep -q TIERS "$f" 2>/dev/null && for n in $names; do echo "$n $f"; done; done < "$list"; exit 0
EOS
chmod +x "$TB/yara"
TR="$T/tiered"; mkdir -p "$TR"
cat > "$TR/t.yar" << 'EOS'
rule HiRule { meta: score = 80 description = "known bad thing" condition: true }
rule MedRule { meta: score = 50 description = "odd thing" condition: true }
rule LowRule { meta: score = 20 condition: true }
EOS
ty() { local g="$1" rules="$2"; shift 2
  env PATH="$TB:$PATH" YARA_RULES="$rules" YARA_SANDBOX=0 "$@" "$Q/wq-yara.sh" "$g" --when manual 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  return "${PIPESTATUS[0]}"; }
mkgame ti1; echo TIERS > "$Q/ti1/game/a.exe"
out="$(ty ti1 "$TR")"; rc=$?
has "auto: high-risk rule is an ALERT with score and description" '\[ALERT\] +YARA: high-risk rule HiRule \(score 80: known bad thing\) matched game/a.exe' "$out"
has "auto: medium rule is a WARN" '\[WARN\] +YARA: MedRule \(score 50: odd thing\) matched' "$out"
hasnt "auto: low-score rule is not listed as a match" 'LowRule matched' "$out"
has "auto: low-score rule is one informational line" 'informational match\(es\), no action needed: LowRule' "$out"
has "auto: totals line" '1 high-risk, 1 suspicious, 1 informational' "$out"
eq "auto: high-risk match exits 1 (launch refused)" 1 "$rc"
[ -e "$Q/ti1/.yara-infected" ] && ok || fail "auto: a match leaves the rescan marker"

mkdir -p "$T/lowonly"; echo 'rule LowRule { meta: score = 20 condition: true }' > "$T/lowonly/l.yar"
mkgame ti2; echo TIERS > "$Q/ti2/game/a.exe"
out="$(ty ti2 "$T/lowonly")"; rc=$?
eq "auto: informational only exits 0" 0 "$rc"; hasnt "auto: informational only is not a WARN" '\[(WARN|ALERT)\]' "$out"
[ ! -e "$Q/ti2/.yara-infected" ] && [ -f "$Q/ti2/.yara-fullstamp" ] && ok || fail "auto: informational only counts as a clean full scan"

mkdir -p "$T/medonly"; echo 'rule MedRule { meta: score = 50 condition: true }' > "$T/medonly/m.yar"
mkgame ti3; echo TIERS > "$Q/ti3/game/a.exe"
out="$(ty ti3 "$T/medonly")"; rc=$?
eq "auto: medium only exits 0" 0 "$rc"; has "auto: medium only warns" '\[WARN\] +YARA: MedRule' "$out"

mkgame ti4; echo TIERS > "$Q/ti4/game/a.exe"
out="$(ty ti4 "$TR" YARA_BLOCK_SCORE=90)"; rc=$?
eq "auto: YARA_BLOCK_SCORE=90 makes the score-80 rule only a warning" 0 "$rc"

mkgame ti5; echo TIERS > "$Q/ti5/game/a.exe"
out="$(ty ti5 "$TR" YARA_LEVEL=WARN)"; rc=$?
eq "YARA_LEVEL=WARN: old behaviour, exit 0" 0 "$rc"; has "YARA_LEVEL=WARN: every match is a plain WARN" '\[WARN\] +YARA: HiRule matched' "$out"
mkgame ti6; echo TIERS > "$Q/ti6/game/a.exe"
out="$(ty ti6 "$TR" YARA_LEVEL=ALERT)"; rc=$?
eq "YARA_LEVEL=ALERT: old behaviour, exit 1" 1 "$rc"; has "YARA_LEVEL=ALERT: every match is an ALERT" '\[ALERT\] +YARA: LowRule matched' "$out"

# the helper, directly (scores from the rule, folder when there is no score)
h="$(python3 "$Q/wq-yara-info.py" "$TR" HiRule MedRule LowRule Nope)"
has "helper: scored high" 'HiRule	HIGH	80	known bad thing' "$h"; has "helper: scored medium" 'MedRule	MEDIUM	50' "$h"
has "helper: scored low is informational" 'LowRule	INFO	20' "$h"; has "helper: unknown rule is medium" 'Nope	MEDIUM	-	-' "$h"
mkdir -p "$T/fold/rules/malware" "$T/fold/rules/packers" "$T/fold/rules/other"
echo 'rule FamRule { condition: true }' > "$T/fold/rules/malware/f.yar"; echo 'rule PackRule { condition: true }' > "$T/fold/rules/packers/p.yar"
echo 'rule OddRule { condition: true }' > "$T/fold/rules/other/o.yar"
h="$(python3 "$Q/wq-yara-info.py" "$T/fold" FamRule PackRule OddRule)"
has "helper: unscored malware folder is high" 'FamRule	HIGH' "$h"; has "helper: unscored packers folder is informational" 'PackRule	INFO' "$h"; has "helper: unscored elsewhere is medium" 'OddRule	MEDIUM' "$h"

# 15. a big near-random block appended to a program is reported; small or low-entropy ones are not
mkpe_min() { python3 - "$1" <<'PY'
import struct, sys
hdr = b"MZ" + b"\0"*58 + struct.pack("<I", 0x40)
coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 1, 0, 0x200, 0, 0, 0x1000, 0x1000,
                  0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0,
                  0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + b"\0"*(16*8)
sec = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 3, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
open(sys.argv[1], "wb").write((hdr + coff + opt + sec).ljust(0x200, b"\0") + b"\x31\xc0\xc3".ljust(0x200, b"\0"))
PY
}
mkgame bl1; mkpe_min "$Q/bl1/game/a.exe"; head -c 1500000 /dev/urandom >> "$Q/bl1/game/a.exe"
out="$(PRESCAN_CAPA=0 PRESCAN_DIE=0 python3 "$Q/wq-prescan.py" "$Q/bl1" --start a.exe 2>&1)"
has "blob: 1.4 MiB of random data after the last section is reported" 'FINDING	big_blob	2	large block of encrypted or compressed data appended to the program.*a.exe \(1\.4 MiB, entropy 8' "$out"
mkgame bl2; mkpe_min "$Q/bl2/game/a.exe"; head -c 1500000 /dev/zero >> "$Q/bl2/game/a.exe"
out="$(PRESCAN_CAPA=0 PRESCAN_DIE=0 python3 "$Q/wq-prescan.py" "$Q/bl2" --start a.exe 2>&1)"; hasnt "blob: low-entropy overlay is not reported" 'big_blob' "$out"
mkgame bl3; mkpe_min "$Q/bl3/game/a.exe"; head -c 100000 /dev/urandom >> "$Q/bl3/game/a.exe"
out="$(PRESCAN_CAPA=0 PRESCAN_DIE=0 python3 "$Q/wq-prescan.py" "$Q/bl3" --start a.exe 2>&1)"; hasnt "blob: a small random overlay is not reported" 'big_blob' "$out"

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
