#!/bin/bash
# Tests the optional capa and Detect It Easy checks in wq-prescan.py.
# The real tools are NOT needed: stubs stand in for them and print the output shapes the
# analyzers read (capa: JSON with rules[].meta.namespace; diec: a "Packer:" line).
#   bash wq-ui/test_external_analyzers.sh
set -u
unset WQ_PRESCAN WQ_PRESCAN_ALLOW
export PRESCAN_SANDBOX=0   # these tests are about what the analyzers report; the jail has its own test (test_helper_jail.sh)
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
eq()   { [ "$2" = "$3" ] && ok || fail "$1" "expected [$2] got [$3]"; }
has()  { grep -qE -- "$2" <<< "$3" && ok || fail "$1" "no match for /$2/ in: $(head -c 400 <<< "$3")"; }
hasnt(){ grep -qE -- "$2" <<< "$3" && fail "$1" "unexpected match /$2/" || ok; }

Q="$T/q"; mkdir -p "$Q"; . "$(dirname "$(readlink -f "$0")")/test_lib.sh"; wq_copy_src "$SRC" "$Q"

# PE builder, copied from the prescan tests so the fixtures are identical
sed -n '/^cat > "\$T\/mkpe.py" <<.PY.$/,/^PY$/p' "$(dirname "$(readlink -f "$0")")/test_prescan.sh" | sed '1d;$d' > "$T/mkpe.py"
mkpe() { python3 "$T/mkpe.py" "$@"; }

# fake clamscan (ClamAV is not under test here): always clean
ST="$T/bin"; mkdir -p "$ST"
cat > "$ST/clamscan" << 'EOS'
#!/bin/bash
echo "Scanned files: 0"; exit 0
EOS
chmod +x "$ST/clamscan"
mkdir -p "$T/db"; touch "$T/db/main.cvd"

# fake capa: prints rule namespaces based on the file name; records the arguments it was given
cat > "$ST/capa" << 'EOS'
#!/bin/bash
echo "$*" >> "$(dirname "$0")/capa-args.log"
f="${@: -1}"
case "$(basename "$f")" in
  *crash*)  echo 'ERROR: rule format mismatch in persist.yml' >&2; exit 1 ;;
  *hang*)   (sleep 25) & sleep 25; echo '{"rules":{}}' ;;   # leaves a helper process holding the output pipe
  *slow*)   sleep 5; echo '{"rules":{}}' ;;
  *broken*) echo "not json at all" ;;
  *persist*) echo '{"rules":{"create run key":{"meta":{"namespace":"persistence/registry/create-run-key"}}}}' ;;
  *keylog*)  echo '{"rules":{"log keys":{"meta":{"namespace":"collection/keylog/log-keys"}}}}' ;;
  *c2*)      echo '{"rules":{"beacon":{"meta":{"namespace":"communication/c2/beacon"}}}}' ;;
  *cred*)    echo '{"rules":{"steal browser data":{"meta":{"namespace":"collection/browser/steal"}}}}' ;;
  *inject*)  echo '{"rules":{"inject code":{"meta":{"namespace":"host-interaction/process/inject/x"}}}}' ;;
  *destroy*) echo '{"rules":{"wipe disk":{"meta":{"namespace":"impact/wipe-disk/x"}}}}' ;;
  *)       echo '{"rules":{"read file":{"meta":{"namespace":"host-interaction/file-system/read"}}}}' ;;
esac
EOS
chmod +x "$ST/capa"

# fake diec: reports a packer for names containing upx
cat > "$ST/diec" << 'EOS'
#!/bin/bash
f="${@: -1}"
echo "PE64"
case "$(basename "$f")" in *upx*) echo "    Packer: UPX(3.96)[LZMA]" ;; *) echo "    Compiler: MSVC(2019)" ;; esac
EOS
chmod +x "$ST/diec"

mkgame() { mkdir -p "$Q/$1/game" "$Q/$1/logs"; printf 'EXE=a.exe\n' > "$Q/$1/game.conf"; }
# run the prescan with stub analyzers; $1 = game name, the rest are extra env assignments
pre() {
  local g="$1"; shift
  env YARA_SCAN=0 CLAM_SCAN=0 CLAM_BIN=/nonexistent CLAM_DB_DIR="$T/db" \
      PRESCAN_CAPA_BIN="$ST/capa" PRESCAN_DIE_BIN="$ST/diec" "$@" \
      "$Q/wq-prescan.sh" "$g" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
  return "${PIPESTATUS[0]}"
}

# 1. analyzers off: nothing from them, behaviour unchanged
mkgame off; mkpe "$Q/off/game/persist.exe" .text "kernel32.dll=CreateFileA"
out="$(pre off PRESCAN_CAPA=0 PRESCAN_DIE=0)"; rc=$?
hasnt "off: no capa line" 'capa:' "$out"; eq "off: exit" 0 "$rc"

# 2. capa persistence alone: logged and scored 2, below the block score of 5, so the launch goes ahead
mkgame persist; mkpe "$Q/persist/game/persist.exe" .text "kernel32.dll=CreateFileA"
out="$(pre persist)"; rc=$?
has "persist: logged" 'capa: startup/persistence' "$out"; eq "persist alone: exit" 0 "$rc"

# 3. persistence (2) + keylogging (3) = 5: refused at the default block score
mkgame combo; mkpe "$Q/combo/game/persist.exe" .text "kernel32.dll=CreateFileA"; mkpe "$Q/combo/game/keylog.exe" .text "kernel32.dll=CreateFileA"
out="$(pre combo)"; rc=$?
has "combo: keylog logged" 'capa: keylogging' "$out"; eq "combo: refused" 1 "$rc"

# 4. Detect It Easy packer: informational, 0 points, launch goes ahead
mkgame pk; mkpe "$Q/pk/game/upx_app.exe" UPX0,UPX1 "kernel32.dll=LoadLibraryA"
out="$(pre pk)"; rc=$?
has "pk: DIE reported" 'Detect It Easy: packer' "$out"; eq "pk: DIE alone is not a refusal" 0 "$rc"

# 5. capa output that is not JSON is ignored, not a crash, not evidence
mkgame broken; mkpe "$Q/broken/game/broken.exe" .text "kernel32.dll=CreateFileA"
out="$(pre broken)"; rc=$?
hasnt "broken: no capa finding" 'capa: (startup|keylogging)' "$out"; has "broken: missing capa result is reported" 'capa gave NO result' "$out"; eq "broken: exit" 0 "$rc"

# 6. an analyzer that hangs is cut off by the timeout and gives no finding
mkgame slow; mkpe "$Q/slow/game/slow.exe" .text "kernel32.dll=CreateFileA"
start=$(date +%s); out="$(pre slow PRESCAN_EXTERNAL_TIMEOUT=1)"; rc=$?; took=$(( $(date +%s) - start ))
hasnt "slow: no capa finding" 'capa: (startup|keylogging)' "$out"; has "slow: missing capa result is reported" 'capa gave NO result' "$out"; eq "slow: exit" 0 "$rc"
[ "$took" -lt 4 ] && ok || fail "slow: timeout not honoured" "took ${took}s"

# 6a. capa that crashes: the reason capa gave on stderr is shown instead of thrown away
mkgame crash; mkpe "$Q/crash/game/crash.exe" .text "kernel32.dll=CreateFileA"
out="$(pre crash)"; rc=$?
has "crash: capa's own error text is in the log" 'rule format mismatch' "$out"; eq "crash: exit" 0 "$rc"

# 6a2. extra capa arguments from PRESCAN_CAPA_ARGS reach capa
rm -f "$ST/capa-args.log"; mkgame xargs; mkpe "$Q/xargs/game/a.exe" .text "kernel32.dll=CreateFileA"
pre xargs PRESCAN_CAPA_ARGS="-b pefile" >/dev/null
has "PRESCAN_CAPA_ARGS is passed to capa" '-b pefile' "$(cat "$ST/capa-args.log" 2>/dev/null)"

# 6b. capa that starts a helper process and hangs: the whole process group is killed at the timeout (the old
# subprocess.run() waited for the helper's copy of the pipe, so the check ran into its hard limit instead)
mkgame hang; mkpe "$Q/hang/game/hang.exe" .text "kernel32.dll=CreateFileA"
start=$(date +%s); out="$(pre hang PRESCAN_EXTERNAL_TIMEOUT=2)"; rc=$?; took=$(( $(date +%s) - start ))
has "hang: timeout is named in the capa line" 'ran out of time' "$out"; eq "hang: exit" 0 "$rc"
[ "$took" -lt 12 ] && ok || fail "hang: helper process kept the check waiting" "took ${took}s"

# 6c. the analyzers share one time budget: two hanging files cost the budget, not 2 x the per-file limit
mkgame budget; mkpe "$Q/budget/game/hang1.exe" .text "kernel32.dll=CreateFileA"; mkpe "$Q/budget/game/hang2.exe" .text "kernel32.dll=CreateFileA"
start=$(date +%s); out="$(pre budget PRESCAN_EXTERNAL_TIMEOUT=20 PRESCAN_EXTERNAL_BUDGET=6)"; rc=$?; took=$(( $(date +%s) - start ))
eq "budget: exit" 0 "$rc"; [ "$took" -lt 14 ] && ok || fail "budget: shared budget not honoured" "took ${took}s"

# 6d. files over PRESCAN_CAPA_MAX_MB are not given to capa, and the log says so
rm -f "$ST/capa-args.log"; mkgame big; mkpe "$Q/big/game/persist.exe" .text "kernel32.dll=CreateFileA"
out="$(pre big PRESCAN_CAPA_MAX_MB=0.0001)"; rc=$?
has "big: size limit is reported" 'not given to capa' "$out"; hasnt "big: capa never ran on it" 'capa: startup' "$out"
[ ! -s "$ST/capa-args.log" ] && ok || fail "big: capa was started on an oversize file"

# 8. capa is given a rules folder (capa cannot run without its rules; the bundled copy is the default)
rm -f "$ST/capa-args.log"; mkgame rules; mkpe "$Q/rules/game/a.exe" .text "kernel32.dll=CreateFileA"
# the test copy leaves third_party/ out, so point the override at a folder of its own
mkdir -p "$T/capa-rules"
pre rules PRESCAN_CAPA_RULES="$T/capa-rules" >/dev/null
has "capa gets -r with the rules folder" "-r $T/capa-rules" "$(cat "$ST/capa-args.log" 2>/dev/null)"
# signatures are passed with -s when a folder exists
mkdir -p "$T/capa-sigs"; rm -f "$ST/capa-args.log"
pre rules PRESCAN_CAPA_RULES="$T/capa-rules" PRESCAN_CAPA_SIGS="$T/capa-sigs" >/dev/null
has "capa gets -s with the signatures folder" "-s $T/capa-sigs" "$(cat "$ST/capa-args.log" 2>/dev/null)"

# 7. the per-run file cap: with a cap of 1, only the first file is analysed
mkgame cap; mkpe "$Q/cap/game/a_persist.exe" .text "kernel32.dll=CreateFileA"; mkpe "$Q/cap/game/b_persist.exe" .text "kernel32.dll=CreateFileA"
out="$(pre cap PRESCAN_EXTERNAL_MAX=1)"
n=$(grep -c 'capa: startup' <<< "$out"); eq "cap: only one file analysed" 1 "$n"

# 13. the other capa categories are logged by name; each alone scores below the block score, two together refuse
mkgame c2g; mkpe "$Q/c2g/game/c2.exe" .text "kernel32.dll=CreateFileA"
out="$(pre c2g)"; rc=$?; has "c2: logged" 'capa: command-and-control' "$out"; eq "c2 alone: exit" 0 "$rc"
mkgame crg; mkpe "$Q/crg/game/cred.exe" .text "kernel32.dll=CreateFileA"
out="$(pre crg)"; rc=$?; has "credential theft: logged" 'capa: browser/password/credential theft' "$out"; eq "cred alone (3): exit" 0 "$rc"
mkgame ing; mkpe "$Q/ing/game/inject.exe" .text "kernel32.dll=CreateFileA"
out="$(pre ing)"; rc=$?; has "injection: logged" 'capa: process-injection' "$out"; eq "inject alone: exit" 0 "$rc"
mkgame dsg; mkpe "$Q/dsg/game/destroy.exe" .text "kernel32.dll=CreateFileA"
out="$(pre dsg)"; rc=$?; has "wipe: logged" 'capa: disk-wipe' "$out"; eq "wipe alone (3): exit" 0 "$rc"
mkgame cc2; mkpe "$Q/cc2/game/c2.exe" .text "kernel32.dll=CreateFileA"; mkpe "$Q/cc2/game/cred.exe" .text "kernel32.dll=CreateFileA"
out="$(pre cc2)"; rc=$?; eq "c2 (2) + credential theft (3): refused" 1 "$rc"

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
