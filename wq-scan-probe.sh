#!/bin/bash
# wq-scan-probe.sh: quick check that YARA and capa really work on this machine, the way wq uses them.
#   ./wq-scan-probe.sh          takes about a minute, changes nothing outside a throwaway _scanprobe-* folder
#   ./wq-scan-probe.sh --pe FILE.exe   also lists what capa recognises in a real Windows program
#   ./wq-scan-probe.sh --keep   keeps that folder (as _scanprobe) so you can scan it yourself, e.g.
#                               ./wq-yara.sh _scanprobe --full    ./wq-scan.sh _scanprobe --when manual
# One command, about a minute. It builds a throwaway game with: an EICAR bait file, a tiny clean PE, a PE with
# 1.5 MiB of random data appended, then runs what a launch would run (YARA, capa, the pre-launch scan, the
# run summary) and checks each result. ClamAV is left out here: its own scan is tested by the launch itself.
# YARA: bundled ruleset in the firejail (expect "no matches"), then a rules file in /tmp (expect a match).
# capa: runs it on a tiny test PE with the same options as wq-prescan.py and checks it returns JSON.
set -u
QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"; export QROOT
source "$QROOT/config.sh" || { echo "cannot load config.sh" >&2; exit 2; }
KEEP=0; PE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --pe)   shift; PE="${1:-}"; [ -f "$PE" ] || { echo "--pe needs an existing file" >&2; exit 2; } ;;
    *)      echo "usage: wq-scan-probe.sh [--keep] [--pe FILE.exe]" >&2; exit 2 ;;
  esac
  shift
done
NAME="_scanprobe-$$"; [ "$KEEP" = 1 ] && NAME="_scanprobe"
G="$QROOT/$NAME"; T="$(mktemp -d)"
[ "$KEEP" = 1 ] && rm -rf "$G"
trap 'rm -rf "$T"; [ "$KEEP" = 1 ] || rm -rf "$G"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $*"; }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

mkdir -p "$G/game" "$G/logs" "$G/prefix"; printf 'EXE=a.exe\n' > "$G/game.conf"
echo "WQPROBECANARY" > "$G/game/canary.txt"
# bait for the bundled YARA rules: the standard EICAR test string (harmless; rule SUSP_Just_EICAR needs it
# exactly, at offset 0, in a file under 70 bytes). ClamAV flags it too, which is what a test file is for.
# written in pieces so this script is not itself an EICAR file (YARA's eicar rule flagged it when it sat in a game folder)
e1='X5O!P%@AP[4\PZX54(P^)7CC)7}$EI'; e2='CAR-STANDARD-ANTI'; e3='VIRUS-TEST-FILE!$H+H*'
printf '%s%s%s' "$e1" "$e2" "$e3" > "$G/game/eicar-bait.txt"
python3 - "$G/game/a.exe" <<'PY'
import struct, sys
hdr = b"MZ" + b"\0"*58 + struct.pack("<I", 0x40)                         # DOS header, e_lfanew=0x40
coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 1, 0, 0x200, 0, 0, 0x1000, 0x1000,
                  0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 3, 0,
                  0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + b"\0"*(16*8)
sec = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 3, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
img = (hdr + coff + opt + sec).ljust(0x200, b"\0") + (b"\x31\xc0\xc3").ljust(0x200, b"\0")
open(sys.argv[1], "wb").write(img)
PY

# a PE with a big near-random block appended (what a hidden/encrypted payload looks like)
cp "$G/game/a.exe" "$G/game/blob.exe"; head -c 1500000 /dev/urandom >> "$G/game/blob.exe"

echo "== YARA"
if ! command -v "${YARA_BIN:-yara}" >/dev/null 2>&1; then bad "yara is not installed"
else
  "$QROOT/wq-yara.sh" --check 2>&1 | strip | sed 's/^/  info  /'
  out="$("$QROOT/wq-yara.sh" "$NAME" --when manual --alertlog "$T/a1.log" 2>&1 | strip)"
  # the bundled rules include informational file-type rules (IsPE64, IsConsole ...) that match the test PE:
  # a match is fine. What counts is that the scan finished, not that it was silent.
  if grep -qE 'skipped|did not complete|cannot run|did not finish|reported errors' <<< "$out" || ! grep -qE 'file\(s\) scanned' <<< "$out"; then
    bad "bundled ruleset scan did not complete: $(grep -E 'WARN|ALERT|error' <<< "$out" | head -n2 | tr '\n' ' ')"
  else
    ok "bundled ruleset scans in the sandbox and finished"
    grep -E 'YARA: .*(high-risk|suspicious|informational) match' <<< "$out" | sed 's/^\[[A-Z]*\] *//; s/ Rules fire.*//' | sed 's/^/  info  /'
  fi
  if grep -qE 'SUSP_Just_EICAR.*matched game/eicar-bait.txt' <<< "$out"; then ok "bundled rules catch the bait file (SUSP_Just_EICAR matched game/eicar-bait.txt)"
  else bad "bundled rules did not flag game/eicar-bait.txt (expected SUSP_Just_EICAR): is gen_suspicious_strings.yar in the ruleset?"; fi
  if grep -qE '\[ALERT\] +YARA: high-risk rule' <<< "$out"; then ok "a high-risk match is an ALERT: wq-prescan would refuse to launch this"
  else bad "no high-risk ALERT for the bait (the unscored 'eicar' rule in malware/ should be rated high-risk): $(grep -E 'YARA:' <<< "$out" | head -n3 | tr '\n' ' ')"; fi
  printf 'rule wq_probe { strings: $a = "WQPROBECANARY" condition: $a }\n' > "$T/probe.yar"
  out="$(YARA_RULES="$T/probe.yar" "$QROOT/wq-yara.sh" "$NAME" --when manual --alertlog "$T/a2.log" 2>&1 | strip)"
  if grep -q 'wq_probe matched' <<< "$out"; then ok "rules file in /tmp is found and matches (sandbox copy works)"
  else bad "rules file in /tmp: $(grep -E 'WARN|ALERT|error' <<< "$out" | head -n2 | tr '\n' ' ')"; fi
fi

echo "== capa"
CAPA="${PRESCAN_CAPA_BIN:-$(command -v capa 2>/dev/null || true)}"
if [ -z "$CAPA" ] || [ ! -x "$CAPA" ]; then bad "capa is not installed (Arch: yay -S capa-bin, or pipx install flare-capa)"
else
  echo "  info  $CAPA: $("$CAPA" --version 2>&1 | head -n1)"
  RULES="${PRESCAN_CAPA_RULES:-$QROOT/third_party/capa-rules}"; SIGS="${PRESCAN_CAPA_SIGS:-$QROOT/third_party/capa-sigs}"
  CMD=("$CAPA" -q -j)
  if [ -d "$RULES" ]; then CMD+=(-r "$RULES"); ok "rules folder present ($(find "$RULES" -name '*.yml' | wc -l) rules)"; else echo "  info  no $RULES: capa uses its own rules"; fi
  if [ -d "$SIGS" ]; then CMD+=(-s "$SIGS"); else echo "  info  no $SIGS: capa uses its built-in signatures"; fi
  t0=$SECONDS; timeout 180 "${CMD[@]}" "$G/game/a.exe" > "$T/capa.json" 2> "$T/capa.err"; rc=$?; took=$((SECONDS - t0))
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if "rules" in d else 1)' "$T/capa.json" 2>/dev/null
  then ok "capa ran on a test PE and returned JSON, same command as the prescan (exit $rc)"
  else bad "capa gave no usable JSON (exit $rc): $(grep -v '^[[:space:]]*$' "$T/capa.err" | tail -n2 | cut -c1-200 | tr '\n' ' ')"
       echo "        wq-prescan treats that as 'no findings', so a broken capa looks like a clean scan"
       echo "  info  that run took ${took}s (exit 124 = cut off at 180s). Narrowing it down, 120s each:"
       # same file, capa's own rules and signatures: is it capa, or the bundled rules folder?
       t0=$SECONDS; timeout 120 "$CAPA" -q -j "$G/game/a.exe" > "$T/capa2.json" 2> "$T/capa2.err"; rc2=$?; took2=$((SECONDS - t0))
       if python3 -c 'import json,sys; sys.exit(0 if "rules" in json.load(open(sys.argv[1])) else 1)' "$T/capa2.json" 2>/dev/null
       then echo "  info  capa's own rules: finished in ${took2}s, so the slow or failing part is the rules folder ($RULES) or the signatures folder"
       else echo "  info  capa's own rules: also no result after ${took2}s (exit $rc2), so it is capa itself (version, install, or this machine), not our rules: $(grep -v '^[[:space:]]*$' "$T/capa2.err" | tail -n1 | cut -c1-200)"; fi
       # progress output (no -q) shows what capa was doing when it stalled: loading rules, extracting features ...
       timeout 40 "$CAPA" -j "$G/game/a.exe" 2>&1 >/dev/null | tr '\r' '\n' | grep -v '^[[:space:]]*$' | tail -n3 | cut -c1-160 | sed 's/^/  info  after 40s capa was at: /'
       echo "  info  if capa has a fast file-only backend (capa --help | grep -i backend), set PRESCAN_CAPA_ARGS=\"-b pefile\" in config.local.sh"
  fi
fi
echo "== pre-launch scan (what a launch would do, without launching)"
if [ ! -x "$QROOT/wq-prescan.sh" ]; then bad "wq-prescan.sh is missing or not executable"
else
  CLAM_SCAN=0 timeout 600 "$QROOT/wq-prescan.sh" "$NAME" --alertlog "$T/pre.log" > "$T/pre.out" 2>&1; prc=$?
  strip < "$T/pre.out" > "$T/pre.txt"
  grep -E 'Pre-launch|YARA: .*(high-risk|suspicious|informational)|refusing|refused' "$T/pre.txt" | cut -c1-170 | sed 's/^/  info  /'
  if grep -q 'large block of encrypted or compressed data' "$T/pre.txt"; then ok "large encrypted/compressed block appended to blob.exe is reported"
  else bad "the 1.5 MiB random block in blob.exe was not reported (is wq-prescan.py the new version?)"; fi
  if [ -n "${CAPA:-}" ] && [ -x "$CAPA" ]; then
    if grep -q 'capa gave NO result' "$T/pre.txt"; then bad "capa gave no result for the test PEs in the pre-launch scan"
    elif grep -q 'capa: analysed' "$T/pre.txt"; then ok "capa is reported in the pre-launch scan ($(grep -o 'capa: analysed [^(]*' "$T/pre.txt" | head -n1))"
    else bad "the pre-launch scan printed nothing about capa"; fi
  fi
  if grep -qE '\[ALERT\] +YARA: high-risk rule' "$T/pre.txt" && [ "$prc" -eq 1 ] && grep -q 'refusing to launch' "$T/pre.txt"; then ok "high-risk match refuses the launch (exit $prc)"
  else bad "launch was not refused for the EICAR bait (exit $prc): see the info lines above"; fi
  sum="$("$QROOT/summarize-run.sh" "$G" "$T/pre.log" 2>&1 | strip)"
  if grep -q 'Static scans' <<< "$sum" && grep -q 'REVIEW NEEDED' <<< "$sum"; then ok "run summary has a static-scans section and says REVIEW NEEDED"
  else bad "run summary is missing the static-scans section or the verdict"; fi
fi
python3 - "$G/game/blob.exe" <<'PY' 2>/dev/null && true
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("QROOT", "."), "wq-ui"))
try:
    import wq_entropy as E
    d = open(sys.argv[1], "rb").read()[-(1 << 20):]
    print("  info  your wq_entropy.shannon_entropy on the last MiB of blob.exe: %.2f (8.00 = random)" % E.shannon_entropy(d))
except Exception as e:
    print("  info  wq_entropy not checked (%s)" % e)
PY

if [ -n "$PE" ] && [ -n "${CAPA:-}" ] && [ -x "$CAPA" ]; then
  echo "== capa on $PE"
  timeout 300 "${CMD[@]}" "$PE" > "$T/capa-pe.json" 2> "$T/capa-pe.err" || true
  python3 - "$T/capa-pe.json" <<'PY' || echo "  FAIL  capa gave no usable output: $(tail -n1 "$T/capa-pe.err" | cut -c1-200)"
import json, sys
r = (json.load(open(sys.argv[1])).get("rules") or {})
print("  info  capa matched %d rule(s). Rules in persistence/ or collection/keylog raise the launch score:" % len(r))
rows = sorted(((((v or {}).get("meta") or {}).get("namespace") or "-"), k) for k, v in r.items())
for ns, name in rows[:40]:
    flag = "  <- scored" if ns.startswith(("persistence/", "collection/keylog")) else ""
    print("  info    %-38s %s%s" % (ns[:38], name, flag))
if len(rows) > 40: print("  info    ... and %d more" % (len(rows) - 40))
PY
fi
echo; echo "$PASS ok, $FAIL failed"
[ "$KEEP" = 1 ] && { rm -f "$G"/.yara-* "$G"/.clam-*; echo "kept $G (test PE: game/a.exe, canary: game/canary.txt). Delete it with: rm -rf $G"; }
[ "$FAIL" -eq 0 ]
