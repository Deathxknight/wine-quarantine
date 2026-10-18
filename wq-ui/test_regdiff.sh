#!/bin/bash
# reg-diff.sh against Wine-format registry files (key headers are followed by a #time= line, key
# paths have doubled backslashes, long values continue on indented lines).
#   bash wq-ui/test_regdiff.sh
set -u
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
count(){ grep -c "$1" "$T/alerts" || true; }
eqn()  { [ "$2" = "$3" ] && ok || fail "$1" "expected $2 got $3. alerts were:$(printf '\n        %s' "$(sed 's/^\[[^]]*\] //' "$T/alerts")")"; }

G="$T/g"; mkdir -p "$G/prefix" "$G/logs"
cat > "$T/before.reg" <<'R'
WINE REGISTRY Version 2
;; All keys relative to \\Machine

#arch=win64

[Software\\Microsoft\\Windows\\CurrentVersion\\Run] 1699999999
#time=1da0123456789ab
"Existing"="C:\\keep.exe"

[Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon] 1699999999
#time=1da0123456789ab
"Shell"="explorer.exe"
"Userinit"="C:\\windows\\system32\\userinit.exe"

[Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows] 1699999999
#time=1da0123456789ab
"AppInit_DLLs"=""

[Software\\MyGame] 1699999999
#time=1da0123456789ab
"volume"=dword:00000005
R
run() {   # run <after.reg>
  cp "$T/before.reg" "$G/prefix/system.reg"; rm -rf "$G/.reg-snapshot" "$G"/logs/*; : > "$T/alerts"
  "$SRC/reg-diff.sh" snapshot "$G"; cp "$1" "$G/prefix/system.reg"
  "$SRC/reg-diff.sh" compare "$G" "$T/alerts" >/dev/null
}

run "$T/before.reg"
eqn "identical registry: no alerts" 0 "$(count ALERT)"; grep -q 'unchanged' "$T/alerts" && ok || fail "says unchanged"

# value added to a key that already existed, plus keys that merely look similar
sed 's/^"Existing"="C:\\\\keep.exe"$/&\n"Evil"="C:\\\\users\\\\x\\\\evil.exe"/' "$T/before.reg" > "$T/a1.reg"
printf '\n[Software\\\\MyGame\\\\Runtime] 1700000000\n#time=1da0\n"x"="1"\n\n[Software\\\\MyGame\\\\Running] 1700000000\n#time=1da0\n"y"=hex:01,02,\\\n  03,04\n' >> "$T/a1.reg"
run "$T/a1.reg"
eqn "value added to an EXISTING Run key is an alert" 1 "$(count ALERT)"
grep -q 'Evil' "$T/alerts" && ok || fail "the alert names the value"
grep -qE 'Runtime|Running' "$T/alerts" && fail "Runtime/Running are not the Run key" || ok

# brand new Run key (the case the old grep -A1 could not see: #time sits between header and value)
sed '$d' "$T/before.reg" > /dev/null
{ cat "$T/before.reg"; printf '\n[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce] 1700000000\n#time=1da0\n"X"="C:\\\\x.exe"\n'; } > "$T/a1b.reg"
run "$T/a1b.reg"; eqn "brand new RunOnce key is an alert" 1 "$(count ALERT)"

# AppInit_DLLs set (was empty), Userinit hijacked, a service installed (and a builtin one, which is fine)
sed -e 's/"AppInit_DLLs"=""/"AppInit_DLLs"="C:\\\\evil.dll"/' -e 's/system32\\\\userinit.exe/users\\\\x\\\\u.exe/' "$T/before.reg" > "$T/a2.reg"
printf '\n[System\\\\CurrentControlSet\\\\Services\\\\EvilSvc] 1700000000\n#time=1da0\n"ImagePath"="C:\\\\users\\\\x\\\\svc.exe"\n\n[System\\\\CurrentControlSet\\\\Services\\\\Wineish] 1700000000\n#time=1da0\n"ImagePath"="C:\\\\windows\\\\system32\\\\wineish.exe"\n' >> "$T/a2.reg"
run "$T/a2.reg"
eqn "AppInit_DLLs + Userinit + service = 3 alerts" 3 "$(count ALERT)"
grep -q 'Wineish' "$T/alerts" && fail "a system32 service is not flagged" || ok

# an ordinary game setting
sed 's/dword:00000005/dword:00000009/' "$T/before.reg" > "$T/a3.reg"
run "$T/a3.reg"; eqn "game setting change: no alert" 0 "$(count ALERT)"; grep -q 'Registry changed' "$T/alerts" && ok || fail "still reported as INFO"

# Winlogon key removed
python3 - "$T" <<'P'
import sys; t=sys.argv[1]; s=open(t+"/before.reg").read()
i=s.index("[Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon]"); j=s.index("[Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows]")
open(t+"/a4.reg","w").write(s[:i]+s[j:])
P
run "$T/a4.reg"; eqn "Winlogon key removed is an alert" 1 "$(count 'key removed')"

# many hits are capped, with one pointer line
{ cat "$T/before.reg"; printf '\n[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run] 1700000000\n#time=1\n'; for i in 1 2 3 4 5 6 7 8; do printf '"E%s"="C:\\\\e%s.exe"\n' $i $i; done; } > "$T/a5.reg"
run "$T/a5.reg"; eqn "hits are capped at 5 alerts" 5 "$(count ALERT)"; grep -q '3 more persistence' "$T/alerts" && ok || fail "pointer to the rest"

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
