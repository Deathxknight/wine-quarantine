#!/bin/bash
# Tests wq-yara-update.py with a local zip (no network) and the build/stale hooks with a stub yarac.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "ok   - $1"; pass=$((pass+1)); }
bad() { echo "FAIL - $1"; fail=$((fail+1)); }
U="$HERE/wq-yara-update.py"

python3 - "$T/rules.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("good_one.yar", 'rule yh_good_one { meta:\n yarahub_license = "CC0 1.0"\n strings: $a = "abc"\n condition: $a }\n')
    z.writestr("sub/dir/good_two.yara", 'import "pe"\nrule yh_good_two { condition: pe.is_pe }\n')
    z.writestr("evil_include.yar", 'include "/etc/passwd"\nrule yh_inc { condition: true }\n')
    z.writestr("bad_import.yar", 'import "cuckoo"\nrule yh_cuckoo { condition: true }\n')
    z.writestr("../../escape.yar", 'rule yh_escape { condition: true }\n')
    z.writestr("/abs/path.yar", 'rule yh_abs { condition: true }\n')
    z.writestr("readme.txt", "not a rule")
    z.writestr("binary.yar", b"\xff\xfe\x00rule x")
    z.writestr("huge.yar", "rule yh_huge { condition: true }\n" + "// pad\n" * 300000)
    z.writestr("empty.yar", "// no rules here\n")
PY

D="$T/feeds"
python3 "$U" --zip "$T/rules.zip" --dest "$D" >"$T/log" 2>&1; rc=$?
[ "$rc" = 0 ] && ok "update from a local zip succeeds" || bad "update succeeds (rc=$rc: $(tail -n2 "$T/log"))"
Y="$D/yarahub"
[ -f "$Y/good_one.yar" ] && [ -f "$Y/good_two.yara" ] && ok "good rules kept, flat names" || bad "good rules kept: $(ls "$Y" 2>&1)"
[ ! -e "$Y/evil_include.yar" ] && grep -q 'evil_include.yar: uses "include"' "$Y/REJECTED.txt" && ok "include rejected and listed" || bad "include rejected"
grep -q 'bad_import.yar: imports "cuckoo"' "$Y/REJECTED.txt" && ok "disallowed import rejected and listed" || bad "disallowed import rejected"
grep -q 'huge.yar: larger than' "$Y/REJECTED.txt" && ok "oversized file rejected" || bad "oversized file rejected"
grep -q 'binary.yar' "$Y/REJECTED.txt" && ok "non-text file rejected" || bad "non-text file rejected"
grep -q 'empty.yar: no rule found' "$Y/REJECTED.txt" && ok "file without a rule rejected" || bad "file without a rule rejected"
# traversal names are flattened, nothing lands outside the feeds folder
[ ! -e "$T/escape.yar" ] && [ ! -e "$D/escape.yar" ] && [ ! -e /abs/path.yar ] && ok "path traversal / absolute names never escape" || bad "path traversal"
[ -f "$Y/escape.yar" ] && [ -f "$Y/path.yar" ] && ok "traversal entries stored as flat files inside yarahub/" || bad "traversal entries flattened"
[ ! -e "$Y/readme.txt" ] && ok "non-rule entries ignored" || bad "non-rule entries ignored"
grep -q '"CC0 1.0"' "$Y/.fetched" && ok "stamp records declared licenses" || bad "stamp records licenses"

# same zip again: no change, rule files keep their mtime
before="$(stat -c %Y "$Y/good_one.yar")"; sleep 1
python3 "$U" --zip "$T/rules.zip" --dest "$D" >"$T/log2" 2>&1
grep -q unchanged "$T/log2" && [ "$(stat -c %Y "$Y/good_one.yar")" = "$before" ] && ok "unchanged zip leaves rule files alone" || bad "unchanged zip ($(tail -n1 "$T/log2"))"

# a new zip replaces the set and keeps the previous one
python3 - "$T/rules2.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("only_new.yar", 'rule yh_only_new { condition: true }\n')
PY
python3 "$U" --zip "$T/rules2.zip" --dest "$D" >/dev/null 2>&1
[ -f "$Y/only_new.yar" ] && [ ! -e "$Y/good_one.yar" ] && [ -f "$Y.prev/good_one.yar" ] && ok "new set replaces old, previous kept as yarahub.prev" || bad "replace keeps .prev"

# bad downloads never replace a good set
printf 'not a zip <html>login</html>' > "$T/notzip.zip"
python3 "$U" --zip "$T/notzip.zip" --dest "$D" >"$T/log3" 2>&1; rc=$?
[ "$rc" = 1 ] && [ -f "$Y/only_new.yar" ] && ok "non-zip refused, old rules kept" || bad "non-zip refused (rc=$rc)"
python3 - "$T/rules3.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("evil.yar", 'include "x"\nrule a { condition: true }\n')
PY
python3 "$U" --zip "$T/rules3.zip" --dest "$D" >"$T/log4" 2>&1; rc=$?
[ "$rc" = 1 ] && [ -f "$Y/only_new.yar" ] && ok "zip with nothing usable refused, old rules kept" || bad "empty result refused (rc=$rc)"

# --dry-run writes nothing
python3 "$U" --zip "$T/rules.zip" --dest "$T/dry" --dry-run >/dev/null 2>&1
[ ! -e "$T/dry/yarahub" ] && ok "--dry-run writes nothing" || bad "--dry-run writes nothing"

# network paths: HTTP refused; a fresh stamp skips the download
python3 "$U" --url http://example.invalid/x.zip --dest "$T/net" --force >"$T/log5" 2>&1; rc=$?
[ "$rc" = 1 ] && grep -q 'non-HTTPS' "$T/log5" && ok "plain HTTP URL refused" || bad "plain HTTP refused (rc=$rc: $(tail -n1 "$T/log5"))"
python3 "$U" --url https://example.invalid/x.zip --dest "$D" >"$T/log6" 2>&1; rc=$?
[ "$rc" = 0 ] && grep -q 'waiting\|old' "$T/log6" && ok "recent fetch: no download attempted" || bad "recent fetch skips download (rc=$rc: $(tail -n1 "$T/log6"))"

# build hook: with no roots given, _yara-feeds/ is used after the bundled sets (stub yarac, copied project layout)
cat > "$T/yarac" <<'STUB'
#!/bin/bash
out="${@: -1}"; : > "$out"
STUB
chmod +x "$T/yarac"
P="$T/proj"; mkdir -p "$P/third_party/signature-base-yara" "$P/third_party/yara-rules/malware" "$P/_yara-feeds"
cp "$HERE/wq-yara-build.sh" "$P/"
echo 'rule bundled_one { condition: true }' > "$P/third_party/signature-base-yara/a.yar"
echo 'rule yh_good_one { condition: true }' > "$P/third_party/yara-rules/malware/dup.yar"   # same name as the feed's rule
cp -r "$D/yarahub" "$P/_yara-feeds/yarahub"; cp "$T/rules.zip" /dev/null
python3 "$U" --zip "$T/rules.zip" --dest "$P/_yara-feeds" >/dev/null 2>&1
YARAC="$T/yarac" "$P/wq-yara-build.sh" "$T/built" >"$T/blog" 2>&1
[ -f "$T/built/rules/yarahub/good_two.yara" ] && ok "build picks up _yara-feeds/yarahub" || bad "build picks up feeds ($(tail -n3 "$T/blog"))"
grep -q 'yarahub/good_one.yar: duplicate rule name yh_good_one' "$T/built/SKIPPED.txt" && ok "bundled rule wins over a feed rule with the same name" || bad "duplicate name resolved in favour of bundled rules"
rm -rf "$P/_yara-feeds"
YARAC="$T/yarac" "$P/wq-yara-build.sh" "$T/built2" >/dev/null 2>&1 && [ -f "$T/built2/rules.yarc" ] && ok "build works without _yara-feeds/" || bad "build works without feeds"

echo; echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
