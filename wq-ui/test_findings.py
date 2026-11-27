#!/usr/bin/env python3
"""Tests wq_findings.py: alert-log lines (as the scanners write them) become the rows of the Findings tab."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import wq_findings as F

LOG = """\
[2026-11-23 14:28:39] [INFO] ClamAV: 1 file(s) scanned, none flagged (full) [output: clamscan-20261123-142830.log]
[2026-11-23 14:28:39] [INFO] Pre-launch: capa: analysed 2 PE file(s), 3 behaviour rule(s) matched (host-interaction 2, anti-analysis 1)
[2026-11-23 14:28:39] [WARN] Pre-launch: capa: command-and-control communication behaviour in: a.exe (+2)
[2026-11-23 14:28:39] [WARN] Pre-launch: large block of encrypted or compressed data appended to the program (a way to hide a payload): blob.exe (1.4 MiB, entropy 8.0) (+2)
[2026-11-23 14:28:39] [WARN] Pre-launch: executable code looks packed or encrypted: x.exe (entropy 7.8 in .text) (+2)
[2026-11-23 14:28:39] [INFO] Pre-launch risk score 4 (launch is refused at 5): capa_c2,big_blob
[2026-11-23 14:28:39] [INFO] Pre-launch checks: nothing suspicious in the executables
[2026-11-23 14:29:01] [INFO] YARA: ruleset built (wq-yara-build: 1321 rule files found, 1057 usable, 264 skipped)
[2026-11-23 14:29:01] [INFO] YARA: compiled ruleset, 264 rule file(s) left out at build time (see SKIPPED.txt)
[2026-11-23 14:29:01] [ALERT] YARA: high-risk rule eicar (Rule to detect Eicar pattern) matched game/wq-scan-probe.sh
[2026-11-23 14:29:01] [WARN] YARA: SUSP_Just_EICAR (score 40: Just an EICAR test file) matched game/eicar-bait.txt
[2026-11-23 14:29:01] [WARN] YARA: OldStyle matched game/a.exe
[2026-11-23 14:29:01] [INFO] YARA: 2 informational match(es), no action needed: IsConsole,IsPE64
[2026-11-23 14:29:01] [ALERT] YARA: 1 file(s) scanned: 1 high-risk, 0 suspicious, 0 informational match(es) in wq-scan-probe. Rules fire on suspicious patterns too, so look before you trust or condemn. [output: yara-20261123-142839.log]
[2026-11-23 14:29:01] [ALERT] Launch refused by the pre-launch scan. To run it anyway: tick off 'Pre-launch scan' in wq-ui, or set PRESCAN_ALLOW=1 in game.conf
[2026-11-23 14:29:01] [ALERT] Launch refused by the pre-launch scan. To run it anyway: tick off 'Pre-launch scan' in wq-ui, or set PRESCAN_ALLOW=1 in game.conf
[2026-11-23 14:29:01] [WARN] Pre-launch: references a web service often used to receive stolen data or give orders to malware (webhook, bot API, paste site, tunnel, .onion): a.exe [discord_webhook] (+3)
[2026-11-23 14:29:01] [WARN] Pre-launch: program has a section that is both writable and executable (self-modifying or unpacking code): a.exe (section .x is writable and executable) (+1)
[2026-11-23 14:29:02] [WARN] New process: something unrelated (pid=5)
not a log line
"""
fs = F.parse(LOG)
by = lambda src, what=None: [f for f in fs if f.source == src and (what is None or f.what == what)]

def eq(name, a, b):
    assert a == b, f"FAIL {name}: expected {b!r}, got {a!r}"
    print("ok  ", name)

eq("alerts sort first", [f.level for f in fs[:3]], ["ALERT"] * 3)
eq("levels never go back up", [F.ORDER[f.level] for f in fs], sorted(F.ORDER[f.level] for f in fs))
hi = by("YARA", "eicar")[0]
eq("high-risk rule: level", hi.level, "ALERT"); eq("high-risk rule: file", hi.file, "game/wq-scan-probe.sh")
eq("high-risk rule: detail", hi.detail, "high-risk rule: Rule to detect Eicar pattern")
sc = by("YARA", "SUSP_Just_EICAR")[0]
eq("scored rule: detail", sc.detail, "score 40: Just an EICAR test file"); eq("scored rule: level", sc.level, "WARN")
eq("old-style line still parses", by("YARA", "OldStyle")[0].file, "game/a.exe")
eq("informational rules: names", by("YARA", "informational file-type rules")[0].detail, "IsConsole,IsPE64")
eq("yara scan summary kept", by("YARA", "scan result")[0].level, "ALERT")
eq("ruleset build chatter dropped", [f for f in fs if "ruleset" in f.what or "compiled" in f.detail], [])
c2 = by("capa", "command-and-control communication behaviour")[0]
eq("capa behaviour: file", c2.file, "a.exe"); eq("capa behaviour: level", c2.level, "WARN")
eq("capa analysis row", by("capa", "analysis")[0].detail[:14], "analysed 2 PE ")
bl = by("Encrypted data")[0]
eq("encrypted block: file with size", bl.file, "blob.exe (1.4 MiB, entropy 8.0)")
eq("packing row", by("Packing")[0].file, "x.exe (entropy 7.8 in .text)")
eq("risk score row", by("Heuristics", "risk score 4 of 5")[0].detail, "capa_c2,big_blob")
eq("clean heuristics row", by("Heuristics", "executables checked")[0].detail, "nothing suspicious in the executables")
eq("ClamAV row", by("ClamAV")[0].level, "INFO"); eq("repeated launch-refused line collapsed", len(by("Launch")), 1)
eq("monitor events are not findings", [f for f in fs if "process" in f.what.lower()], [])
eq("string indicators get their own source", by("Indicators")[0].file, "a.exe [discord_webhook]")
eq("PE structure gets its own source", by("Structure")[0].file, "a.exe (section .x is writable and executable)")
eq("summary text", F.summary(fs), "3 alert(s), 7 warning(s): this would be refused or needs review.")
eq("empty log", F.summary(F.parse("")), "Nothing recorded for this run.")
eq("colour codes are ignored", len(F.parse("\x1b[31m[2026-11-23 14:29:01] [ALERT] YARA: high-risk rule X matched a.exe\x1b[0m")), 1)
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "logs").mkdir()
    for n in ("alerts-20261123-100000.log", "alerts-20261123-110000-scan.log", "launch-1.log"):
        (Path(d) / "logs" / n).write_text("")
    eq("logs_for: newest first, alert logs only", [p.name for p in F.logs_for(Path(d))],
       ["alerts-20261123-110000-scan.log", "alerts-20261123-100000.log"])
print("findings: ok")
