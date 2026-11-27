#!/usr/bin/env python3
"""What the scanners found, read from a run's alert log. Plain Python (no Qt), tested on its own.

The alert log has one line per event: "[2026-11-23 14:29:01] [ALERT] YARA: ...". parse() turns the lines that
come from YARA, capa, the pre-launch heuristics (packing, big encrypted blocks, ...) and ClamAV into rows a table
can show: level, source, what, details, file."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LINE = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]\s+\[(ALERT|WARN|INFO)\]\s+(.*)$")
_OUTPUT = re.compile(r"\s*\[output: [^\]]*\]\s*$")
_RULES_FIRE = re.compile(r"\s*Rules fire on suspicious patterns too.*$")
_SCORE = re.compile(r"\s*\(\+\d+\)\s*$")
ORDER = {"ALERT": 0, "WARN": 1, "INFO": 2}
# wq-prescan.py messages that come from the string/structure indicators (wq_indicators.py), by how they start
_INDICATOR_SOURCES = (
    ("references a web service", "Indicators"), ("mentions several places where browsers", "Indicators"),
    ("contains ransomware wording", "Indicators"), ("contains a command that downloads", "Indicators"),
    ("contains a way to start itself", "Indicators"), ("checks whether it is being watched", "Indicators"),
    ("contains words typical of a remote-access", "Indicators"),
    ("program has a section", "Structure"), ("program has code space", "Structure"),
    ("program starts running in an unusual", "Structure"), ("program imports almost nothing", "Structure"),
    ("another Windows program is stored", "Structure"),
)


@dataclass(frozen=True)
class Finding:
    level: str      # ALERT | WARN | INFO
    source: str     # YARA | capa | Encrypted data | Packing | Indicators | Structure | Heuristics | ClamAV | Launch
    what: str       # the rule, behaviour or check
    detail: str     # score/description or the summary
    file: str       # file inside the game folder, when there is one
    when: str = ""


def _clean(msg: str) -> str:
    return _OUTPUT.sub("", msg).strip()


def classify(level: str, msg: str, when: str = "") -> Finding | None:
    msg = _clean(msg)

    def mk(source, what, detail="", file=""):
        return Finding(level, source, what, detail.strip(), file.strip(), when)

    if msg.startswith("YARA:"):
        body = msg[5:].strip()
        if body.startswith(("compiled ruleset", "ruleset built", "scanning", "YARA scan")):
            return None
        m = re.match(r"high-risk rule (\S+?)(?: \((.*)\))? matched (\S.*)$", body)
        if m:
            return mk("YARA", m.group(1), "high-risk rule" + (": " + m.group(2) if m.group(2) else ""), m.group(3))
        m = re.match(r"(\S+?)(?: \((.*)\))? matched (\S.*)$", body)
        if m:
            return mk("YARA", m.group(1), m.group(2) or "", m.group(3))
        m = re.match(r"(\d+) informational match\(es\), no action needed: (.*)$", body)
        if m:
            return mk("YARA", "informational file-type rules", m.group(2))
        if re.search(r"file\(s\) scanned|rule match\(es\) in|\.\.\. and \d+ more", body):
            return mk("YARA", "scan result", _RULES_FIRE.sub("", body))
        return mk("YARA", body)

    if msg.startswith("Pre-launch"):
        body = re.sub(r"^Pre-launch(?: checks)?:?\s*", "", msg)
        if msg.startswith("Pre-launch checks:"):
            return mk("Heuristics", "executables checked", body)
        m = re.match(r"risk score (\d+) \(launch is refused at (\d+)\)(?:: (.*))?$", body)
        if m:
            return mk("Heuristics", "risk score %s of %s" % (m.group(1), m.group(2)), m.group(3) or "nothing counted")
        if body.startswith("capa:"):
            b = body[5:].strip()
            if b.startswith(("analysed", "installed")):
                return mk("capa", "analysis", b)
            if "NO result" in b:
                return mk("capa", "capa gave no result", b)
            m = re.match(r"(.*?) in: (.*)$", b)
            return mk("capa", m.group(1) if m else b, "", _SCORE.sub("", m.group(2)) if m else "")
        m = re.match(r"(large block of encrypted or compressed data[^:]*): (.*)$", body)
        if m:
            return mk("Encrypted data", "large encrypted/compressed block", "appended to the program (a way to hide a payload)", _SCORE.sub("", m.group(2)))
        m = re.match(r"(executable code looks packed or encrypted|protected with a commercial packer[^:]*|UPX-packed): (.*)$", body)
        if m:
            return mk("Packing", m.group(1), "", _SCORE.sub("", m.group(2)))
        for pat, source in _INDICATOR_SOURCES:
            m = re.match(r"(" + pat + r"[^:]*(?:\([^)]*\))?[^:]*): (.*)$", body)
            if m:
                return mk(source, m.group(1), "", _SCORE.sub("", m.group(2)))
        m = re.match(r"(.*?): (.*)$", body)
        if m:
            return mk("Heuristics", m.group(1), "", _SCORE.sub("", m.group(2)))
        return mk("Heuristics", _SCORE.sub("", body))

    if msg.startswith("ClamAV"):
        return mk("ClamAV", "scan" if level == "INFO" else "detection", msg)

    if msg.startswith("Launch refused"):
        return mk("Launch", "launch refused", "the pre-launch scan found something serious")
    return None


def parse(text: str) -> list[Finding]:
    """Findings of one alert log: alerts first, then warnings, then info; repeats collapsed."""
    seen, out = set(), []
    for raw in text.splitlines():
        m = _LINE.match(_ANSI.sub("", raw))
        if not m:
            continue
        f = classify(m.group(2), m.group(3), m.group(1))
        if f is None:
            continue
        key = (f.level, f.source, f.what, f.detail, f.file)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: ORDER[f.level])        # stable: log order is kept inside each level
    return out


def logs_for(game_dir: Path, limit: int = 12) -> list[Path]:
    """Newest alert logs of a game first."""
    try:
        return sorted((Path(game_dir) / "logs").glob("alerts-*.log"), reverse=True)[:limit]
    except OSError:
        return []


def summary(findings: list[Finding]) -> str:
    a = sum(f.level == "ALERT" for f in findings)
    w = sum(f.level == "WARN" for f in findings)
    if not findings:
        return "Nothing recorded for this run."
    if a:
        return "%d alert(s), %d warning(s): this would be refused or needs review." % (a, w)
    if w:
        return "No alerts, %d warning(s)." % w
    return "No alerts or warnings."
