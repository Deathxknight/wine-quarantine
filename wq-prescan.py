#!/usr/bin/env python3
"""wq-prescan.py <game-dir> [--start <relative exe>]

Static checks on <game-dir>/game before the game is allowed to start. Standard library only,
nothing is executed. Prints tab-separated lines:

    FINDING <kind> <points> <message>
    SCORE   <total>  <kinds, comma separated>

A kind counts once however many files hit it, so a game with thirty UPX'd DLLs scores the same as
one with a single UPX'd DLL. The caller blocks the launch when SCORE reaches its threshold.
These are signals, not verdicts: each one alone is common in honest games.
"""
import json
import math
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import glob
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wq_indicators as ind

TIME_CAP = float(os.environ.get("PRESCAN_TIME_CAP", "60"))
MAX_EXAMPLES = 3

PE_EXT = {".exe", ".dll", ".scr", ".com", ".sys", ".asi", ".ocx", ".cpl"}
ASSET_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ogg", ".wav", ".mp3", ".flac", ".mp4", ".webm", ".ogv", ".avi",
             ".ttf", ".otf", ".woff", ".woff2", ".pak", ".bank", ".assets", ".unity3d", ".dds", ".tga", ".psd", ".zip", ".7z", ".rar"}
DATA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".ini", ".cfg", ".json", ".xml", ".mp3", ".ogg", ".wav", ".mp4", ".zip", ".rar", ".7z"}
SCRIPTLIKE_EXT = {".scr", ".pif", ".hta", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".cpl"}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp[34]|zip|rar|7z)"
                        r"\s*\.(exe|scr|com|pif|bat|cmd|js|vbs|lnk|hta)$", re.I)
HIDDEN_NAME = re.compile("[\u202a-\u202e\u2066-\u2069\u061c\u200b-\u200f\u2028\u2029\u2060-\u2064\u206a-\u206f"
                         "\ufeff\u00ad\u180e\u2800\ufff9-\ufffb\U000e0000-\U000e007f]")

PACKER_UPX = {"upx0", "upx1", "upx2", ".upx0", ".upx1"}
PACKER_PROTECT = {".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2", ".enigma1", ".enigma2", ".aspack",
                  ".adata", ".petite", ".mpress1", ".mpress2", ".perplex", ".taz", ".nsp0", ".nsp1"}

INJECT = {"writeprocessmemory", "createremotethread", "createremotethreadex", "virtualallocex",
          "ntunmapviewofsection", "queueuserapc", "setthreadcontext", "ntcreatethreadex",
          "rtlcreateuserthread", "ntwritevirtualmemory"}
DOWNLOAD = {"urldownloadtofilea", "urldownloadtofilew", "urldownloadtocachefilea", "urldownloadtocachefilew"}
RUNS_PROGRAM = {"createprocessa", "createprocessw", "winexec", "shellexecutea", "shellexecutew",
                "shellexecuteexa", "shellexecuteexw"}

POINTS = {
    "double_ext": 3, "odd_name": 3, "inject": 3, "dropper": 3, "shell_net": 3,
    "packed_entropy": 2, "packer_protect": 2, "disguised": 2, "scriptlike": 2, "shell_persist": 2,
    "packer_upx": 1,
    "capa_persist": 2, "capa_keylog": 3, "die_packed": 0,
    "dotnet_framework": 0, "dotnet_protected": 0,
    "capa_cred": 3, "capa_destroy": 3, "capa_c2": 2, "capa_inject": 2,
    "big_blob": 2,
    "pe_wx_section": 1, "pe_unpack_stub": 2, "pe_odd_entry": 2, "pe_thin_imports": 2, "pe_embedded": 1,
    "ind_c2_service": 3, "ind_stealer": 3, "ind_ransom": 3, "ind_lolbin": 3,
    "ind_persist": 1, "ind_anti_analysis": 1, "ind_rat_words": 2,
    "ind_payload_desc": 3, "ind_revshell": 3, "ind_linux_dropper": 3, "ind_linux_persist": 2,
    "script_decode_exec": 3, "fork_bomb": 3, "mal_name": 3, "mal_name_weak": 1,
    # YARA matches promoted to score
    "yara_vmdetect": 2, "yara_encrypted": 3, "yara_ransomware": 5,
    # ATT&CK T1059.004 cumulative chain
    "attack_chain_t1059": 4,
    # ELF capability detection
    "capa_exec": 3, "capa_write": 2, "capa_net": 3,
}
BLOB_MIN = 1 << 20
BLOB_ENTROPY = 7.5

SHELL_NET = [
    re.compile(r"(curl|wget)\b[^\n|]{0,2000}\|\s*(sudo\s+)?(ba|z)?sh\b"),
    re.compile(r"base64\s+(-d|--decode)[^\n]{0,2000}\|\s*(ba|z)?sh\b"),
    re.compile(r"\bnc\b[^\n]{0,2000}\s-e\b|\bncat\b[^\n]{0,2000}(-e\b|--exec)"),
    re.compile(r"exec\s+\d+<>\s*/dev/(tcp|udp)/|/dev/(tcp|udp)/[a-zA-Z0-9.-]+/\d+"),
    re.compile(r"exec\s+-a\s+['\"]?[a-zA-Z0-9_-]+['\"]?\s+"),
    re.compile(r"\bsetsid\b[^\n]{0,200}\bexec\s+-a\b"),
    re.compile(r"\bdd\b[^\n]{0,100}\bof=[\"']?\$0"),
]
SHELL_PERSIST = re.compile(r"\bcrontab\b|authorized_keys|\.ssh/id_|/etc/(passwd|shadow|sudoers)"
                           r"|\.bashrc|\.zshrc|\.bash_profile|systemctl\s+--user|\.config/autostart"
                           r"|\.local/share/|\.desktop\b|\.icon\b")
SHELL_WRITE = re.compile(r"(?:(?<!\d)>>?(?!&))|&>>?|\btee\b|\bcp\b|\bmv\b|\bln\b|\binstall\b"
                         r"|\bsed\s+-i|\bcrontab\s+(?:-\s*(?:$|[|;&])|[^-\s])|\benable\b|\bchmod\b")

NET_CONN = re.compile(r"\.connect\(|fsockopen|TCPSocket\.new|net\.connect|new\s+Socket", re.I)
PY_SHELL = re.compile(r"dup2\([^)\n]{0,40}fileno|pty\.spawn|/bin/(?:ba|da|z)?sh[\"']?\s*,?\s*[\"']?-i\b|shell_exec|passthru|proc_open"
                      r"|\b(?:exec|spawn|popen|system)\s*\(?\s*[\"']/bin/(?:ba|da|z)?sh", re.I)
DECODE_EXEC = re.compile(r"\b(?:exec|eval)\s*\(\s*(?:[a-z_.]*decompress\(\s*)?(?:base64\.)?b64decode|\b(?:exec|eval)\s*\(\s*marshal\.loads"
                         r"|\bmarshal\.loads\(\s*(?:zlib\.)?(?:decompress|b64decode)|\beval\s*\(\s*(?:atob|string\.fromcharcode)|\beval\s*\(\s*base64_decode\("
                         r"|\beval\s*\(\s*gzinflate\s*\(\s*base64_decode", re.I)
FORK_BOMB = re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|while\s+(?:true|:)[^\n;]{0,10};?\s*do[^\n]{0,60}\$0\s*&"
                       r"|while\s+True\s*:\s*\n?\s*os\.fork\(\)|\bfork\s+while\s+1|for\s*\(\s*;\s*;\s*\)\s*\{?\s*fork\(\)", re.I)
MAL_NAME = re.compile(r"reverse[_ -]?shell|revshell|keylog|backdoor|stealer|ransom|rootkit|meterpreter|mimikatz|webshell|botnet|cryptolocker"
                      r"|(?<![a-z])rat(?![a-z])|trojan", re.I)
NAME_WEAK = re.compile(r"payload|exploit|dropper|implant|beacon|spawner", re.I)
ELF_SKIP = re.compile(r"(?:libcef\S*|libnss\S*|libsoup\S*|libsentry\S*|crashpad_handler|libvulkan\S*|libllvm\S*|libgallium\S*|libmono\S*|"
                      r"libcoreclr\S*|libicu\S*|libqt\S*|libpsl\S*|libpython\S*|libssl\S*|libcrypto\S*|libgnutls\S*|libcurl\S*|libwebkit\S*|libnode\S*)", re.I)
if os.environ.get("PRESCAN_ELF_SKIP"):
    try:
        _extra = re.compile(os.environ["PRESCAN_ELF_SKIP"], re.I)
        _base_skip = ELF_SKIP
        class _Skip:
            @staticmethod
            def match(name):
                return _base_skip.match(name) or _extra.match(name)
        ELF_SKIP = _Skip
    except re.error:
        pass

capa_stats = {"ok": 0, "fail": 0, "timeout": 0, "big": 0, "why": "", "names": set(), "ns": Counter()}
findings = {}
counts = Counter()

_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u061c\u200b-\u200f\u2028\u2029\u2060-\u2064\u206a-\u206f"
                     "\ufeff\u00ad\u180e\u2800\ufff9-\ufffb\U000e0000-\U000e007f]")


def _safe(text):
    out = []
    for ch in str(text):
        o = ord(ch)
        if 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif 0xD800 <= o <= 0xDFFF or _UNSAFE.match(ch):
            out.append("<U+%04X>" % o)
        else:
            out.append(ch)
    return "".join(out)


def add(kind, example):
    counts[kind] += 1
    ex = findings.setdefault(kind, [])
    if len(ex) < MAX_EXAMPLES:
        ex.append(_safe(example))


def entropy(buf):
    if not buf:
        return 0.0
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in Counter(buf).values())


def read_cstr(f, off, limit=80):
    f.seek(off)
    raw = f.read(limit)
    return raw.split(b"\0", 1)[0].decode("latin1", "replace")


def parse_pe(path, size):
    with open(path, "rb") as f:
        head = f.read(64)
        if len(head) < 64 or head[:2] != b"MZ":
            return None
        pe_off = struct.unpack("<I", head[0x3C:0x40])[0]
        if pe_off + 24 > size:
            return None
        f.seek(pe_off)
        hdr = f.read(24)
        if hdr[:4] != b"PE\0\0":
            return None
        nsec, = struct.unpack("<H", hdr[6:8])
        optsz, = struct.unpack("<H", hdr[20:22])
        opt = f.read(optsz)
        if len(opt) < 2:
            return None
        plus = struct.unpack("<H", opt[:2])[0] == 0x20B
        entry_rva = struct.unpack("<I", opt[16:20])[0] if len(opt) >= 20 else 0
        dd = 112 if plus else 96
        imp_rva = 0
        if len(opt) >= dd + 16 and struct.unpack("<I", opt[dd - 4:dd])[0] > 1:
            imp_rva = struct.unpack("<I", opt[dd + 8:dd + 12])[0]
        sections = []
        for _ in range(min(nsec, 96)):
            s = f.read(40)
            if len(s) < 40:
                break
            name = s[:8].rstrip(b"\0").decode("latin1", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack("<IIII", s[8:24])
            flags, = struct.unpack("<I", s[36:40])
            sections.append((name, vsize, vaddr, rawsize, rawptr, flags))

        def to_off(rva):
            for _n, vs, va, rs, rp, _fl in sections:
                if va <= rva < va + max(vs, rs):
                    return rp + rva - va
            return None

        imports, dlls = set(), []
        off = to_off(imp_rva) if imp_rva else None
        step = 8 if plus else 4
        for i in range(512 if off is not None else 0):
            f.seek(off + i * 20)
            d = f.read(20)
            if len(d) < 20 or d == b"\0" * 20:
                break
            oft, _t, _fc, name_rva, ft = struct.unpack("<IIIII", d)
            noff = to_off(name_rva)
            if noff is not None:
                dlls.append(read_cstr(f, noff).lower())
            toff = to_off(oft or ft)
            if toff is None:
                continue
            for j in range(4096):
                f.seek(toff + j * step)
                raw = f.read(step)
                if len(raw) < step:
                    break
                val = int.from_bytes(raw, "little")
                if val == 0:
                    break
                if val >> (step * 8 - 1):
                    continue
                hoff = to_off(val)
                if hoff is not None:
                    imports.add(read_cstr(f, hoff + 2, 64).lower())
        hot = []
        for name, _vs, _va, rs, rp, fl in sections:
            if fl & 0x20000000 and rs >= 65536:
                f.seek(rp)
                e = entropy(f.read(min(rs, 1 << 20)))
                if e >= 7.2:
                    hot.append((name, e))
        blob = None
        if sections:
            raw_end = max(sec[4] + sec[3] for sec in sections)
            if size - raw_end >= BLOB_MIN:
                f.seek(raw_end)
                e = entropy(f.read(1 << 20))
                if e >= BLOB_ENTROPY:
                    blob = (size - raw_end, e)
        return {"sections": [s[0] for s in sections], "imports": imports, "dlls": dlls, "hot": hot,
                "dotnet": "mscoree.dll" in dlls, "blob": blob, "secinfo": sections, "entry": entry_rva,
                "size": size}


def check_pe(rel, info):
    names = {n.lower() for n in info["sections"]}
    if names & PACKER_UPX:
        add("packer_upx", rel)
    if names & PACKER_PROTECT:
        add("packer_protect", rel)
    if info["hot"] and not info["dotnet"]:
        add("packed_entropy", "%s (entropy %.1f in %s)" % (rel, info["hot"][0][1], info["hot"][0][0]))
    if info["dotnet"]:
        add("dotnet_framework", rel)
        if info["hot"]:
            add("dotnet_protected", "%s (entropy %.1f in %s)" % (rel, info["hot"][0][1], info["hot"][0][0]))
    if info.get("blob"):
        add("big_blob", "%s (%.1f MiB, entropy %.1f)" % (rel, info["blob"][0] / 1048576, info["blob"][1]))
    for kind, text in ind.pe_structure_flags(info.get("secinfo") or [], info.get("entry", 0), info["imports"],
                                             info["dotnet"], info.get("size", 0)).items():
        add(kind, "%s (%s)" % (rel, text))
    imp = info["imports"]
    if "writeprocessmemory" in imp and len(imp & INJECT) >= 3:
        add("inject", rel)
    if imp & DOWNLOAD and imp & RUNS_PROGRAM:
        add("dropper", rel)


def check_strings(path, rel, size, want_embedded=False):
    found, embedded = ind.scan_file(path, size, DEADLINE, want_embedded)
    for cat, fams in found.items():
        add("ind_" + cat, "%s [%s]" % (rel, ", ".join(fams[:4])))
    if embedded:
        add("pe_embedded", "%s (%d)" % (rel, embedded))


def _looks_text(path):
    try:
        with open(path, "rb") as f:
            return b"\0" not in f.read(4096)
    except OSError:
        return False


def check_script(path, rel):
    try:
        with open(path, "rb") as f:
            text = f.read(1 << 20).decode("utf-8", "replace")
    except OSError:
        return
    if any(p.search(text) for p in SHELL_NET):
        add("shell_net", rel)
    elif NET_CONN.search(text) and PY_SHELL.search(text):
        add("shell_net", rel)
    if DECODE_EXEC.search(text):
        add("script_decode_exec", rel)
    if FORK_BOMB.search(text):
        add("fork_bomb", rel)
    if not (rel.lower().endswith((".sh", ".bash", ".zsh")) or re.match(r"#!\s*\S*(?:ba|z|da|k)?sh\b|#!\s*/usr/bin/env\s+(?:ba|z|da|k)?sh\b", text[:80])):
        return
    if any(SHELL_PERSIST.search(line) and SHELL_WRITE.search(line) for line in text.splitlines()):
        add("shell_persist", rel)


# --- YARA Log Scanner ---
def check_yara_logs(gamedir):
    """Read all recent YARA logs and add scores for matched rules."""
    logs = glob.glob(os.path.join(gamedir, "logs", "yara-*.log"))
    if not logs:
        return
    found_vm = False
    found_enc = False
    found_ransom = False
    for logfile in logs:
        try:
            with open(logfile, "r") as f:
                content = f.read()
                if "vmdetect" in content:
                    found_vm = True
                if "DetectEncryptedVariants" in content:
                    found_enc = True
                if "RANSOMWARE" in content:
                    found_ransom = True
                if "MIRAI" in content or "MassHunt" in content or "CYFARE" in content:
                    found_ransom = True
                # ELF-specific rules
                if "ELF_Obfuscated_Ransom_String" in content:
                    found_ransom = True
                if "ELF_High_Entropy" in content:
                    found_enc = True
        except OSError:
            pass
    if found_vm:
        add("yara_vmdetect", "cached YARA log")
    if found_enc:
        add("yara_encrypted", "cached YARA log")
    if found_ransom:
        add("yara_ransomware", "cached YARA log")
# --- END YARA Log Scanner ---


EXT_TIMEOUT = float(os.environ.get("PRESCAN_EXTERNAL_TIMEOUT", "120"))
EXT_MAX = int(os.environ.get("PRESCAN_EXTERNAL_MAX", "10"))
EXT_BUDGET = float(os.environ.get("PRESCAN_EXTERNAL_BUDGET", "180"))
CAPA_MAX_MB = float(os.environ.get("PRESCAN_CAPA_MAX_MB", "30"))
ext_spent = 0.0
CAPA_BIN = (os.environ.get("PRESCAN_CAPA_BIN") or shutil.which("capa")) if os.environ.get("PRESCAN_CAPA", "auto") != "0" else None
HERE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPA_RULES = os.environ.get("PRESCAN_CAPA_RULES") or os.path.join(HERE_DIR, "third_party", "capa-rules")
CAPA_SIGS = os.environ.get("PRESCAN_CAPA_SIGS") or os.path.join(HERE_DIR, "third_party", "capa-sigs")
CAPA_EXTRA = shlex.split(os.environ.get("PRESCAN_CAPA_ARGS", ""))
DEADLINE = None
DIE_BIN = (os.environ.get("PRESCAN_DIE_BIN") or shutil.which("diec")) if os.environ.get("PRESCAN_DIE", "auto") != "0" else None
CAPA_KINDS = [
    (("persistence/",), "capa_persist"),
    (("collection/keylog",), "capa_keylog"),
    (("collection/browser", "collection/password-manager", "collection/acquire-credentials",
      "collection/get-steam-token"), "capa_cred"),
    (("impact/",), "capa_destroy"),
    (("communication/",), "capa_c2"),
    (("host-interaction/process/inject",), "capa_inject"),
    (("host-interaction/process/create",), "capa_exec"),
    (("host-interaction/file-system/write",), "capa_write"),
    (("communication/named-pipe", "communication/socket"), "capa_net"),
]
DIE_PACKED = re.compile(r"\b(Packer|Protector)\s*:", re.I)
ext_runs = 0


def _run_limited(cmd, timeout):
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, text=True,
                                errors="replace", start_new_session=True)
        timed_out = False
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                proc.kill()
            try:
                proc.communicate(timeout=5)
            except (subprocess.TimeoutExpired, ValueError, OSError):
                pass
            out = ""
        why = ""
        try:
            errf.seek(0, 2)
            errf.seek(max(0, errf.tell() - 2000))
            lines = [l.strip() for l in errf.read().decode("utf-8", "replace").replace("\r", "\n").split("\n") if l.strip()]
            why = re.sub(r"[\x00-\x1f\x7f]+", " ", lines[-1])[:160] if lines else ""
        except (OSError, ValueError):
            pass
        return out, timed_out, why


def _ext_timeout():
    left = EXT_BUDGET - ext_spent
    return 0 if left < 5 else min(EXT_TIMEOUT, left)


def run_external(path, rel):
    global ext_runs, ext_spent
    if not (CAPA_BIN or DIE_BIN) or ext_runs >= EXT_MAX:
        return
    if DEADLINE is not None and time.monotonic() > DEADLINE:
        return
    if _ext_timeout() == 0:
        return
    ext_runs += 1
    seen = set()
    if CAPA_BIN:
        try:
            big = CAPA_MAX_MB > 0 and os.path.getsize(path) > CAPA_MAX_MB * 1048576
        except OSError:
            big = False
        limit = _ext_timeout()
        if big:
            capa_stats["big"] += 1
            rules = {}
        elif limit == 0:
            rules = {}
        else:
            t_start = time.monotonic()
            try:
                cmd = [CAPA_BIN, "-q", "-j"]
                if os.path.isdir(CAPA_RULES):
                    cmd += ["-r", CAPA_RULES]
                if os.path.isdir(CAPA_SIGS):
                    cmd += ["-s", CAPA_SIGS]
                out, timed_out, why = _run_limited(cmd + CAPA_EXTRA + [path], limit)
                if timed_out:
                    capa_stats["timeout"] += 1
                    capa_stats["fail"] += 1
                    rules = {}
                    capa_stats["why"] = capa_stats["why"] or ("last output before the cut-off: " + why if why else "")
                else:
                    rules = (json.loads(out).get("rules") or {}) if out.strip() else {}
                    if out.strip():
                        capa_stats["ok"] += 1
                        capa_stats["names"].update(rules.keys())
                        for _r in rules.values():
                            _ns = (((_r or {}).get("meta") or {}).get("namespace") or "other")
                            capa_stats["ns"][_ns.split("/")[0]] += 1
                    else:
                        capa_stats["fail"] += 1
                        capa_stats["why"] = capa_stats["why"] or ("capa said: " + why if why else "capa printed nothing")
            except (OSError, subprocess.SubprocessError, ValueError, AttributeError):
                rules = {}
                capa_stats["fail"] += 1
            ext_spent += time.monotonic() - t_start
        for rule in rules.values():
            ns = (((rule or {}).get("meta") or {}).get("namespace") or "")
            for prefixes, kind in CAPA_KINDS:
                if ns.startswith(prefixes) and kind not in seen:
                    seen.add(kind)
                    add(kind, rel)
    if DIE_BIN:
        limit = _ext_timeout()
        out = ""
        if limit:
            t_start = time.monotonic()
            try:
                out, _t, _w = _run_limited([DIE_BIN, path], limit)
            except (OSError, subprocess.SubprocessError):
                out = ""
            ext_spent += time.monotonic() - t_start
        if DIE_PACKED.search(out):
            add("die_packed", rel)


def main():
    args = sys.argv[1:]
    if not args:
        print("usage: wq-prescan.py <game-dir> [--start <relative exe>]", file=sys.stderr)
        return 2
    gamedir = args[0]
    start = args[args.index("--start") + 1] if "--start" in args and args.index("--start") + 1 < len(args) else ""
    root = os.path.join(gamedir, "game")
    if not os.path.isdir(root):
        print("no game/ folder in %s" % gamedir, file=sys.stderr)
        return 2
    try:
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    skipped_files = 0
    t0 = time.monotonic()
    global DEADLINE
    DEADLINE = t0 + TIME_CAP
    ind.reset_budget()
    timed_out = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if time.monotonic() - t0 > TIME_CAP:
            timed_out = True
            break
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            ext = os.path.splitext(fn)[1].lower()
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not os.path.isfile(path) or os.path.islink(path):
                continue
            if DOUBLE_EXT.search(fn):
                add("double_ext", rel)
            if HIDDEN_NAME.search(rel):
                add("odd_name", rel)
            if ext in SCRIPTLIKE_EXT:
                add("scriptlike", rel)
            is_start = start and rel == start
            stem = os.path.splitext(fn)[0]
            if ext in ind.SCRIPT_EXT or ext in PE_EXT or st.st_mode & 0o111:
                if MAL_NAME.search(stem):
                    add("mal_name", rel)
                elif NAME_WEAK.search(stem):
                    add("mal_name_weak", rel)
            if ext == ".sh" or (is_start and ext not in PE_EXT):
                check_script(path, rel)
            if ext in ind.SCRIPT_EXT and st.st_size <= (8 << 20):
                check_strings(path, rel, st.st_size)
            if ext not in PE_EXT and ext not in ASSET_EXT and st.st_size >= 4 and not is_start:
                try:
                    with open(path, "rb") as f:
                        magic = f.read(4)
                    is_elf = magic == b"\x7fELF"
                    is_shebang = magic[:2] == b"#!"
                    is_text = ext in ind.TEXT_EXT or (ext == "" and not is_elf and st.st_size <= ind.TEXT_MAX_BYTES and _looks_text(path))
                    if is_elf:
                        if not ELF_SKIP.match(fn):
                            check_strings(path, rel, st.st_size)
                            run_external(path, rel)
                    elif (is_text or is_shebang or ext in ind.SCRIPT_EXT) and st.st_size <= ind.TEXT_MAX_BYTES:
                        if (is_shebang or ext in ind.SCRIPT_EXT) and ext != ".sh":
                            check_script(path, rel)
                        if ext not in ind.SCRIPT_EXT:
                            check_strings(path, rel, st.st_size)
                except (OSError, ValueError):
                    pass
            try:
                if ext in PE_EXT or is_start:
                    info = parse_pe(path, st.st_size)
                    if info:
                        check_pe(rel, info)
                        check_strings(path, rel, st.st_size, want_embedded=True)
                        run_external(path, rel)
                elif ext in DATA_EXT and st.st_size >= 4:
                    with open(path, "rb") as f:
                        magic = f.read(4)
                    if magic[:2] == b"MZ" or magic == b"\x7fELF":
                        add("disguised", rel)
                elif st.st_mode & 0o111 and st.st_size >= 4:
                    with open(path, "rb") as f:
                        blob = f.read(4096)
                    if blob[:4] == b"\x7fELF" and b"UPX!" in blob:
                        add("packer_upx", rel)
            except (OSError, struct.error, ValueError):
                continue
            except Exception:
                skipped_files += 1
                continue

    # --- YARA Log Scanner ---
    check_yara_logs(gamedir)

    # --- ATT&CK T1059.004: Cumulative shell abuse detection ---
    chain_score = 0
    chain_reasons = []
    if "shell_net" in findings:
        chain_score += 2
        chain_reasons.append("network")
    if "shell_persist" in findings or "ind_linux_persist" in findings:
        chain_score += 2
        chain_reasons.append("persistence")
    if "ind_linux_dropper" in findings or "script_decode_exec" in findings:
        chain_score += 1
        chain_reasons.append("dropper")
    if chain_score >= 3:
        add("attack_chain_t1059", "cumulative shell abuse: " + "+".join(chain_reasons))
    # -----------------------------------------------------------

    msgs = {
        "double_ext": "file posing as a document or image: %s",
        "odd_name": "file name uses hidden or direction-changing characters (a way to fake an extension): %s",
        "inject": "imports for injecting code into other processes: %s",
        "dropper": "imports to download a file and run it: %s",
        "shell_net": "script pipes a download into a shell or opens a raw network socket: %s",
        "packed_entropy": "executable code looks packed or encrypted: %s",
        "packer_protect": "protected with a commercial packer/virtualiser: %s",
        "disguised": "program stored under a document/image/data file name: %s",
        "scriptlike": "screensaver/HTA/VBS-type file: %s",
        "shell_persist": "script touches startup files, cron, ssh keys or system accounts: %s",
        "packer_upx": "UPX-packed: %s",
        "capa_persist": "capa: startup/persistence behaviour in: %s",
        "capa_keylog": "capa: keylogging behaviour in: %s",
        "capa_cred": "capa: browser/password/credential theft behaviour in: %s",
        "capa_destroy": "capa: disk-wipe or system-recovery-destroying behaviour in: %s",
        "capa_c2": "capa: command-and-control communication behaviour in: %s",
        "capa_inject": "capa: process-injection behaviour in: %s",
        "capa_exec": "capa: process-spawning behaviour in: %s",
        "capa_write": "capa: file-system-write behaviour in: %s",
        "capa_net": "capa: network-socket behaviour in: %s",
        "big_blob": "large block of encrypted or compressed data appended to the program (a way to hide a payload): %s",
        "dotnet_framework": ".NET Framework program: Wine's built-in Mono may not run it (a crash like 'Invalid IL code' means that; real .NET needs winetricks dotnet48 in a throwaway prefix): %s (informational)",
        "dotnet_protected": ".NET program with encrypted/compressed code, likely obfuscated or packed (try de4dot, then ILSpy, instead of running it): %s (informational)",
        "pe_wx_section": "program has a section that is both writable and executable (self-modifying or unpacking code): %s",
        "pe_unpack_stub": "program has code space that is empty on disk and filled in at run time (an unpacking stub): %s",
        "pe_odd_entry": "program starts running in an unusual place (typical of packers and loaders): %s",
        "pe_thin_imports": "program imports almost nothing except what is needed to load more code (typical of a packed or encrypted payload): %s",
        "pe_embedded": "another Windows program is stored inside this one (a way to carry a payload; some installers do this too): %s",
        "ind_c2_service": "references a web service often used to receive stolen data or give orders to malware (webhook, bot API, paste site, tunnel, .onion): %s",
        "ind_stealer": "mentions several places where browsers, wallets, chat apps or Steam keep logins (credential-stealer pattern): %s",
        "ind_ransom": "contains ransomware wording or commands that delete backups and shadow copies: %s",
        "ind_lolbin": "contains a command that downloads, hides or runs code through a built-in Windows tool, or switches off Defender: %s",
        "ind_persist": "contains a way to start itself at login (Run key, scheduled task, Startup folder, UAC bypass): %s",
        "ind_anti_analysis": "checks whether it is being watched (virtual machine, sandbox, Wine, analysis tools): %s (informational: the run may not show its real behaviour)",
        "ind_payload_desc": "says in plain words that it is an attack tool (reverse shell, meterpreter, mimikatz, miner pool, 'this payload ...'): %s",
        "ind_revshell": "contains the code of a reverse or bind shell (bash /dev/tcp, nc -e, mkfifo, socat exec, python/perl/php/ruby/node socket + shell): %s",
        "ind_linux_dropper": "downloads or decodes code and runs it (curl|sh, base64 -d|sh, exec(b64decode()), memfd exec, chmod +x in /tmp): %s",
        "ind_linux_persist": "writes itself into crontab, shell startup files, authorized_keys, ld.so.preload, autostart or a systemd user unit: %s",
        "script_decode_exec": "script decodes data and runs it (exec/eval of base64, marshal or zlib output): %s",
        "fork_bomb": "script contains a fork bomb or an endless process-spawning loop: %s",
        "mal_name": "file named like an attack tool (reverse shell, keylogger, backdoor, stealer, ransomware ...): %s",
        "mal_name_weak": "script or program named like an attack stage (payload, exploit, dropper, beacon, spawner ...): %s (informational)",
        "ind_rat_words": "contains words typical of a remote-access tool or botnet builder (several of keylogger, reverse shell, hvnc, ddos, stealer ...): %s",
        "die_packed": "Detect It Easy: packer or protector identified in: %s (informational)",
        "yara_vmdetect": "YARA flagged anti-analysis/VM detection behavior (e.g., MAC OUI, timing checks): %s",
        "yara_encrypted": "YARA flagged encrypted/obfuscated payloads (e.g., base64, XOR): %s",
        "yara_ransomware": "YARA flagged ransomware behavior (e.g., shadow copy deletion, file encryption): %s",
        "attack_chain_t1059": "cumulative ATT&CK T1059.004 pattern (shell execution chained with network/persistence/dropper behavior): %s",
    }
    for kind, ex in findings.items():
        more = counts[kind] - len(ex)
        listing = ", ".join(ex) + (" (+%d more)" % more if more > 0 else "")
        print("FINDING\t%s\t%d\t%s" % (kind, POINTS[kind], msgs[kind] % listing))
    if skipped_files:
        print("INFO\t%d file(s) could not be analysed (the checker hit an unexpected error); they were skipped" % skipped_files)
    if timed_out:
        print("FINDING\ttime_cap\t0\tstopped after %ds, the rest of the folder was not checked" % TIME_CAP)
    if CAPA_BIN:
        if capa_stats["ok"] + capa_stats["fail"] + capa_stats["big"] == 0:
            print("INFO\tcapa: installed, no Windows executable in game/ to analyse")
        else:
            msg = "capa: analysed %d PE file(s), %d behaviour rule(s) matched" % (capa_stats["ok"], len(capa_stats["names"]))
            if capa_stats["ns"]:
                msg += " (%s)" % ", ".join("%s %d" % kv for kv in capa_stats["ns"].most_common(6))
            if capa_stats["fail"]:
                msg += ". capa gave NO result for %d file(s)" % capa_stats["fail"]
                if capa_stats["timeout"]:
                    msg += " (%d of them ran out of time: %gs per file, %gs in all; raise PRESCAN_EXTERNAL_TIMEOUT / PRESCAN_EXTERNAL_BUDGET, or untick 'capa behaviour scan')" % (capa_stats["timeout"], EXT_TIMEOUT, EXT_BUDGET)
                if capa_stats["why"]:
                    msg += " [%s]" % capa_stats["why"]
                msg += ": run ./wq-scan-probe.sh to see where capa stalls"
            if capa_stats["big"]:
                msg += ". %d file(s) over %gMB were not given to capa (PRESCAN_CAPA_MAX_MB)" % (capa_stats["big"], CAPA_MAX_MB)
            print("INFO\t" + msg)
    print("SCORE\t%d\t%s" % (sum(POINTS[k] for k in findings), ",".join(sorted(findings))))
    return 0


if __name__ == "__main__":
    try:
        _rc = main()
    except SystemExit:
        raise
    except BaseException as _e:
        try:
            print("ERROR\t%s" % _safe(type(_e).__name__))
            sys.stdout.flush()
        except Exception:
            pass
        sys.exit(3)
    sys.exit(_rc)
