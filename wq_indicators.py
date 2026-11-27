#!/usr/bin/env python3
"""Static malware indicators for wq-prescan.py. Standard library only, nothing is executed."""
from __future__ import annotations

import os
import re
import time

CHUNK = 4 << 20
OVERLAP = 1024
PER_FILE_MAX = int(float(os.environ.get("PRESCAN_STRINGS_MAX_MB", "32")) * (1 << 20))
TOTAL_MAX = int(float(os.environ.get("PRESCAN_STRINGS_BUDGET_MB", "256")) * (1 << 20))
WINDOW_BEFORE, WINDOW_AFTER = 96, 320

CATEGORIES = {
    "c2_service":    (3, 1, ()),
    "stealer":       (3, 2, ()),
    "ransom":        (3, 2, ("shadow_delete", "backup_delete", "recovery_off", "ransom_note")),
    "lolbin":        (3, 1, ()),
    "persist":       (1, 1, ()),
    "anti_analysis": (1, 2, ()),
    "rat_words":     (2, 2, ()),
    "payload_desc":  (3, 1, ()),
    "revshell":      (3, 1, ()),
    "linux_dropper": (3, 1, ()),
    "linux_persist": (2, 1, ()),
}

_I = []

def _add(cat, fam, anchor, rx=None):
    _I.append((cat, fam, anchor.encode(), re.compile(rx.encode()) if rx else None))

# -- places that receive stolen data or give orders -------------------------------------------------
_add("c2_service", "discord_webhook", "/api/webhooks/", r"discord(?:app)?\.com/api/webhooks/\d")
_add("c2_service", "telegram_bot", "api.telegram.org/bot")
_add("c2_service", "paste_site", "pastebin.com/raw")
_add("c2_service", "paste_site", "paste.ee/r/")
_add("c2_service", "paste_site", "hastebin.com/raw")
_add("c2_service", "file_drop", "transfer.sh/")
_add("c2_service", "file_drop", "anonfiles.com")
_add("c2_service", "file_drop", "gofile.io/", r"gofile\.io/(?:uploadfile|api|d/)")
_add("c2_service", "tunnel_ddns", "ngrok", r"ngrok(?:-free)?\.(?:io|app|dev)")
_add("c2_service", "tunnel_ddns", "trycloudflare.com")
_add("c2_service", "tunnel_ddns", "serveo.net")
_add("c2_service", "tunnel_ddns", "duckdns.org")
_add("c2_service", "tunnel_ddns", "no-ip.", r"no-ip\.(?:com|org|biz|info)")
_add("c2_service", "tunnel_ddns", "ddns.net")
_add("c2_service", "tunnel_ddns", "hopto.org")
_add("c2_service", "tunnel_ddns", "zapto.org")
_add("c2_service", "tunnel_ddns", "sytes.net")
_add("c2_service", "tor_hidden_service", ".onion", r"[a-z2-7]{16,56}\.onion\b")

# -- credential and wallet theft ---------------------------------------------------------------------
_add("stealer", "chromium_masterkey", "os_crypt")
_add("stealer", "chromium_masterkey", "encrypted_key", r"\"?encrypted_key\"?\s*:")
_add("stealer", "chromium_profile", "user data", r"(?:chrome|edge|brave|vivaldi|chromium|opera)[^\n]{0,24}user data")
_add("stealer", "chromium_profile", "login data", r"\blogin data\b")
_add("stealer", "firefox_profile", "logins.json")
_add("stealer", "firefox_profile", "key4.db")
_add("stealer", "firefox_profile", "cookies.sqlite")
_add("stealer", "firefox_profile", "signons.sqlite")
_add("stealer", "dpapi", "cryptunprotectdata")
_add("stealer", "crypto_wallet", "wallet.dat")
_add("stealer", "crypto_wallet", "exodus", r"exodus[\\/]{1,2}(?:exodus\.wallet|\w)|\\exodus\b")
_add("stealer", "crypto_wallet", "electrum", r"electrum[\\/]{1,2}wallets|\\electrum\b")
_add("stealer", "crypto_wallet", "metamask")
_add("stealer", "crypto_wallet", "nkbihfbeogaeaoehlefnkodbefgpgknn")
_add("stealer", "crypto_wallet", "coinomi")
_add("stealer", "discord_token", "dqw4w9wgxcq:")
_add("stealer", "discord_token", "leveldb", r"(?:discord|discordcanary|discordptb)[^\n]{0,40}local storage[\\/]{1,2}leveldb")
_add("stealer", "steam_session", "ssfn", r"ssfn[\d\*?]")
_add("stealer", "steam_session", "loginusers.vdf")
_add("stealer", "telegram_session", "tdata", r"telegram desktop[\\/]{1,2}tdata")
_add("stealer", "ftp_credentials", "recentservers.xml")
_add("stealer", "ftp_credentials", "sitemanager.xml")

_add("stealer", "chromium_profile", ".config/google-chrome")
_add("stealer", "chromium_profile", ".config/chromium")
_add("stealer", "chromium_profile", ".config/bravesoftware")
_add("stealer", "firefox_profile", ".mozilla/firefox")
_add("stealer", "ssh_keys", ".ssh/id_rsa")
_add("stealer", "ssh_keys", ".ssh/id_ed25519")
_add("stealer", "ssh_keys", ".ssh/id_ecdsa")
_add("stealer", "gnupg", ".gnupg/")
_add("stealer", "cloud_creds", ".aws/credentials")
_add("stealer", "cloud_creds", ".kube/config")
_add("stealer", "cloud_creds", ".config/gcloud")
_add("stealer", "shell_history", ".bash_history")
_add("stealer", "crypto_wallet", ".electrum/wallets")
_add("stealer", "crypto_wallet", ".bitcoin/wallet.dat")
_add("stealer", "discord_token", ".config/discord/local storage")
_add("stealer", "keyring", ".local/share/keyrings")

# -- blunt self-description ---------------------------------------------------------------------------
_add("payload_desc", "reverse_shell", "reverse shell", r"reverse[ _-]?shell")
_add("payload_desc", "reverse_shell", "revshell")
_add("payload_desc", "meterpreter", "meterpreter")
_add("payload_desc", "mimikatz", "mimikatz")
_add("payload_desc", "miner", "stratum+tcp://")
_add("payload_desc", "miner", "stratum+ssl://")
_add("payload_desc", "miner", "xmrig")
_add("payload_desc", "malware_self_description", "this payload",
     r"this (?:payload|malware|trojan|backdoor|rat|stealer)\b[^\n]{0,40}\b(?:steal|install|encrypt|connect|exfiltrat|keylog|persist|infect)")

# -- Linux: reverse / bind shell (expanded for Falco-style detection) ---------------------------------
_add("revshell", "bash_dev_tcp", "/dev/tcp/", r"(?:bash|sh|exec|0<&\d+|>&)[^\n]{0,60}/dev/(?:tcp|udp)/[^\n/]{1,60}/\d")
_add("revshell", "bash_dev_tcp", "/dev/udp/", r"(?:bash|sh|exec|0<&\d+|>&)[^\n]{0,60}/dev/(?:tcp|udp)/[^\n/]{1,60}/\d")
for _a in (" -e /bin/sh", " -e /bin/bash", " -e sh", " -e bash", " -c sh", " -c bash", "--exec"):
    _add("revshell", "nc_exec", _a, r"\b(?:nc|ncat|netcat)\b[^\n]{0,80}(?:\s-[ec]\s*(?:/bin/)?(?:ba|da|z)?sh\b|--exec)")
_add("revshell", "mkfifo_nc", "mkfifo", r"mkfifo[^\n]{0,120}\b(?:nc|ncat|netcat|telnet|openssl)\b")
_add("revshell", "socat_exec", "socat", r"socat[^\n]{0,120}exec:[^\n]{0,40}(?:ba|da|z)?sh|socat[^\n]{0,60}(?:ba|da|z)?sh[^\n]{0,60}tcp")
_add("revshell", "python_revshell", "dup2(", r"socket[\s\S]{0,200}dup2\([^)]{0,40}fileno")
_add("revshell", "python_revshell", "pty.spawn", r"socket[\s\S]{0,200}pty\.spawn")
_add("revshell", "php_revshell", "fsockopen", r"fsockopen[\s\S]{0,300}(?:proc_open|shell_exec|passthru|exec|system)\(|proc_open[\s\S]{0,200}fsockopen")
_add("revshell", "ruby_revshell", "tcpsocket.new", r"tcpsocket\.new[\s\S]{0,300}(?:exec|spawn|popen|/bin/(?:ba)?sh)")
_add("revshell", "perl_revshell", "socket(", r"socket\([^)]*\)[\s\S]{0,300}(?:exec\s*\(?\s*[\"']/bin/|open\(\s*stdin)")
_add("revshell", "node_revshell", "child_process", r"(?:net\.socket|net\.connect)[\s\S]{0,300}child_process|child_process[\s\S]{0,300}(?:net\.socket|net\.connect)")
_add("revshell", "sh_interactive", "sh -i", r"/bin/(?:ba|da|z)?sh\s+-i\b[^\n]{0,40}(?:2>&1|<&|>&)[^\n]{0,40}(?:nc|ncat|netcat|/dev/tcp)")
_add("revshell", "interpreter_socket_shell", "socket",
     r"(?:python|perl|ruby|node|php)[\s\S]{0,500}(?:socket|net\.connect|fsockopen)[\s\S]{0,500}(?:pty\.spawn|dup2|/bin/(?:ba)?sh|child_process)")

# -- Linux: downloaders, decoders, fileless execution --------------------------------------------------
_add("linux_dropper", "pipe_to_shell", "curl", r"\bcurl\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
_add("linux_dropper", "pipe_to_shell", "wget", r"\bwget\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
_add("linux_dropper", "decode_pipe", "base64", r"base64\s+(?:-d|--decode)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
_add("linux_dropper", "decode_exec", "b64decode", r"\b(?:exec|eval)\s*\(\s*(?:[a-z_.]*decompress\(\s*)?(?:base64\.)?b64decode|\bmarshal\.loads\(\s*(?:base64\.)?b64decode")
_add("linux_dropper", "decode_exec", "marshal.loads", r"\b(?:exec|eval)\s*\(\s*marshal\.loads|\bmarshal\.loads\(\s*(?:zlib\.)?(?:decompress|b64decode)")
_add("linux_dropper", "fileless_exec", "memfd_create", r"memfd_create[\s\S]{0,300}/proc/self/fd/")
_add("linux_dropper", "tmp_exec", "chmod +x",
     r"(?:curl|wget)[^\n]{0,200}(?:-o|>)\s*/(?:tmp|dev/shm|var/tmp)/[^\n]{0,120}chmod\s+\+x"
     r"|chmod\s+\+x\s+/(?:tmp|dev/shm|var/tmp)/\S+\s*(?:&&|;)\s*/(?:tmp|dev/shm|var/tmp)/")
# Phantom/Poltergeist-style: pure bash hex/XOR decode loops
_add("linux_dropper", "bash_hex_xor", "for",
     r"for\s*\([^)]*\)[^\n]{0,200}(?:16#|\^|\bxor\b)")
_add("linux_dropper", "bash_xor_print", "printf",
     r"printf[^\n]{0,100}\\\\(?:[0-7]{3}|x[0-9a-f]{2})[^\n]{0,100}\b(?:for|eval|while|bash)\b")
# V2 evasion: raw sockets / process masquerading
_add("linux_dropper", "masquerade", "exec -a", r"exec\s+-a\s+['\"]?[a-zA-Z0-9_-]+['\"]?\s+")
_add("linux_dropper", "setsid_hide", "setsid", r"\bsetsid\b[^\n]{0,200}\bexec\s+-a\b")
_add("linux_dropper", "self_destruct", "dd", r"\bdd\b[^\n]{0,100}\bof=[\"']?\$0")

# -- Linux: persistence (expanded for ATT&CK T1546) ---------------------------------------------------
_add("linux_persist", "cron", "crontab", r"(?:echo|printf|cat)[^\n]{0,200}\|\s*crontab\s+-|\(\s*crontab\s+-l[^\n]{0,40}\)\s*\|\s*crontab")
_add("linux_persist", "ssh_keys", "authorized_keys", r"\b(?:echo|printf|cat)\b[^\n]{0,200}(?:>>?|\btee(?:\s+-a)?)\s*\S*authorized_keys")
_add("linux_persist", "shell_rc", ".bashrc", r"\b(?:echo|printf|cat)\b[^\n]{0,200}>>\s*\S*(?:\.bashrc|\.zshrc|\.bash_profile|\.profile)\b")
_add("linux_persist", "shell_rc", ".zshrc", r"\b(?:echo|printf|cat)\b[^\n]{0,200}>>\s*\S*(?:\.bashrc|\.zshrc|\.bash_profile|\.profile)\b")
_add("linux_persist", "ld_preload", "ld.so.preload", r"(?:>>?|\btee(?:\s+-a)?|\bcp\b|\bln\b)\s*\S*/etc/ld\.so\.preload")
_add("linux_persist", "autostart", ".config/autostart", r"(?:>>?|\btee(?:\s+-a)?)\s*\S*\.config/autostart/\S*\.desktop|\bcp\s[^\n]{0,80}\.config/autostart")
_add("linux_persist", "systemd_user", "systemctl --user", r"systemctl\s+--user\s+(?:enable|daemon-reload)")
_add("linux_persist", "systemd_user_write", "systemd/user",
     r"(?:>>?|\btee(?:\s+-a)?|\bcp\b)\s*\S*\.config/systemd/user/\S*\.(?:service|timer)")
_add("linux_persist", "xdg_desktop_write", ".local/share",
     r"(?:>>?|\btee(?:\s+-a)?|\bcp\b)\s*\S*\.local/share/\S*\.desktop")

# -- ransomware ---------------------------------------------------------------------------------------
_add("ransom", "shadow_delete", "vssadmin", r"vssadmin(?:\.exe)?\s+delete\s+shadows")
_add("ransom", "shadow_delete", "shadowcopy", r"wmic[^\n]{0,24}shadowcopy\s+delete")
_add("ransom", "recovery_off", "bcdedit", r"bcdedit[^\n]{0,48}recoveryenabled\s+no")
_add("ransom", "backup_delete", "wbadmin", r"wbadmin\s+delete\s+(?:catalog|systemstatebackup|backup)")
_add("ransom", "ransom_note", "files have been encrypted", r"(?:your|all)[^\n]{0,24}files (?:have been|are|were) encrypted")
_add("ransom", "ransom_note", "files are encrypted")
_add("ransom", "ransom_word", "ransom", r"\bransom(?:ware)?\b")
_add("ransom", "payment_word", "bitcoin", r"\bbitcoin\b|\bmonero\b")
_add("ransom", "decrypt_word", "decrypt", r"decrypt your files|\bdecryptor\b|decryption tool")

# -- living-off-the-land droppers ---------------------------------------------------------------------
_add("lolbin", "powershell_abuse", "powershell",
     r"powershell(?:\.exe)?[^\n]{0,80}?(?:-e(?:nc(?:odedcommand)?)?\s+[a-z0-9+/=]{20,}"
     r"|-w(?:indowstyle)?\s+hidden|-ep\s+bypass|-executionpolicy\s+bypass)")
_add("lolbin", "certutil_download", "certutil", r"certutil(?:\.exe)?\s+[^\n]{0,40}-(?:urlcache|decode)")
_add("lolbin", "bitsadmin_download", "bitsadmin", r"bitsadmin[^\n]{0,40}/transfer")
_add("lolbin", "mshta_remote", "mshta", r"mshta(?:\.exe)?\s+(?:https?|vbscript|javascript):")
_add("lolbin", "regsvr32_remote", "regsvr32", r"regsvr32[^\n]{0,40}/i:https?://")
_add("lolbin", "defender_tamper", "add-mppreference", r"add-mppreference\s+-exclusion(?:path|extension|process)")
_add("lolbin", "defender_tamper", "disablerealtimemonitoring")

# -- persistence (Windows) ----------------------------------------------------------------------------
_add("persist", "run_key", "currentversion", r"currentversion[\\/]{1,2}run(?:once)?(?![a-z])")
_add("persist", "scheduled_task", "schtasks", r"schtasks(?:\.exe)?\s+/create")
_add("persist", "startup_folder", "start menu", r"start menu[\\/]{1,2}programs[\\/]{1,2}startup")
_add("persist", "uac_bypass", "ms-settings", r"classes[\\/]{1,2}ms-settings[\\/]{1,2}shell")
_add("persist", "uac_bypass", "fodhelper.exe")

# -- anti-analysis checks -----------------------------------------------------------------------------
_add("anti_analysis", "vm_check", "vboxservice")
_add("anti_analysis", "vm_check", "vboxguest")
_add("anti_analysis", "vm_check", "vmtoolsd")
_add("anti_analysis", "sandbox_check", "sbiedll.dll")
_add("anti_analysis", "sandbox_check", "cuckoomon")
_add("anti_analysis", "sandbox_check", "joeboxcontrol")
_add("anti_analysis", "wine_check", "wine_get_version")
_add("anti_analysis", "wine_check", "wine_get_unix_file_name")
_add("anti_analysis", "analysis_tools", "wireshark", r"\bwireshark\b")
_add("anti_analysis", "analysis_tools", "processhacker")
_add("anti_analysis", "analysis_tools", "x64dbg")
_add("anti_analysis", "analysis_tools", "ollydbg")
_add("anti_analysis", "analysis_tools", "procmon", r"\bprocmon(?:64)?\b")

# -- RAT builder words --------------------------------------------------------------------------------
_add("rat_words", "keylogger", "keylogger")
_add("rat_words", "hvnc", "hvnc")
_add("rat_words", "ddos", "ddos", r"\bddos\b|\bflood(?:er|ing)?\b[^\n]{0,12}\b(?:udp|tcp|http)\b")
_add("rat_words", "botnet", "botnet")
_add("rat_words", "clipper", "clipper", r"\bclipper\b|clipboard[^\n]{0,20}(?:wallet|address)")
_add("rat_words", "uac_bypass_word", "uac bypass", r"(?:bypass|disable)[ _-]?uac|uac[ _-]?bypass")
_add("rat_words", "process_hollowing", "hollowing", r"process[ _-]?hollowing")
_add("rat_words", "stealer_word", "stealer", r"\bstealer\b|\bpassword[ _-]?recovery\b")
_add("rat_words", "remote_desktop", "remote desktop", r"remote[ _-]?(?:desktop|webcam|microphone)")

SCRIPT_EXT = {".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".py",
              ".pl", ".pm", ".rb", ".php", ".lua"}
TEXT_EXT = {".txt", ".md", ".rst", ".cfg", ".conf", ".ini", ".json", ".yml", ".yaml", ".xml", ".html", ".htm", ".log", ".desktop", ".service"}
TEXT_MAX_BYTES = 2 << 20
ANCHORS = sorted({a for _c, _f, a, _r in _I}, key=len, reverse=True)
_BY_ANCHOR: dict[bytes, list] = {}
for _c, _f, _a, _r in _I:
    _BY_ANCHOR.setdefault(_a, []).append((_c, _f, _r))
_MZ = re.compile(rb"MZ")


def _scan_view(view: bytes, hits: dict, rel_hits: set) -> None:
    for anchor in ANCHORS:
        start, tries = 0, 0
        while tries < 12:
            pos = view.find(anchor, start)
            if pos < 0:
                break
            tries += 1
            start = pos + len(anchor)
            window = view[max(0, pos - WINDOW_BEFORE): pos + len(anchor) + WINDOW_AFTER]
            for cat, fam, rx in _BY_ANCHOR[anchor]:
                if (cat, fam) in hits:
                    continue
                if rx is None or rx.search(window):
                    hits[(cat, fam)] = True


def _spans(size: int):
    if size <= PER_FILE_MAX:
        yield 0, size
    else:
        half = PER_FILE_MAX // 2
        yield 0, half
        yield size - half, size


_budget = {"left": TOTAL_MAX}


def reset_budget() -> None:
    _budget["left"] = TOTAL_MAX


def embedded_pe_count(buf: bytes, base_offset: int, whole: bytes | None = None) -> int:
    n = 0
    for m in _MZ.finditer(buf):
        off = m.start()
        if base_offset + off == 0 or off + 0x40 > len(buf):
            continue
        e_lfanew = int.from_bytes(buf[off + 0x3C: off + 0x40], "little")
        if 0x40 <= e_lfanew <= 0x400 and off + e_lfanew + 4 <= len(buf) and buf[off + e_lfanew: off + e_lfanew + 4] == b"PE\0\0":
            n += 1
            if n >= 8:
                break
    return n


def scan_file(path: str, size: int, deadline: float | None = None, want_embedded: bool = False):
    hits: dict = {}
    embedded = 0
    if size <= 0 or _budget["left"] <= 0:
        return {}, 0
    try:
        with open(path, "rb") as f:
            for lo, hi in _spans(size):
                pos, tail = lo, b""
                while pos < hi:
                    if deadline is not None and time.monotonic() > deadline:
                        raise TimeoutError
                    n = min(CHUNK, hi - pos)
                    f.seek(pos)
                    raw = f.read(n)
                    if not raw:
                        break
                    pos += len(raw)
                    _budget["left"] -= len(raw)
                    data = tail + raw
                    low = data.lower()
                    _scan_view(low, hits, set())
                    if b"\0" in low:
                        _scan_view(low.replace(b"\0", b""), hits, set())
                    if want_embedded and embedded < 8:
                        embedded += embedded_pe_count(data, pos - len(raw) - len(tail))
                    tail = data[-OVERLAP:]
                    if _budget["left"] <= 0:
                        break
                if _budget["left"] <= 0:
                    break
    except (OSError, TimeoutError):
        pass
    found: dict[str, set] = {}
    for (cat, fam) in hits:
        found.setdefault(cat, set()).add(fam)
    out = {}
    for cat, fams in found.items():
        points, need, strong = CATEGORIES[cat]
        weak = {f for f in fams if f not in strong}
        if (fams & set(strong)) or len(weak) >= need:
            out[cat] = sorted(fams)
    return out, embedded


def pe_structure_flags(sections, entry_rva: int, imports: set, dotnet: bool, size: int) -> dict:
    EXEC, WRITE = 0x20000000, 0x80000000
    out = {}
    if not sections:
        return out
    for name, _vs, _va, _rs, _rp, fl in sections:
        if fl & EXEC and fl & WRITE:
            out["pe_wx_section"] = "section %s is writable and executable" % name
            break
    for name, vs, _va, rs, _rp, fl in sections:
        if fl & EXEC and rs == 0 and vs >= 0x10000:
            out["pe_unpack_stub"] = "section %s is empty on disk but %d KiB in memory" % (name, vs // 1024)
            break
    if entry_rva:
        host = None
        for i, (name, vs, va, rs, _rp, fl) in enumerate(sections):
            if va <= entry_rva < va + max(vs, rs):
                host = (i, name, fl)
                break
        last = len(sections) - 1
        if host is None:
            out["pe_odd_entry"] = "entry point is outside every section"
        elif not host[2] & EXEC:
            out["pe_odd_entry"] = "entry point is in %s, which is not executable" % host[1]
        elif host[0] == last and host[2] & WRITE and len(sections) >= 3:
            out["pe_odd_entry"] = "entry point is in the last, writable section %s" % host[1]
    if (not dotnet) and size >= 65536 and imports and len(imports) <= 5 \
            and imports <= {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getprocaddress",
                            "virtualalloc", "virtualprotect", "virtualfree", "exitprocess", "getmodulehandlea",
                            "getmodulehandlew"}:
        out["pe_thin_imports"] = "only %d imported function(s), all for loading more code" % len(imports)
    return out
