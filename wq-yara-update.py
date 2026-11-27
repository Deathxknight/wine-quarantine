#!/usr/bin/env python3
"""wq-yara-update.py [--force] [--zip FILE] [--url URL] [--dest DIR] [--min-hours N] [--dry-run]

Fetches the public YARAhub rules (abuse.ch, https://yaraify.abuse.ch/yarahub/) and stores the usable ones
under _yara-feeds/yarahub/ next to this script. wq-yara-build.sh picks that folder up automatically, so the
next scan rebuilds the ruleset with them. Nothing is bundled: the rules are downloaded by you, and every rule
keeps its own yarahub_license / author meta.

YARAhub is community-submitted, so the zip is treated as untrusted input:
  * downloaded over HTTPS only, with a size limit; abuse.ch asks for no more than one fetch per 5 minutes,
    and this script waits --min-hours (default 24) between fetches unless --force is given
  * zip entries are never extracted by path: only *.yar / *.yara names are read, as data, and written under a
    sanitised flat file name (no path traversal, no zip bombs: entry count, entry size and total size are capped)
  * a rule file is rejected (and listed in REJECTED.txt) when it uses "include", imports a module other than
    pe, elf, math or hash, is not valid UTF-8 text, or is too large
  * the new set replaces the old one only when at least one file survives; the previous set is kept as
    yarahub.prev, so a bad download never leaves you with an empty ruleset

Optional: ABUSECH_AUTH_KEY in the environment is sent as the Auth-Key header (the YARAify API asks for one;
the rules download behind the YARAhub page's button needs no key, so it is only sent when you set it).

Exit: 0 updated, or nothing to do (fresh enough); 1 failed (the old rules stay in place); 2 usage error.
Stdlib only.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
import zipfile

# The "Download all YARA rules" button on https://yaraify.abuse.ch/yarahub/ links to the first one. No key needed.
# The second is the API host's copy, tried only when the first fails.
DEFAULT_URLS = ["https://yaraify.abuse.ch/yarahub/yaraify-rules.zip",
                "https://yaraify-api.abuse.ch/download/yaraify-rules.zip"]
HERE = os.path.dirname(os.path.realpath(__file__))
FEEDS = os.path.join(HERE, "_yara-feeds")

MAX_ZIP_BYTES = 200 * 1024 * 1024        # the download itself
MAX_TOTAL_BYTES = 800 * 1024 * 1024      # all entries together, uncompressed
MAX_ENTRIES = 200000
MAX_RULE_BYTES = 1024 * 1024             # one rule file
FLOOR_SECONDS = 15 * 60                  # never fetch more often than this, even with --force
ALLOWED_IMPORTS = {"pe", "elf", "math", "hash"}

IMPORT_RE = re.compile(r'(?m)^[ \t]*import[ \t]+"([^"]*)"')
INCLUDE_RE = re.compile(r'(?m)^[ \t]*include[ \t]+"')
RULE_RE = re.compile(r'(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+[A-Za-z_]')
LICENSE_RE = re.compile(r'\byarahub_license\s*=\s*"([^"]*)"')
SAFE_NAME_RE = re.compile(r'[^A-Za-z0-9._-]+')


def say(msg):
    print("wq-yara-update: " + msg)


def fail(msg):
    print("wq-yara-update: " + msg, file=sys.stderr)
    return 1


def sanitise(member):
    """A flat, safe file name for a zip member, or None when it is not a rule file."""
    base = member.replace("\\", "/").rstrip("/").split("/")[-1]
    if not base.lower().endswith((".yar", ".yara")):
        return None
    base = SAFE_NAME_RE.sub("_", base).lstrip(".")
    return base or None


def check_rule_text(text):
    """None when the rule file is acceptable, else the reason it is not."""
    if INCLUDE_RE.search(text):
        return 'uses "include"'
    for mod in IMPORT_RE.findall(text):
        if mod not in ALLOWED_IMPORTS:
            return 'imports "%s"' % mod
    if not RULE_RE.search(text):
        return "no rule found"
    return None


def read_stamp(dest):
    try:
        with open(os.path.join(dest, ".fetched"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def download(url, auth_key):
    if not url.lower().startswith("https://"):
        raise RuntimeError("refusing a non-HTTPS URL: " + url)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; wine-quarantine-yara-update/2)",
                                               "Accept": "application/zip, */*"})
    if auth_key:
        req.add_header("Auth-Key", auth_key)
    fd, tmp = tempfile.mkstemp(prefix="yarahub-", suffix=".zip")
    size = 0
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(req, timeout=60) as resp:
            ctype = resp.headers.get("Content-Type", "")
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ZIP_BYTES:
                    raise RuntimeError("download is larger than %d MB, giving up" % (MAX_ZIP_BYTES >> 20))
                out.write(chunk)
    except urllib.error.HTTPError as exc:
        os.unlink(tmp)
        raise RuntimeError("%s answered HTTP %s %s" % (url.split("/")[2], exc.code, exc.reason))
    except urllib.error.URLError as exc:
        os.unlink(tmp)
        raise RuntimeError("cannot reach %s (%s)" % (url.split("/")[2], exc.reason))
    except BaseException:
        os.unlink(tmp)
        raise
    if not zipfile.is_zipfile(tmp):
        with open(tmp, "rb") as fh:
            head = fh.read(80).decode("utf-8", "replace").replace("\n", " ").strip()
        os.unlink(tmp)
        raise RuntimeError("%s did not return a zip (%s, %d bytes: %r)" % (url.split("/")[2], ctype or "no content type", size, head))
    return tmp


def download_any(urls, auth_key):
    """First URL that gives a zip wins; if none does, every reason is reported."""
    problems = []
    for url in urls:
        say("downloading " + url)
        try:
            return download(url, auth_key), url
        except RuntimeError as exc:
            problems.append(str(exc))
            say("  failed: %s" % exc)
    raise RuntimeError("; ".join(problems))


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_rules(zip_path, stage):
    """Reads rule files out of the zip into stage/. Returns (kept, rejected[(name, reason)], licenses{})."""
    kept, rejected, licenses = 0, [], {}
    used = set()
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise RuntimeError("the zip lists %d entries (limit %d)" % (len(infos), MAX_ENTRIES))
        for info in infos:
            if info.is_dir():
                continue
            name = sanitise(info.filename)
            if name is None:
                continue
            if info.file_size > MAX_RULE_BYTES:
                rejected.append((info.filename, "larger than %d KB" % (MAX_RULE_BYTES >> 10)))
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise RuntimeError("the zip unpacks to more than %d MB, giving up" % (MAX_TOTAL_BYTES >> 20))
            with zf.open(info) as fh:
                raw = fh.read(MAX_RULE_BYTES + 1)     # trust the bytes read, not the size the header claims
            if len(raw) > MAX_RULE_BYTES:
                rejected.append((info.filename, "larger than %d KB" % (MAX_RULE_BYTES >> 10)))
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                rejected.append((info.filename, "not valid UTF-8 text"))
                continue
            if "\x00" in text:
                rejected.append((info.filename, "contains NUL bytes"))
                continue
            why = check_rule_text(text)
            if why:
                rejected.append((info.filename, why))
                continue
            final, n = name, 1
            while final.lower() in used:             # two entries with the same base name: keep both
                n += 1
                stem, ext = os.path.splitext(name)
                final = "%s-%d%s" % (stem, n, ext)
            used.add(final.lower())
            with open(os.path.join(stage, final), "w", encoding="utf-8", newline="") as out:
                out.write(text)
            kept += 1
            for lic in LICENSE_RE.findall(text) or ["(none stated)"]:
                licenses[lic] = licenses.get(lic, 0) + 1
    return kept, rejected, licenses


def main():
    ap = argparse.ArgumentParser(add_help=True, description="Fetch the public YARAhub rules for wq-yara-build.sh")
    ap.add_argument("--force", action="store_true", help="fetch even if the last fetch is recent")
    ap.add_argument("--zip", metavar="FILE", help="use this zip instead of downloading (offline use, tests)")
    ap.add_argument("--url", default=os.environ.get("YARAHUB_URL", ""), help="rules zip URL (HTTPS); default: the YARAhub page's download link")
    ap.add_argument("--dest", default=FEEDS, help="feeds folder (default: _yara-feeds next to this script)")
    ap.add_argument("--min-hours", type=float,
                    default=float(os.environ.get("YARAHUB_MIN_HOURS", "24") or 24),
                    help="wait this long between fetches (default 24)")
    ap.add_argument("--dry-run", action="store_true", help="download and check, write nothing")
    args = ap.parse_args()

    dest_root = os.path.abspath(args.dest)
    target = os.path.join(dest_root, "yarahub")
    stamp = read_stamp(target)
    age = time.time() - float(stamp.get("fetched_epoch", 0) or 0)
    if not args.zip:
        floor = FLOOR_SECONDS
        if age < floor:
            say("last fetched %d min ago; abuse.ch regenerates the zip every 5 minutes, waiting" % (age // 60))
            return 0
        if not args.force and age < args.min_hours * 3600:
            say("rules are %.1f h old (fetching again after %g h; --force to override)" % (age / 3600, args.min_hours))
            return 0

    tmp_zip, own_zip, used_url = args.zip, False, ""
    try:
        if not tmp_zip:
            tmp_zip, used_url = download_any([args.url] if args.url else DEFAULT_URLS,
                                             os.environ.get("ABUSECH_AUTH_KEY", "").strip())
            own_zip = True
        elif not os.path.isfile(tmp_zip):
            return fail("not a file: " + tmp_zip)
        if not zipfile.is_zipfile(tmp_zip):
            return fail("the download is not a zip file (a login page or an error page?); old rules kept")
        digest = sha256_of(tmp_zip)
        if stamp.get("zip_sha256") == digest and os.path.isdir(target) and not args.dry_run:
            say("rules unchanged since the last fetch (sha256 %s...)" % digest[:12])
            _touch(target, stamp, digest)
            return 0

        os.makedirs(dest_root, exist_ok=True)
        stage = tempfile.mkdtemp(prefix=".yarahub-new-", dir=dest_root)
        try:
            kept, rejected, licenses = extract_rules(tmp_zip, stage)
            if kept == 0:
                return fail("no usable rule file in the zip (%d rejected); old rules kept" % len(rejected))
            say("%d rule files usable, %d rejected" % (kept, len(rejected)))
            if args.dry_run:
                for n, why in rejected[:20]:
                    say("  rejected: %s - %s" % (n, why))
                return 0
            with open(os.path.join(stage, "REJECTED.txt"), "w", encoding="utf-8") as fh:
                fh.write("# YARAhub files not used, and why. Rules stay untouched; nothing here is scanned.\n")
                for n, why in rejected:
                    fh.write("%s: %s\n" % (n, why))
            _write_stamp(stage, digest, used_url if not args.zip else "file:" + os.path.basename(args.zip),
                         kept, len(rejected), licenses)
            prev = target + ".prev"
            if os.path.isdir(target):
                shutil.rmtree(prev, ignore_errors=True)
                os.rename(target, prev)
            try:
                os.rename(stage, target)
            except OSError:
                if os.path.isdir(prev):
                    os.rename(prev, target)          # put the old set back
                raise
            stage = None
        finally:
            if stage:
                shutil.rmtree(stage, ignore_errors=True)
    except (RuntimeError, OSError, zipfile.BadZipFile, urllib.error.URLError) as exc:
        return fail("%s; old rules kept" % exc)
    finally:
        if own_zip and tmp_zip and os.path.exists(tmp_zip):
            os.unlink(tmp_zip)

    say("updated %s" % target)
    lic = ", ".join("%s x%d" % (k, v) for k, v in sorted(licenses.items(), key=lambda kv: -kv[1])[:6])
    say("licenses declared in the rules: " + lic)
    say("run wq-yara-build.sh (or just launch a game: the ruleset rebuilds when rules are newer)")
    return 0


def _write_stamp(folder, digest, source, kept, rejected, licenses):
    data = {"fetched_epoch": int(time.time()),
            "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "zip_sha256": digest, "source": source, "rules_kept": kept, "rules_rejected": rejected,
            "licenses": licenses}
    with open(os.path.join(folder, ".fetched"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)


def _touch(folder, stamp, digest):
    """Same zip as last time: only move the 'last fetched' time forward, so the build is not triggered."""
    stamp["fetched_epoch"] = int(time.time())
    stamp["fetched_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    stamp["zip_sha256"] = digest
    try:
        with open(os.path.join(folder, ".fetched"), "w", encoding="utf-8") as fh:
            json.dump(stamp, fh, indent=1, sort_keys=True)
    except OSError:
        pass


if __name__ == "__main__":
    sys.exit(main())
