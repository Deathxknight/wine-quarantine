#!/bin/bash
# lib-extract.sh - helpers shared by new-quarantine.sh and wq-ui/new-native.sh (sourced, not run).

# Archives come from the internet and the extractors are parsers, so they run inside the helper jail
# (lib-firejail.sh): no network, no sockets, and the ONLY writable path is the folder being filled.
# That closes the "symlink first, then a file written through it" trick, which would otherwise land
# in your home folder or the launcher while the archive is still being unpacked (wq_sanitize_extracted
# below only cleans up afterwards). If the jail cannot be set up the extraction stops;
# WQ_EXTRACT_SANDBOX=0 runs the extractor on the host after all, with a warning.
# shellcheck source=lib-firejail.sh
declare -F wq_helper_jail >/dev/null 2>&1 || . "$(dirname "${BASH_SOURCE[0]}")/lib-firejail.sh"

# wq_xrun <destdir> <command> [args...]
wq_xrun() {
  local dest="$1"; shift
  if [ "${WQ_EXTRACT_SANDBOX:-1}" = 0 ]; then
    echo "wq: WARNING: unpacking on the host without a sandbox (WQ_EXTRACT_SANDBOX=0)" >&2
    "$@"; return
  fi
  local jopts=() a rp
  # an input file under /tmp would be invisible in a private /tmp
  for a in "$@"; do
    [ -e "$a" ] || continue
    rp="$(readlink -f -- "$a" 2>/dev/null || true)"
    case "$rp" in /tmp/*|/var/tmp/*) jopts+=(--host-tmp-ro); break ;; esac
  done
  if ! WQ_HELPER_JAIL_STRICT=1 wq_helper_jail --rw "$dest" "${jopts[@]+"${jopts[@]}"}"; then
    echo "wq: cannot set up the sandbox for unpacking, so nothing was unpacked." >&2
    echo "wq: (WQ_EXTRACT_SANDBOX=0 in config.local.sh unpacks on the host instead, which is the risk this avoids)" >&2
    return 97
  fi
  "${WQ_HJAIL[@]}" "--timeout=${WQ_EXTRACT_TIMEOUT:-02:00:00}" -- "$@"
}

# path of a 7-Zip binary, or nothing
wq_find_7z() { command -v 7z || command -v 7zz || command -v 7za || true; }

# After unpacking something we don't trust: make the tree writable (ISO images unpack
# read-only, which later breaks removing the game) and delete symlinks that point outside it.
wq_sanitize_extracted() {   # wq_sanitize_extracted <dir>
  local dest="$1" root link real
  root="$(readlink -f "$dest")"
  chmod -R u+rwX "$dest" 2>/dev/null || true
  # an archive can carry setuid/setgid/sticky bits; nothing here may keep them
  find "$dest" -type f -perm /6000 -exec chmod ug-s {} + 2>/dev/null || true
  while IFS= read -r -d '' link; do
    real="$(readlink -f "$link" 2>/dev/null || true)"
    case "$real" in
      "$root"|"$root"/*) ;;
      *) echo "Removed a symlink that points outside the game folder: ${link#"$dest"/}" >&2
         rm -f -- "$link" ;;
    esac
  done < <(find "$dest" -type l -print0)
}

# Unpack an .iso without mounting it (no root needed). 7-Zip first, bsdtar as the fallback.
wq_extract_iso() {   # wq_extract_iso <image.iso> <destdir>
  local src="$1" dest="$2" sevenz
  sevenz="$(wq_find_7z)"
  if [ -n "$sevenz" ]; then
    wq_xrun "$dest" "$sevenz" x -y -o"$dest" "$src" >/dev/null || { echo "Error: could not unpack the .iso with $sevenz." >&2; return 1; }
  elif command -v bsdtar >/dev/null 2>&1; then
    wq_xrun "$dest" bsdtar -xf "$src" --no-same-owner -C "$dest" || { echo "Error: could not unpack the .iso with bsdtar." >&2; return 1; }
  else
    echo "Error: an .iso needs 7z (p7zip) or bsdtar (libarchive), and neither is installed." >&2
    return 1
  fi
  wq_sanitize_extracted "$dest"
}

# Unpack a .zip with unzip. 7-Zip is only the fallback, and only when unzip really could not
# unpack everything: it failed outright, or it skipped files (unsupported compression method such
# as zstd or deflate64, exit 81, or a skipped-file warning). A plain warning (exit 1, e.g. a zip
# made on Windows with backslash separators) means everything was unpacked, so it is accepted.
wq_extract_zip() {   # wq_extract_zip <archive.zip> <destdir>
  local src="$1" dest="$2" sevenz rc=0 err why
  sevenz="$(wq_find_7z)"
  if command -v unzip >/dev/null 2>&1; then
    err="$(mktemp)"
    # -o: never stop to ask about overwriting, -qq: quiet. unzip prints some warnings on stdout, so capture both.
    wq_xrun "$dest" unzip -qq -o "$src" -d "$dest" </dev/null >"$err" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then rm -f "$err"; return 0; fi
    if [ "$rc" -eq 1 ] && ! grep -qiE 'unsupported compression|skipping|cannot create|bad CRC|incorrect password|need PK compat' "$err"; then
      echo "unzip finished with warnings (exit 1); all files were unpacked." >&2
      rm -f "$err"; return 0
    fi
    why="$(head -n 3 "$err" | tr '\n' ' ')"
    if [ -z "$why" ] && [ "$rc" -eq 81 ]; then why="unsupported compression method"; fi   # if, not &&: safe under set -e
    rm -f "$err"
    [ -n "$sevenz" ] || { echo "Error: unzip failed (exit $rc: ${why:-no message}) and 7z is not installed to retry. If the zip uses zstd or another newer method, install p7zip / 7zip." >&2; return 1; }
    echo "unzip could not unpack every file (exit $rc: ${why:-no message}); retrying with $sevenz..." >&2
  elif [ -z "$sevenz" ]; then
    echo "Error: a .zip needs unzip or 7z, and neither is installed." >&2
    return 1
  fi
  wq_xrun "$dest" "$sevenz" x -y -o"$dest" "$src" >/dev/null || { echo "Error: could not unpack the .zip with $sevenz." >&2; return 1; }
}
