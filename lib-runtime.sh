# lib-runtime.sh - recognise the DLLs and EXEs that Proton puts into a Wine prefix.
#
# A system32 write that matches the Proton build's own file (same name AND same SHA-256) is what
# Proton's setup does, so the monitor can log it quietly. Anything else is still judged by the
# monitor's normal rules. A list is built once per launch, before the game starts, from the
# Proton directory the game uses. Source this file; it has no side effects.
#
# List format: one line per file, "<sha256>  <lowercase basename>" (the same as sha256sum output).

# runtime_build_allowlist <proton_dir> <out_file>
# Hashes every .dll/.exe/.sys under <proton_dir>/files and <proton_dir>/dist (GE-Proton and
# Proton-Experimental layouts). Writes atomically; returns non-zero and leaves no file when the
# directory is missing or holds no such files.
runtime_build_allowlist() {
  local src="$1" out="$2" tmp
  [ -d "$src" ] || return 1
  tmp="$(mktemp "${out}.XXXXXX")" || return 1
  local root
  for root in "$src/files" "$src/dist"; do
    [ -d "$root" ] || continue
    find "$root" -type f \( -iname '*.dll' -o -iname '*.exe' -o -iname '*.sys' \) -print0 2>/dev/null |
      while IFS= read -r -d '' f; do
        printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$(basename "$f" | tr '[:upper:]' '[:lower:]')"
      done
  done | sort -u > "$tmp"
  if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$out"
}

# _runtime_alias <lowercase basename> <allowlist>
# Proton keeps a renamed copy of some shipped DLLs next to them (ddraw.dll -> ddraw_.dll). When "x_.dll" is not
# in the list but "x.dll" is, check it against x.dll's hash. The content is still compared, so a dropped
# file with that name that differs from the shipped one is MODIFIED, not trusted.
_runtime_alias() {
  local b="$1" l="$2" alt
  case "$b" in
    *_.dll)
      alt="${b%_.dll}.dll"
      if [ -s "$l" ] && ! awk -v b="$b" 'substr($0, 67) == b { f = 1 } END { exit !f }' "$l" \
         && awk -v b="$alt" 'substr($0, 67) == b { f = 1 } END { exit !f }' "$l"; then b="$alt"; fi ;;
  esac
  printf '%s' "$b"
}

# runtime_classify <file> <allowlist>
# Prints one word:
#   MATCH    - a file with this name is in the list and its content hashes the same
#   MODIFIED - the name is in the list but the content differs (Proton edited it, or it was replaced)
#   UNKNOWN  - the name is not in the list, or the file has already gone
#   NOLIST   - there is no list to check against
runtime_classify() {
  local f="$1" list="$2" base hash
  if [ ! -s "$list" ]; then echo NOLIST; return 0; fi
  base="$(basename "$f" | tr '[:upper:]' '[:lower:]')"
  base="$(_runtime_alias "$base" "$list")"
  # the list is "<64 hex>  <name>": compare by position, because a name can hold spaces
  if ! awk -v b="$base" 'substr($0, 67) == b { found = 1 } END { exit !found }' "$list"; then
    echo UNKNOWN; return 0
  fi
  if [ ! -f "$f" ]; then echo UNKNOWN; return 0; fi
  hash="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
  if [ -z "$hash" ]; then echo UNKNOWN; return 0; fi
  if awk -v b="$base" -v h="$hash" 'substr($0, 67) == b && substr($0, 1, 64) == h { ok = 1 } END { exit !ok }' "$list"; then
    echo MATCH
  else
    echo MODIFIED
  fi
}

# runtime_run_score <run-score file>
# The points a run saved (lines "<kind> <points>", written by monitor.sh). Each kind counts once, the
# way wq-prescan.py counts its kinds. Prints "<total> <kinds comma separated>", or "0 " for no file.
runtime_run_score() {
  local f="$1" pts=0 kinds="" k p
  if [ ! -s "$f" ]; then echo "0 "; return 0; fi
  while read -r k p; do
    case "$p" in ''|*[!0-9]*) continue ;; esac
    case ",$kinds," in *",$k,"*) continue ;; esac
    pts=$((pts + p)); kinds="${kinds:+$kinds,}$k"
  done < "$f"
  echo "$pts $kinds"
}

# runtime_listed <basename> <allowlist>
# True when a file with this name is in the list (content not checked). Used to decide whether the
# monitor should wait for a file to finish being written before hashing it.
runtime_listed() {
  local base
  base="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  base="$(_runtime_alias "$base" "$2")"
  [ -s "$2" ] && awk -v b="$base" 'substr($0, 67) == b { found = 1 } END { exit !found }' "$2"
}
