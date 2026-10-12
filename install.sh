#!/bin/bash
# install.sh - checks requirements, fixes the common setup problems, creates ./wq
# Safe to re-run. Works on a fresh machine: clone, run, done.
set -u
QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$QROOT" || exit 1

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
ask()  { local a; read -r -p "$1 [y/N] " a; [[ $a =~ ^[Yy] ]]; }

echo "wine-quarantine setup"
echo

# --- 1. location -----------------------------------------------------------
echo "Location"
H="$(readlink -f "$HOME")"; R="$(readlink -f "$QROOT")"
case "$R" in
  "$H"|"$H"/*)
    bad "$R is inside your home folder. firejail --private hides it."
    DEST=/mnt/wine-quarantine
    if ask "  Move this checkout to $DEST now (needs sudo)?"; then
      if [ -e "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
        bad "$DEST already exists and is not empty. Pick another place and re-run."; exit 1
      fi
      sudo mkdir -p "$DEST" && sudo chown "$USER" "$DEST" && cp -a "$R/." "$DEST/" \
        || { bad "copy failed"; exit 1; }
      ok "copied to $DEST (you can delete $R afterwards)"
      exec "$DEST/install.sh"
    fi
    echo "    Or do it yourself:"
    echo "      sudo mkdir /mnt/wine-quarantine && sudo chown \$USER /mnt/wine-quarantine"
    echo "      git clone <repo url> /mnt/wine-quarantine && /mnt/wine-quarantine/install.sh"
    exit 1 ;;
  *) ok "$R (outside \$HOME)" ;;
esac

# --- 2. packages -----------------------------------------------------------
echo; echo "Packages"
UMU_PKG=""
if   command -v pacman >/dev/null; then PM="sudo pacman -S --needed"; PY=python;  QT=pyside6;                 EXTRA_7Z=p7zip;       UMU_PKG=umu-launcher
elif command -v apt    >/dev/null; then PM="sudo apt install";        PY=python3; QT=python3-pyside6.qtwidgets; EXTRA_7Z=p7zip-full
elif command -v dnf    >/dev/null; then PM="sudo dnf install";        PY=python3; QT=python3-pyside6;         EXTRA_7Z=p7zip;       UMU_PKG=umu-launcher
else PM=""; fi

missing=()
need() { if command -v "$1" >/dev/null 2>&1; then ok "$1"; else bad "$1 missing"; missing+=("$2"); fi; }
need firejail firejail
if command -v umu-run >/dev/null 2>&1 && [ "$(head -c2 "$(command -v umu-run)")" != "PK" ]; then
  ok "umu-run ($(command -v umu-run))"
else
  warn "umu-run not found or is a ZIP archive (not executable)"
  if [ -n "$UMU_PKG" ]; then missing+=("$UMU_PKG")
  else echo "    Install umu-launcher from: https://github.com/Open-Wine-Components/umu-launcher/releases"; fi
fi
need inotifywait inotify-tools
need python3 "${PY:-python3}"
need curl curl
need unzip unzip
if command -v 7z >/dev/null || command -v 7zz >/dev/null || command -v 7za >/dev/null; then ok 7z; else warn "7z missing (optional)"; missing+=("${EXTRA_7Z:-p7zip}"); fi
command -v unrar >/dev/null && ok unrar || warn "unrar missing (optional)"
command -v Xephyr >/dev/null && ok "Xephyr (optional)" || warn "Xephyr missing (optional, only for isolated X11)"
if python3 -c 'import PySide6.QtWidgets' 2>/dev/null; then ok "PySide6"; else bad "PySide6 missing (needed for the UI)"; missing+=("${QT:-PySide6}"); fi

if [ "${#missing[@]}" -gt 0 ]; then
  echo
  if [ -n "$PM" ]; then
    echo "  Missing: ${missing[*]}"
    echo "  Command: $PM ${missing[*]}"
    ask "  Run it now?" && $PM "${missing[@]}"
  else
    echo "  Unknown package manager. Install: ${missing[*]}"
  fi
fi

# --- 3. Proton --------------------------------------------------------------
# Steam is NOT needed. Proton lives in $QROOT/_proton (outside $HOME, no sudo):
# firejail --private empties $HOME, so a Proton under it is invisible to umu
# ("toolmanifest.vdf not found").
echo; echo "Proton"
res() { bash -c 'cd "$1" && source ./config.sh >/dev/null 2>&1 && eval "$2"' _ "$QROOT" "$1"; }
PDIR="$QROOT/_proton"

# drop settings written by older versions of this script
if [ -f config.local.sh ]; then
  sed -i '/^QUARANTINE_EXTRA_RO_PATHS=/d' config.local.sh
  if grep -q "^PROTON_PREFERRED=.*$H" config.local.sh 2>/dev/null; then sed -i '/^PROTON_PREFERRED=/d' config.local.sh; fi
fi

PROTON="$(res 'find_proton')"
in_home() { case "$1" in "$H"/*) return 0 ;; *) return 1 ;; esac; }

fetch_ge_proton() {   # download + sha512-verify the latest GE-Proton into $PDIR
  local tmp url sum
  tmp="$(mktemp -d)" || return 1
  mapfile -t U < <(python3 - <<'PY'
import json, urllib.request
r = json.load(urllib.request.urlopen(
    "https://api.github.com/repos/GloriousEggroll/proton-ge-custom/releases/latest", timeout=30))
import platform, sys
a = {x["name"]: x["browser_download_url"] for x in r["assets"]}
want = "aarch64" if platform.machine() in ("aarch64", "arm64") else "x86_64"
def arch(n):
    return "aarch64" if ("aarch64" in n or "arm64" in n) else "x86_64"
t = next((n for n in a if n.endswith(".tar.gz") and arch(n) == want), None)
if t is None:
    sys.exit("no %s GE-Proton tarball in the latest release" % want)
s = t[:-7] + ".sha512sum"
print(a[t]); print(a.get(s, ""))
PY
  ) || { bad "could not query GitHub for the latest GE-Proton"; rm -rf "$tmp"; return 1; }
  url="${U[0]:-}"; sum="${U[1]:-}"
  [ -n "$url" ] || { bad "no GE-Proton tarball found in the latest release"; rm -rf "$tmp"; return 1; }
  echo "  downloading $(basename "$url") (~500MB)"
  curl -fL --progress-bar -o "$tmp/$(basename "$url")" "$url" || { bad "download failed"; rm -rf "$tmp"; return 1; }
  if [ -n "$sum" ] && curl -fsSL -o "$tmp/sum" "$sum"; then
    ( cd "$tmp" && sha512sum -c sum >/dev/null 2>&1 ) && ok "checksum verified" \
      || { bad "checksum mismatch, refusing to install"; rm -rf "$tmp"; return 1; }
  else
    warn "no checksum published for this release, skipping verification"
  fi
  mkdir -p "$PDIR" && tar -xf "$tmp/$(basename "$url")" -C "$PDIR"; local rc=$?
  rm -rf "$tmp"; return $rc
}

if [ -z "$PROTON" ] || in_home "$PROTON"; then
  if [ -n "$PROTON" ]; then
    warn "Proton is under your home folder: $PROTON"
    echo "    firejail --private hides it inside the sandbox."
    if ask "  Copy it to $PDIR (no sudo)?"; then
      mkdir -p "$PDIR" && cp -a "$PROTON" "$PDIR/" && ok "copied (the old copy in your home folder can be deleted)"
    fi
  else
    bad "no Proton build found"
    LOCAL_TGZ="$(ls -t "$HOME"/Downloads/GE-Proton*.tar.gz 2>/dev/null | head -n1 || true)"
    if [ -n "$LOCAL_TGZ" ] && ask "  Install $(basename "$LOCAL_TGZ") from ~/Downloads into $PDIR?"; then
      mkdir -p "$PDIR" && tar -xf "$LOCAL_TGZ" -C "$PDIR" && ok "extracted"
    elif ask "  Download the latest GE-Proton from GitHub into $PDIR?"; then
      fetch_ge_proton && ok "installed"
    else
      echo "    Manual install:"
      echo "      mkdir -p \"$PDIR\""
      echo "      tar -xf ~/Downloads/GE-Proton*.tar.gz -C \"$PDIR\""
    fi
  fi
  PROTON="$(res 'find_proton')"
fi

if [ -z "$PROTON" ]; then bad "still no Proton build; fix this and re-run"
elif in_home "$PROTON"; then bad "Proton is still under \$HOME ($PROTON); the sandbox cannot see it"
else ok "Proton: $PROTON"; fi

UMU="$(res 'echo $LUTRIS_UMU')"
if [ -n "$UMU" ] && [ -x "$UMU" ]; then ok "umu-run: $UMU"
else bad "umu-run not found. Install umu-launcher or set LUTRIS_UMU in config.local.sh"; fi

# --- 4. umu runtime (one-time download) -------------------------------------
echo; echo "umu runtime"
UMU_DATA="$QROOT/_umu-data"
mkdir -p "$UMU_DATA/umu"
ARCH="$(uname -m)"
if [ "$ARCH" = x86_64 ]; then rm -rf "$UMU_DATA/umu"/steamrt*arm64* "$UMU_DATA/umu"/steamrt*aarch64* 2>/dev/null; fi
rt_dir() {   # first runtime folder that matches this CPU
  local d
  for d in "$UMU_DATA/umu"/steamrt*; do
    [ -d "$d" ] || continue
    case "$d" in
      *arm64*|*aarch64*) [ "$ARCH" = x86_64 ] && continue ;;
    esac
    echo "$d"; return 0
  done
  return 1
}
if RT="$(rt_dir)"; then
  ok "already downloaded ($(basename "$RT"))"
elif [ -z "$UMU" ] || [ ! -x "$UMU" ]; then
  warn "skipped, umu-run not found (see above)"
elif [ -z "$PROTON" ] || in_home "$PROTON"; then
  warn "skipped, it needs a usable Proton build first (see above)"
else
  echo "  downloading (about 200MB, once, needs internet). umu prints its own progress:"
  echo
  PRIME_PFX="$(mktemp -d)"
  XDG_DATA_HOME="$UMU_DATA" WINEPREFIX="$PRIME_PFX" PROTONPATH="$PROTON" GAMEID=umu-default python3 "$UMU" /bin/true
  rc=$?
  rm -rf "$PRIME_PFX"
  echo
  if [ "$rc" -eq 0 ] && RT="$(rt_dir)"; then ok "umu runtime ready ($(basename "$RT"))"
  else bad "umu runtime setup failed (exit code $rc). Check your connection and Proton architecture, then run install.sh again."; fi
fi

# --- 5. integration + launcher ---------------------------------------------
echo; echo "wq-ui"
if grep -q "wq-ui integration" _launch-core.sh 2>/dev/null; then ok "integration already applied"
else echo "  applying integration..."; python3 wq-ui/integrate.py && ok "integration applied"; fi

cat > wq <<'WQ'
#!/bin/bash
exec python3 "$(dirname "$(readlink -f "$0")")/wq-ui/wq_ui.py" "$@"
WQ
chmod +x wq
ok "created ./wq"

if ask "  Add an application-menu entry?"; then
  mkdir -p ~/.local/share/applications
  cat > ~/.local/share/applications/wine-quarantine.desktop <<DESK
[Desktop Entry]
Type=Application
Name=Wine Quarantine
Comment=Run Windows games in a firejail sandbox
Exec=$QROOT/wq
Terminal=false
Categories=Game;
DESK
  ok "menu entry added"
fi

# --- 6. final check ----------------------------------------------------------
echo; echo "Final check"
if bash -c 'cd "$1" && source ./config.sh && check_deps' _ "$QROOT"; then
  ok "all dependencies satisfied"
  echo
  echo "Next:"
  echo "  ./wq                                   open the UI (Debug button = setup check + report)"
  echo "  ./new-quarantine.sh \"My Game\" ~/Downloads/mygame.zip"
else
  bad "setup is not complete, see the list above"; exit 1
fi
