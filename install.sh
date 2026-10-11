#!/bin/bash
# install.sh - checks requirements, fixes the common setup problems, creates ./wq
set -u
QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$QROOT" || exit 1

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
ask()  { local a; read -r -p "$1 [y/N] " a; [[ $a =~ ^[Yy] ]]; }
setkv() {  # setkv KEY 'bash-value-expression'  (only if not already in config.local.sh)
  grep -q "^$1=" config.local.sh 2>/dev/null || printf '%s=%s\n' "$1" "$2" >> config.local.sh
}

echo "wine-quarantine setup"
echo

# --- 1. location -----------------------------------------------------------
echo "Location"
H="$(readlink -f "$HOME")"; R="$(readlink -f "$QROOT")"
case "$R" in
  "$H"|"$H"/*)
    bad "$R is inside your home folder. firejail --private hides it."
    echo "    Move it, e.g.:"
    echo "      sudo mkdir /mnt/wine-quarantine && sudo chown \$USER /mnt/wine-quarantine"
    echo "      git clone <repo url> /mnt/wine-quarantine"
    exit 1 ;;
  *) ok "$R (outside \$HOME)" ;;
esac

# --- 2. packages -----------------------------------------------------------
echo; echo "Packages"
if   command -v pacman >/dev/null; then PM="sudo pacman -S --needed"; PY=python;  QT=pyside6;                 EXTRA_7Z=p7zip;       UNRAR=unrar
elif command -v apt    >/dev/null; then PM="sudo apt install";        PY=python3; QT=python3-pyside6.qtwidgets; EXTRA_7Z=p7zip-full; UNRAR=unrar-free
elif command -v dnf    >/dev/null; then PM="sudo dnf install";        PY=python3; QT=python3-pyside6;         EXTRA_7Z=p7zip;       UNRAR=unrar
else PM=""; fi

missing=()
need() { if command -v "$1" >/dev/null 2>&1; then ok "$1"; else bad "$1 missing"; missing+=("$2"); fi; }
need firejail firejail
need inotifywait inotify-tools
need python3 "${PY:-python3}"
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

# --- 3. umu / Steam / Proton (resolved by config.sh itself) -----------------
echo; echo "umu-launcher, Steam, Proton"
res() { bash -c 'cd "$1" && source ./config.sh >/dev/null 2>&1 && eval "$2"' _ "$QROOT" "$1"; }
UMU="$(res 'echo $LUTRIS_UMU')"
if [ -n "$UMU" ] && [ -x "$UMU" ]; then ok "umu-run: $UMU"
else bad "umu-run not found. Install umu-launcher (https://github.com/Open-Wine-Components/umu-launcher) or set LUTRIS_UMU in config.local.sh"; fi

PROTON="$(res 'find_proton')"
if [ -z "$PROTON" ]; then
  bad "no Proton build found"
  echo "    Download GE-Proton (https://github.com/GloriousEggroll/proton-ge-custom/releases) or use ProtonUp-Qt, then run this again."
  echo "    Manual install:"
  echo "      mkdir -p ~/.local/share/Steam/compatibilitytools.d"
  echo "      tar -xf ~/Downloads/GE-Proton*.tar.gz -C ~/.local/share/Steam/compatibilitytools.d"
else
  case "$PROTON" in
    "$H"/*)
      warn "Proton is under your home folder: $PROTON"
      echo "    firejail --private hides it inside the sandbox (this breaks umu with 'toolmanifest.vdf not found')."
      if ask "  Copy it to /opt/proton (needs sudo) and configure it?"; then
        sudo mkdir -p /opt/proton && sudo cp -a "$PROTON" /opt/proton/ && {
          setkv PROTON_PREFERRED "/opt/proton/$(basename "$PROTON")"
          setkv QUARANTINE_EXTRA_RO_PATHS '("/opt/proton")'
          ok "configured in config.local.sh"
        }
      fi ;;
    *) ok "Proton: $PROTON" ;;
  esac
fi

# --- 4. integration + launcher ---------------------------------------------
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

echo
echo "Next:"
echo "  ./wq                                   open the UI (Debug button = setup check + report)"
echo "  ./new-quarantine.sh \"My Game\" ~/Downloads/mygame.zip"
