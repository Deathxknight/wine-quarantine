#!/bin/bash
# wq-ui/install-menu.sh - put Wine Quarantine in the application menu with its logo.
#
#   wq-ui/install-menu.sh              install (or refresh) the menu entry and icons
#   wq-ui/install-menu.sh --uninstall  remove them
#
# Writes only under $XDG_DATA_HOME (default ~/.local/share):
#   applications/wine-quarantine.desktop
#   icons/hicolor/<size>x<size>/apps/wine-quarantine.png and icons/hicolor/scalable/apps/wine-quarantine.svg
#
# On Wayland a window has no icon of its own: the desktop shows the icon of the .desktop file whose name
# matches the window's app id. wq-ui sets that app id to "wine-quarantine", so this file is what replaces
# the generic placeholder in the taskbar, the Alt-Tab switcher and the menu.
set -u
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
QROOT="$(dirname "$HERE")"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
ID=wine-quarantine
SIZES="16 24 32 48 64 128 256 512"

refresh_caches() {
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$DATA/applications" 2>/dev/null
  command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f "$DATA/icons/hicolor" 2>/dev/null
  command -v kbuildsycoca6 >/dev/null 2>&1 && kbuildsycoca6 --noincremental >/dev/null 2>&1
  return 0
}

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$DATA/applications/$ID.desktop" "$DATA/icons/hicolor/scalable/apps/$ID.svg"
  for s in $SIZES; do rm -f "$DATA/icons/hicolor/${s}x${s}/apps/$ID.png"; done
  refresh_caches
  echo "removed the Wine Quarantine menu entry and icons"
  exit 0
fi

case "$QROOT" in
  *[\"\\\`\$]*) echo "The folder path contains a quote, backslash, backtick or \$, which a menu entry cannot hold safely: $QROOT" >&2; exit 1 ;;
esac
[ -f "$HERE/icons/$ID.svg" ] || { echo "missing $HERE/icons/$ID.svg" >&2; exit 1; }
[ -x "$QROOT/wq" ] || { echo "missing $QROOT/wq (run install.sh first)" >&2; exit 1; }

mkdir -p "$DATA/applications" "$DATA/icons/hicolor/scalable/apps"
cp "$HERE/icons/$ID.svg" "$DATA/icons/hicolor/scalable/apps/$ID.svg"
for s in $SIZES; do
  if [ -f "$HERE/icons/$ID-$s.png" ]; then
    mkdir -p "$DATA/icons/hicolor/${s}x${s}/apps"
    cp "$HERE/icons/$ID-$s.png" "$DATA/icons/hicolor/${s}x${s}/apps/$ID.png"
  fi
done

# Point Icon= straight at the image file. A bare name ("wine-quarantine") goes through icon-theme lookup, which on
# KDE (Papirus, Breeze, ...) can fall back to the generic "wine" glass because of the dash in the name.
if   [ -f "$DATA/icons/hicolor/256x256/apps/$ID.png" ]; then ICON_REF="$DATA/icons/hicolor/256x256/apps/$ID.png"
elif [ -f "$DATA/icons/hicolor/scalable/apps/$ID.svg" ]; then ICON_REF="$DATA/icons/hicolor/scalable/apps/$ID.svg"
else ICON_REF="$ID"; fi

cat > "$DATA/applications/$ID.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Wine Quarantine
GenericName=Sandboxed Windows games
Comment=Run Windows games in a firejail sandbox
Exec="$QROOT/wq"
Icon=$ICON_REF
Terminal=false
Categories=Game;Utility;
Keywords=wine;proton;sandbox;firejail;quarantine;
StartupWMClass=$ID
StartupNotify=false
DESK
chmod 644 "$DATA/applications/$ID.desktop"
refresh_caches
echo "installed: $DATA/applications/$ID.desktop"
echo "If the old icon is still shown, log out and back in (or restart the panel) so the desktop re-reads its icon cache."
