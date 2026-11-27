"""Colour themes for wq-ui. Qt-free, like wq_core.

A theme is a set of colour tokens (the same names the CSS files use, see
wq_core.SAMPLE_CSS) plus optional extra QSS for things a palette can't do (sharp
corners, glow borders). The layers, lowest first:

    wq_core.DARK / LIGHT      defaults for the theme's mode
    theme tokens              this file, or a user theme file
    wq_core.BUILTIN_QSS       the shared stylesheet
    theme QSS                 per-theme extras
    the user's CSS file       Settings -> CSS file, still applied last, so
                              anything that worked before keeps working

User themes: drop a `.css` file in ~/.config/wq-ui/themes/. It uses the same
`@define-color` lines as any wq-ui CSS file, plus two optional header lines:

    /* theme: My Theme */
    @define-color mode dark;        (or light; decides which defaults fill the gaps)

Anything below the @define-color lines is QSS for that theme. That is also the
easy way to port a theme from another project: copy its palette into the tokens.

The Pixel theme's images and font sit in theme_assets/ and are referred to as @assets/... in its QSS.

The palettes below are colour values taken from these open-source themes (all
permissively licensed): Dracula, Nord, Gruvbox, Catppuccin, Tokyo Night,
Solarized, Rosé Pine and One Dark. Cyberpunk, Synthwave and Matrix are in the
style of the usual neon editor themes (e.g. Synthwave '84), not copies. Anime is an
original palette (sakura pink and sky blue on a night-sky indigo), not taken from a project.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import wq_core as core

HERE = Path(__file__).resolve().parent
ASSETS_DIR = HERE / "theme_assets"         # images and the pixel font; a theme's QSS refers to them as @assets/...

TOKEN_KEYS = ("surface", "surface_container", "surface_container_high", "on_surface",
              "on_surface_variant", "primary", "on_primary", "outline", "error", "ok", "warn")


@dataclass(frozen=True)
class Theme:
    id: str
    label: str
    mode: str                      # "dark" or "light": which base defaults and {mode} use
    tokens: dict = field(default_factory=dict)
    qss: str = ""
    source: str = ""               # where the palette comes from, shown in the settings hint


def _t(id_, label, mode, source, qss="", **tokens) -> Theme:
    return Theme(id_, label, mode, tokens, qss, source)


# --- extra QSS ------------------------------------------------------------
# Tokens (@primary ...) are substituted like everywhere else.

# Hard edges, thin neon outlines, monospace. Shared by the neon themes.
_NEON_QSS = """
* { font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", "DejaVu Sans Mono", monospace; font-size: 12px; }
QToolButton, QPushButton, QLineEdit, QComboBox, QSpinBox, QMenu, QMenu::item, QLabel#badge, QLabel#banner,
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { border-radius: 2px; }
QTabWidget::pane, QGroupBox, QTreeWidget#gameList, QPlainTextEdit, QTreeWidget, QTableWidget, QListWidget { border-radius: 2px; }
QLabel#badge { border-radius: 2px; }
QTabBar::tab { text-transform: uppercase; letter-spacing: 1px; }
QTabBar::tab:selected { border-bottom: 2px solid @accent2; color: @primary; }
QToolButton:hover { border-color: @primary; background: @surface_container; }
QPushButton:hover { border-color: @accent2; }
QPushButton[accent="true"] { border: 1px solid @accent2; }
QLineEdit:focus, QComboBox:focus { border-color: @accent2; }
QGroupBox::title { color: @primary; }
QHeaderView::section { border-bottom: 1px solid @primary; color: @primary; }
QMenu { border: 1px solid @primary; }
QToolBar { border-bottom: 1px solid @primary; }
QStatusBar { border-top: 1px solid @primary; }
QTreeWidget#gameList, QPlainTextEdit#console, QPlainTextEdit#alerts { border: 1px solid @outline; }
QTreeWidget#gameList:focus, QPlainTextEdit#console:focus, QPlainTextEdit#alerts:focus { border-color: @primary; }
"""

# Flat, slightly rounder, for the soft pastel themes (Catppuccin, Rosé Pine).
_SOFT_QSS = """
QToolButton, QPushButton, QLineEdit, QComboBox, QSpinBox { border-radius: 8px; }
QTabWidget::pane, QGroupBox { border-radius: 10px; }
"""

# Anime: sakura pink + sky blue on night-sky indigo. Big soft corners, pastel gradients on the
# primary buttons and the selected tab. Literal hex is fine here for the colours that are not tokens.
_ANIME_QSS = """
QToolButton, QPushButton, QLineEdit, QComboBox, QSpinBox, QMenu { border-radius: 12px; }
QTabWidget::pane, QGroupBox { border-radius: 14px; }
QTreeWidget, QTableWidget, QListWidget, QPlainTextEdit { border-radius: 12px; }
QTreeWidget#gameList { border-radius: 14px; }
QLabel#badge { border-radius: 9px; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { border-radius: 6px; background: #5a5791; }
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover { background: @primary; }
QTabBar::tab:selected { border-bottom: 3px solid qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @primary, stop:1 #8fd3ff); color: @primary; }
QTabBar::tab:hover { color: #8fd3ff; }
QToolButton:hover { border-color: #8fd3ff; background: @surface_container_high; }
QPushButton:hover { border-color: #8fd3ff; }
QPushButton[accent="true"] { border: 1px solid @primary;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 @primary, stop:1 #c4b0ff); }
QPushButton[accent="true"]:hover { border-color: #ffffff; }
QPushButton[accent="true"]:disabled { background: @surface_container_high; color: @on_surface_variant; border-color: @outline; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: #8fd3ff; }
QGroupBox::title { color: @primary; }
QHeaderView::section { border-bottom: 2px solid @primary; color: #8fd3ff; }
QMenu { border: 1px solid @primary; }
QToolBar { border-bottom: 1px solid @primary; }
QStatusBar { border-top: 1px solid @outline; }
"""

# Pixel: real pixel-art frames (theme_assets/pixel_*.png, drawn by tools/make_pixel_assets.py) as nine-slice
# border images on buttons, group boxes and text fields, a faint dither tile behind the window, square
# everything else, and the Pixelify Sans font (bundled, SIL OFL; wq_ui registers it at startup).
# 6px = one corner of the 2x-scaled frames. The fonts fall back to monospace if the file is missing.
_PIXEL_QSS = """
* { font-family: "Pixelify Sans", "Silkscreen", "DejaVu Sans Mono", monospace; font-size: 14px; }
QMainWindow, QDialog, QWidget#central { background-color: @surface; background-image: url("@assets/pixel_bg.png"); }
QToolTip { border: 2px solid @primary; border-radius: 0; }
QToolButton { border-radius: 0; border-width: 2px; }
QToolButton:hover { border-color: @primary; }
QToolBar { border-bottom: 2px solid @outline; }
QStatusBar { border-top: 2px solid @outline; }

QPushButton { border: 6px solid transparent; border-image: url("@assets/pixel_button.png") 6 6 6 6 stretch stretch;
    border-radius: 0; background: transparent; padding: 0 6px; min-height: 16px; }
QPushButton:hover { border-image: url("@assets/pixel_button_hover.png") 6 6 6 6 stretch stretch; }
QPushButton:pressed { border-image: url("@assets/pixel_button_pressed.png") 6 6 6 6 stretch stretch; padding-top: 2px; }
QPushButton:disabled { border-image: url("@assets/pixel_button_disabled.png") 6 6 6 6 stretch stretch; }
QPushButton[accent="true"], QPushButton[seg="true"]:checked { border-image: url("@assets/pixel_accent.png") 6 6 6 6 stretch stretch;
    background: transparent; font-weight: bold; }
QPushButton[accent="true"]:hover, QPushButton[seg="true"]:checked:hover { border-image: url("@assets/pixel_accent_hover.png") 6 6 6 6 stretch stretch; }
QPushButton[accent="true"]:pressed { border-image: url("@assets/pixel_accent_pressed.png") 6 6 6 6 stretch stretch; }
QPushButton[accent="true"]:disabled { border-image: url("@assets/pixel_button_disabled.png") 6 6 6 6 stretch stretch; background: transparent; }

QGroupBox { border: 6px solid transparent; border-image: url("@assets/pixel_panel.png") 6 6 6 6 stretch stretch; border-radius: 0;
    margin-top: 16px; padding: 12px 6px 4px 6px; }
QGroupBox::title { color: @primary; font-weight: bold; }
QLineEdit { border: 6px solid transparent; border-image: url("@assets/pixel_field.png") 6 6 6 6 stretch stretch; border-radius: 0; padding: 0 2px; }
QLineEdit:focus { border-image: url("@assets/pixel_field_focus.png") 6 6 6 6 stretch stretch; }

QTabWidget::pane { border: 2px solid @outline; border-radius: 0; }
QTabBar::tab { border-bottom: 4px solid transparent; padding: 6px 14px; }
QTabBar::tab:selected { border-bottom: 4px solid @primary; color: @primary; }
QTreeWidget, QTableWidget, QListWidget, QPlainTextEdit, QComboBox, QSpinBox { border: 2px solid @outline; border-radius: 0; }
QTreeWidget#gameList { border-radius: 0; }
QComboBox:focus, QSpinBox:focus { border-color: @primary; }
QHeaderView::section { border-bottom: 2px solid @primary; color: @primary; }
QMenu { border: 2px solid @primary; border-radius: 0; }
QMenu::item { border-radius: 0; }
QLabel#badge, QLabel#banner { border-radius: 0; border-width: 2px; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal { border-radius: 0; margin: 2px; }
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover { background: @primary; }
QProgressBar { border: 2px solid @outline; border-radius: 0; background: @surface_container; text-align: center; }
QProgressBar::chunk { background: @primary; width: 8px; margin: 1px; }
"""


def _neon(extra_accent: str) -> str:
    # accent2 is only a helper token for _NEON_QSS; themes pass their second neon colour
    return _NEON_QSS.replace("@accent2", extra_accent)


# --- the themes -----------------------------------------------------------
THEME_LIST: list[Theme] = [
    _t("cyberpunk", "Cyberpunk", "dark", "neon cyan, magenta and yellow on near-black",
       qss=_neon("#ff2a6d"),
       surface="#0a0a14", surface_container="#10101f", surface_container_high="#1a1a30",
       on_surface="#d7f7ff", on_surface_variant="#7f8ab8", primary="#00f0ff", on_primary="#001418",
       outline="#2e2e57", error="#ff2a6d", ok="#05ffa1", warn="#fcee0a",
       indicator_border="#4a4a85"),
    _t("synthwave", "Synthwave", "dark", "after Synthwave '84 (Robb Owen, MIT)",
       qss=_neon("#36f9f6"),
       surface="#241b2f", surface_container="#2a2139", surface_container_high="#34294f",
       on_surface="#f4eefc", on_surface_variant="#9d8fc0", primary="#ff7edb", on_primary="#2a1030",
       outline="#4a3a6e", error="#fe4450", ok="#72f1b8", warn="#fede5d",
       indicator_border="#6b5a96"),
    _t("matrix", "Matrix", "dark", "green phosphor terminal",
       qss=_neon("#00ff66"),
       surface="#000a03", surface_container="#03140a", surface_container_high="#06220f",
       on_surface="#9dffb8", on_surface_variant="#3fa062", primary="#00ff66", on_primary="#001a08",
       outline="#0f4a24", error="#ff5555", ok="#00ff66", warn="#d7ff3a",
       indicator_border="#1f7a3f"),
    _t("anime", "Anime", "dark", "original: sakura pink and sky blue on a night-sky indigo",
       qss=_ANIME_QSS,
       surface="#1b1a2e", surface_container="#23213b", surface_container_high="#2f2d50",
       on_surface="#f6effb", on_surface_variant="#b0aad6", primary="#ff9ecf", on_primary="#2b0f20",
       outline="#48457a", error="#ff7096", ok="#8ff0c8", warn="#ffd98e",
       indicator_border="#7370ad"),
    _t("pixel", "Pixel", "dark", "original: night-violet and amber, pixel-art frames, Pixelify Sans (SIL OFL)",
       qss=_PIXEL_QSS,
       surface="#1a1428", surface_container="#251f3d", surface_container_high="#342c55",
       on_surface="#efeaff", on_surface_variant="#a29bcb", primary="#ffb02e", on_primary="#1a1428",
       outline="#5b5486", error="#ff5d6c", ok="#6ee05a", warn="#ffe066",
       indicator_border="#7d76b0"),
    _t("dracula", "Dracula", "dark", "Dracula (draculatheme.com, MIT)",
       surface="#282a36", surface_container="#21222c", surface_container_high="#343746",
       on_surface="#f8f8f2", on_surface_variant="#a3acd1", primary="#bd93f9", on_primary="#1e1b2e",
       outline="#44475a", error="#ff5555", ok="#50fa7b", warn="#ffb86c"),
    _t("nord", "Nord", "dark", "Nord (nordtheme.com, MIT)",
       surface="#2e3440", surface_container="#3b4252", surface_container_high="#434c5e",
       on_surface="#eceff4", on_surface_variant="#a9b3c6", primary="#88c0d0", on_primary="#1f2933",
       outline="#4c566a", error="#bf616a", ok="#a3be8c", warn="#ebcb8b"),
    _t("gruvbox-dark", "Gruvbox Dark", "dark", "Gruvbox (morhetz, MIT)",
       surface="#282828", surface_container="#32302f", surface_container_high="#3c3836",
       on_surface="#ebdbb2", on_surface_variant="#a89984", primary="#fabd2f", on_primary="#282828",
       outline="#504945", error="#fb4934", ok="#b8bb26", warn="#fe8019"),
    _t("catppuccin-mocha", "Catppuccin Mocha", "dark", "Catppuccin (MIT)", qss=_SOFT_QSS,
       surface="#1e1e2e", surface_container="#181825", surface_container_high="#313244",
       on_surface="#cdd6f4", on_surface_variant="#a6adc8", primary="#cba6f7", on_primary="#1e1e2e",
       outline="#45475a", error="#f38ba8", ok="#a6e3a1", warn="#f9e2af"),
    _t("tokyo-night", "Tokyo Night", "dark", "Tokyo Night (enkia, MIT)",
       surface="#1a1b26", surface_container="#16161e", surface_container_high="#292e42",
       on_surface="#c0caf5", on_surface_variant="#8089b3", primary="#7aa2f7", on_primary="#10131f",
       outline="#3b4261", error="#f7768e", ok="#9ece6a", warn="#e0af68"),
    _t("rose-pine", "Rosé Pine", "dark", "Rosé Pine (MIT)", qss=_SOFT_QSS,
       surface="#191724", surface_container="#1f1d2e", surface_container_high="#26233a",
       on_surface="#e0def4", on_surface_variant="#908caa", primary="#ebbcba", on_primary="#191724",
       outline="#403d52", error="#eb6f92", ok="#9ccfd8", warn="#f6c177"),
    _t("one-dark", "One Dark", "dark", "Atom One Dark (MIT)",
       surface="#282c34", surface_container="#21252b", surface_container_high="#2c313a",
       on_surface="#abb2bf", on_surface_variant="#7f8796", primary="#61afef", on_primary="#10161d",
       outline="#3e4451", error="#e06c75", ok="#98c379", warn="#e5c07b"),
    _t("solarized-dark", "Solarized Dark", "dark", "Solarized (Ethan Schoonover, MIT)",
       surface="#002b36", surface_container="#073642", surface_container_high="#0d4350",
       on_surface="#93a1a1", on_surface_variant="#7d9094", primary="#2aa198", on_primary="#002b36",
       outline="#586e75", error="#dc322f", ok="#859900", warn="#b58900"),
    # light themes
    _t("catppuccin-latte", "Catppuccin Latte", "light", "Catppuccin (MIT)", qss=_SOFT_QSS,
       surface="#eff1f5", surface_container="#ffffff", surface_container_high="#e6e9ef",
       on_surface="#4c4f69", on_surface_variant="#6c6f85", primary="#8839ef", on_primary="#ffffff",
       outline="#ccd0da", error="#d20f39", ok="#2f8a1f", warn="#a85f0c",
       indicator_border="#8c8fa1"),
    _t("gruvbox-light", "Gruvbox Light", "light", "Gruvbox (morhetz, MIT)",
       surface="#fbf1c7", surface_container="#f9f5d7", surface_container_high="#ebdbb2",
       on_surface="#3c3836", on_surface_variant="#665c54", primary="#3b6f4f", on_primary="#fbf1c7",
       outline="#d5c4a1", error="#9d0006", ok="#79740e", warn="#9a5b0a",
       indicator_border="#928374"),
    _t("solarized-light", "Solarized Light", "light", "Solarized (Ethan Schoonover, MIT)",
       surface="#fdf6e3", surface_container="#fffbee", surface_container_high="#eee8d5",
       on_surface="#586e75", on_surface_variant="#657b83", primary="#1f78b8", on_primary="#ffffff",
       outline="#d9d2bd", error="#dc322f", ok="#6b7a00", warn="#946c00",
       indicator_border="#93a1a1"),
]

THEMES: dict[str, Theme] = {t.id: t for t in THEME_LIST}
BASIC = ("system", "light", "dark")        # not in THEMES: they use wq_core.DARK / LIGHT as they are

for _th in THEME_LIST:                 # _neon() must have filled in every helper token
    assert "@accent2" not in _th.qss, _th.id


# --- user themes ------------------------------------------------------------
def parse_user_theme(path: Path) -> Theme | None:
    """Read one theme file. None if it can't be read or defines no colours."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    defs, rest = core.split_css(text)
    mode = defs.pop("mode", "dark").strip().strip("\"'").lower()
    if mode not in ("dark", "light"):
        mode = "dark"
    tokens = {k: v for k, v in defs.items() if k in TOKEN_KEYS or k == "indicator_border"}
    if not tokens:
        return None
    label = path.stem
    first = text.lstrip().splitlines()[0] if text.strip() else ""
    if first.startswith("/*") and "theme:" in first:
        label = first.split("theme:", 1)[1].split("*/")[0].strip() or label
    return Theme("user:" + path.stem, label, mode, tokens, rest, f"your file {path.name}")


def load_user_themes(directory: Path) -> list[Theme]:
    out: list[Theme] = []
    try:
        files = sorted(p for p in directory.glob("*.css") if p.is_file())
    except OSError:
        return out
    for p in files:
        th = parse_user_theme(p)
        if th is not None:
            out.append(th)
    return out


def all_themes(user_dir: Path | None = None) -> dict[str, Theme]:
    d = dict(THEMES)
    if user_dir is not None:
        for th in load_user_themes(user_dir):
            d[th.id] = th
    return d


def resolve_tokens(theme: Theme | None, mode: str) -> tuple[dict[str, str], str]:
    """(tokens, qss) for a theme, or for plain light/dark when theme is None.
    Missing tokens come from the base defaults of the theme's mode."""
    base = dict(core.DARK if (theme.mode if theme else mode) == "dark" else core.LIGHT)
    if theme is None:
        return base, ""
    base.update(theme.tokens)
    if "indicator_border" not in theme.tokens:
        base["indicator_border"] = base.get("on_surface_variant", base["indicator_border"])
    return base, theme.qss.replace("@assets", ASSETS_DIR.as_posix())


# --- contrast (used by the tests, and handy when writing a theme) ---------------
def _lin(c: int) -> float:
    s = c / 255
    return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4


def luminance(hex_: str) -> float:
    h = hex_.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)
