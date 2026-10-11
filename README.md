# wine-quarantine

Scripts and a small Qt app for running games from sources you don't fully trust on Linux. Each game runs in its own [firejail](https://firejail.wordpress.com/) sandbox with no network by default, and a monitor watches for suspicious behaviour.

I made this for myself because I like trying small indie games and didn't want to double-click unknown files on my main machine. It handles Windows games (through Proton) and native Linux games (shell scripts, binaries, AppImages).

## This is not total protection

It makes running a sketchy game less risky, not safe.

- It's a firejail sandbox, not a VM. The game shares your kernel and runs as your user.
- The monitor is a tripwire. It matches names and polls every few seconds, so it can miss things.
- X11 is only isolated when you turn on the private X server (Xephyr) for that game, and audio is never isolated.
- Online and multiplayer games need network access, which weakens the sandbox. The allow-list helps, but it isn't a guarantee.

If you think a file is real malware, use a VM or don't run it.

## Features

**Sandboxing**
* One firejail profile per game, plus a shared default profile you can save and reset to.
* Isolation switches: hide your home directory, private `/tmp`, no new privileges, drop all capabilities, block D-Bus, seccomp syscall filter, no root user namespace.
* Device switches: block audio, webcams, U2F/security keys, TV/DVB devices and optical drives. Power users can also hide individual `/dev` nodes per game.
* Only the game's own folder is writable. Extra read-write or read-only folders and files can be whitelisted per game.
* Optional private X server (Xephyr, with a configurable window size). With it on, the host X display and the Wayland socket are hidden from the game.

**Network**
* Off by default.
* Filtered mode with an allow-list of hosts and ports, a chosen interface, and optional DNS.
* Connection logging and a learn mode that allows everything and records it, so you can build an allow-list from what the game actually does.
* A Network tab showing connection attempts live from the kernel firewall log.

**Games**
* Windows games run through [umu-launcher](https://github.com/Open-Wine-Components/umu-launcher) and Proton, each with its own Wine prefix.
* Native Linux games run from a shell script, binary or AppImage, with a persistent private `$HOME` so saves survive.
* Add a game from a folder, an archive (`.zip`, `.rar`, `.7z`, `.tar.*`) or a single file.
* If several start files are found you pick the right one. You can change it later.
* Remove a game from the app. The folder goes to the Trash, or is deleted permanently only after you type its name.
* Optional shell scripts that run before launch or after exit (on your machine, not in the sandbox).

**Monitoring**
* A monitor runs alongside every game and writes an alert log.
* Each run ends with a summary and a verdict.
* Logs are kept per game and pruned after 30 days.

**The app (wq-ui)**
* Game list with location, network, display and state at a glance. Select several games to change them together.
* Tri-state checkboxes show when selected games disagree. Only real changes count as unapplied, and the app asks before you lose any.
* One Add menu for new games, the start file, launch scripts and hidden devices. Right-click a game for more.
* Light, dark or follow-system themes, plus your own CSS that reloads when the file changes.
* A Debug window that checks dependencies and builds a redacted report for bug reports.
* Core logic and the profile script have their own tests.

## Requirements

- `firejail`, `inotify-tools`, `python3`
- For the app: `PySide6`. For the private X server: `Xephyr`.
- For Windows games: [umu-launcher](https://github.com/Open-Wine-Components/umu-launcher) (`umu-run`) and a Proton build in Steam's `compatibilitytools.d` (Proton-GE works)
- `unzip`, `unrar`, `7z` or `tar` if you want to use archives
- For live connection logging in the Network tab: `journalctl` and `net.netfilter.nf_log_all_netns=1`

## Setup

The scripts look for Steam in `~/.local/share/Steam` and for `umu-run` on your PATH or in Lutris's runtime folder. If yours live somewhere else, create a file called `config.local.sh` next to `config.sh`:

```bash
STEAM_ROOT="/path/to/Steam"
LUTRIS_UMU="/path/to/umu-run"
```

It's gitignored, so it won't get committed. If you installed `umu-run` some unusual way and the game can't find it inside the sandbox, add its folder to `QUARANTINE_RO_PATHS` in the same file.

To use the app, wire it into the scripts once, then start it:

```bash
python3 wq-ui/integrate.py      # add --dry-run to preview, --revert to undo
python3 wq-ui/wq_ui.py
```

If you edit `verify-sandbox.sh` by hand, regenerate its hash with `./verify-sandbox.sh --update-hash`.

## Usage

From the app: **Add > New game…**, pick Windows or Native Linux, name it, choose a source, then **Launch**.

From the command line:

```bash
./new-quarantine.sh "My Game" ~/Downloads/mygame.zip          # Windows game
./wq-ui/new-native.sh "My Native Game" ~/Downloads/game.tar.gz  # native Linux game
"./My Game/launch-quarantine.sh"
```

The first command unpacks the game and picks the exe, which is saved in `My Game/game.conf`. Both create `launch-quarantine.sh` in the game's folder; it starts the game in the sandbox with the monitor. If a game picked the wrong start file, change it with **Add > Set executable…** or edit `EXE=` in `game.conf`. Logs go in `My Game/logs/`.

Only the `game/` folder (and `prefix/` for Windows games, `home/` for native ones) is writable from inside the sandbox. The rest of the game folder, including `game.conf` and the logs, is hidden from the game.

## Known issues

- The shared `_umu-data` folder is writable by every Windows game, so one bad game could tamper with the runtime the others use.
- Your whole Steam folder is mounted read-only inside the Windows-game sandbox.
- Registry persistence detection may miss values added to an existing key.
- Native games don't run `verify-sandbox.sh` (it was written for the Windows setup) and have no registry check.
- Sound, input and GPU devices stay visible unless you block them.
- Games that keep running in the background after their start script exits can make a run look clean when it isn't.

Issues and pull requests are welcome.
