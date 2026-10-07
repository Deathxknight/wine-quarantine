# wine-quarantine

Bash scripts for running Windows games from sources you don't fully trust on Linux. Each game runs in a firejail sandbox with no network, and a monitor watches for suspicious behavior.

I made this for myself because I like trying small indie games and didn't want to double-click unknown .exe files on my main machine.

<img width="1909" height="1074" alt="image" src="https://github.com/user-attachments/assets/883a3f16-3a83-4bd7-b482-025a6f1e0183" />

## This is not total protection

It makes running a sketchy game less risky, not safe.

- It's a firejail sandbox, not a VM. The game shares your kernel and runs as your user.
- The monitor is a tripwire. It matches names and polls every few seconds, so it can miss things.
- X11 and audio are not isolated.
- The network is fully off, so online and multiplayer games won't work.

If you think a file is real malware, use a VM or don't run it.

## Requirements

- `firejail`, `inotify-tools`, `python3`
- [umu-launcher](https://github.com/Open-Wine-Components/umu-launcher) (`umu-run`)
- A Proton build in Steam's `compatibilitytools.d` (Proton-GE works)
- `unzip`, `unrar` or `7z` if you want to use archives

Tested with firejail 0.9.80, umu-launcher 1.4.4 and GE-Proton11-6.

## Setup

The scripts look for Steam in `~/.local/share/Steam` and for `umu-run` on your PATH or in Lutris's runtime folder. If yours live somewhere else, create a file called `config.local.sh` next to `config.sh`:

```bash
STEAM_ROOT="/path/to/Steam"
LUTRIS_UMU="/path/to/umu-run"
```

It's gitignored, so it won't get committed. If you installed `umu-run` some unusual way and the game can't find it inside the sandbox, add its folder to `QUARANTINE_RO_PATHS` in the same file.

If you edit `verify-sandbox.sh`, regenerate its hash with `./verify-sandbox.sh --update-hash`.

## Usage

```bash
./new-quarantine.sh "My Game" ~/Downloads/mygame.zip
./launch.sh "My Game"
```

The first command unpacks the game and picks the exe, which is saved in `My Game/game.conf`. The second runs it in the sandbox with the monitor. Logs go in `My Game/logs/`.

Only the `game/` and `prefix/` folders are writable from inside the sandbox. The rest of the game folder, including `game.conf` and the logs, is hidden from the game.

## Known issues

- The shared `_umu-data` folder is writable by every game, so one bad game could tamper with the runtime the others use.
- Your whole Steam folder is mounted read-only inside the sandbox.
- Registry persistence detection may miss values added to an existing key.

Issues and pull requests are welcome.
