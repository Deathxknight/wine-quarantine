# wq-ui

The Qt front end for wine-quarantine: list your games, edit each game's sandbox profile, launch, and watch the network and monitor.

```bash
python3 wq-ui/integrate.py     # once: wires wq-ui into config.sh, _launch-core.sh and verify-sandbox.sh
python3 wq-ui/wq_ui.py
```

Needs PySide6. `integrate.py` keeps backups as `<file>.wq-orig` and supports `--dry-run` and `--revert`.

## Files

| File | What it does |
|---|---|
| `wq_ui.py` | The main window, themes and settings |
| `wq_dialogs.py` | Add-game dialog, `/dev` picker, executable picker |
| `wq_core.py` | Qt-free logic: parsing, validation, game discovery, theme tokens |
| `profile.sh` | Turns a game's settings into firejail arguments |
| `new-native.sh`, `_launch-native.sh` | Create and launch native Linux games |
| `wq_debug.py` | Dependency checks and a redacted bug-report builder |
| `integrate.py` | One-time wiring into the main scripts |
| `test_core.py`, `test_profile.sh` | Tests |

## Toolbar

* **Add** opens a menu: New game…, Set executable…, Attach a shell script (before launch / after exit), Hide a /dev device…, Open game folder.
* **Launch / Stop** start and stop the selected games. Double-click a game to launch it.
* **Rescan** re-reads the games from disk. **Remove** moves the selected game to the Trash.
* **Settings** sets the quarantine folder, theme and custom CSS. **Debug** opens the checks and report builder.
* Right-click a game for Launch, Stop, Set executable, Open folder and Remove.

## Game types

**Windows** games are created by `new-quarantine.sh` and run through umu/Proton with their own prefix.

**Native Linux** games are created by `new-native.sh`. `game.conf` has `RUNNER=native` and `EXE=start.sh`. They use the same protection boxes and whitelists as Windows games, with these differences:

* Only `game/` is writable.
* With "Hide home directory" on, `$HOME` is `<game>/home`, so saves persist between runs.
* `verify-sandbox.sh` is not run and there is no registry check.
* The launcher exits with the game's own exit code.

## Tabs

* **Protection**: isolation and device switches, hidden `/dev` nodes, private X server and size.
* **Paths**: the folders the sandbox can see, extra whitelisted paths, and launch scripts.
* **Network**: off, filtered or learn mode, allow-list, interface, DNS, connection logging and a live view of attempts.
* **Monitor**: alerts and run summaries for the selected game.

Boxes show the effective value: this game's setting, else the default profile, else stock. A box in the middle state means the selected games differ.

## Keys in game.conf and profile.defaults.conf

The header of `profile.sh` lists them all. The ones added with native support: `RUNNER` (`native`), `FJ_DEV_BLOCK` (repeatable), `FJ_HOOK_PRE` and `FJ_HOOK_POST` (per game only, never read from the defaults file).

## Launch scripts

A before-launch or after-exit script runs on your machine with your permissions, not inside the sandbox. A failing before-launch script cancels the launch. Scripts get `WQ_GAME`, `WQ_GAMEDIR` and `WQ_QROOT` in the environment. Only attach scripts you trust.

## Tests

```bash
python3 wq-ui/test_core.py
bash wq-ui/test_profile.sh
```

`test_profile.sh` checks the argument building (blocked devices, hidden Wayland socket, launch scripts) without needing firejail. It doesn't test a real sandbox; for that, run a small probe script as a native game and read its output.
