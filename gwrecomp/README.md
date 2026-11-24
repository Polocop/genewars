# GWRecomp

> **v1.2:** features, installation and the legal notice for players are in the [repository README](../README.md).
> This page covers building from source and the project's internals.

**GWRecomp** is an experimental effort to run *Gene Wars* (Bullfrog Productions, 1996, v1.1 DOS4GW/Watcom LE executable) **natively on Windows, without DOSBox**, by statically lifting the original x86-32 code to C and running it on a modern host-platform layer (SDL2 video/audio/input, DOS/DPMI service emulation, a virtual SB16 for the original Miles mixer, CD-DA playback).

> **Status: research prototype.** It is *not* a finished port and the full campaign has not been tested. **It cannot run without original game files that you must provide yourself.** No file created by the maintainers is required to build it any more. See [PROGRESS.md](PROGRESS.md) for what is and is not verified and [tools/rebuild/README_BUILD.md](tools/rebuild/README_BUILD.md) for the exact build levels and [docs/PORTABILITY.md](docs/PORTABILITY.md) for what has been verified on an independent machine.

## Relationship to the original project

This directory lives in a fork of [mefistotelis/genewars](https://github.com/mefistotelis/genewars), an open-source *re-implementation* effort (hand-written interfaces/classes in C/C++). GWRecomp takes a different, complementary route: **static recompilation of the original binary** instead of re-writing it function by function. The two efforts are independent; GWRecomp does not modify any upstream file, and upstream's work (symbol/structure knowledge in particular) is valuable reference for the recompilation. All upstream credit belongs to mefistotelis and contributors.

## What is in this directory

| Path | Contents |
|---|---|
| `runtime/` | Host layer: DOS/DPMI/INT services, CD-ROM/ISO9660 view, PIT 8254, VBE provider, virtual SB16 (Miles), CD-DA player, x87 and CPU-context helpers (C and Python) |
| `src/le_loader.py` | Parser/loader for the DOS4GW LE executable format |
| `tools/` | Lifter driver, function-boundary/coverage analyzers, rebuild scripts, terrain renderer experiment, probes |
| `tests/` | Unit/contract tests and the SDL2 demo harness (`test_ifctitle_creature_probe.{c,py}`) |
| `scripts/` | `setup.ps1`, `build.ps1`, `test.ps1`, `play.ps1` (entry points), `run_tests.py`, `gwconfig.ps1` |
| `docs/` | Architecture, provenance, test status, issue seeds |

## Quick start

Everything runs from the `gwrecomp` directory in Windows PowerShell. Start scripts with the process-scoped bypass shown (it changes no system setting). The repository can be cloned anywhere.

```powershell
git clone https://github.com/Polocop/genewars.git
cd genewars
git checkout gwrecomp-native-port
cd gwrecomp
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup.ps1      # venv, pinned packages, pcrecomp + patch; reports what is missing
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1 -Level A   # no game files: compile the runtime units
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test.ps1       # classified test run
```

Prerequisites you install yourself: Git, Python 3.10+ (reference 3.13), MSYS2 with the mingw32 gcc/SDL2 packages (`setup.ps1 -InstallMsys2Packages` can install the packages), LLVM clang 19.1.5. Versions and details: [README_BUILD.md](tools/rebuild/README_BUILD.md).

### Levels
- **Level A** (no game files): toolchain check, pcrecomp at its pinned commit with the documented patch, compile all runtime C units, run the independent tests.
- **Level B** (needs your game files): lift the executable, compile and link the demo from a clean clone of the committed state: `scripts\build.ps1 -Level B`.
- **Level C** (needs a Level B build): bounded smoke run of the native executable: `scripts\build.ps1 -Level C`, or `scripts\play.ps1` to play.

### Playing: launcher, profiles and keys
The launcher (double-click `gwrecomp.exe`) saves everything at once in `gwrecomp.ini`, keeping any other key you added.
- **GRAPHICS → PROFILE**: `CLASSIC 1996` (original look, every effect off), `HD-2D (v1.1)` (bloom, soft shadows, terrain AO,
  water effects, 4K particles, 120 Hz cursor; flat terrain), `3D TERRAIN (v2.0)` (all of the above plus the 3D terrain and
  its options). Changing any switch by hand shows `CUSTOM`.
- **3D TERRAIN** tab: 3D terrain, 3D shadows, 3D water, 3D lights, 3D biomes, HD textures (with the `hd_textures` status),
  smooth zoom, 120 Hz cursor. **AUDIO** tab: music and effects volume (0-100 %).
- In a mission: mouse wheel = zoom of the map (0.87x-2x, the HUD stays fixed), `Home` = back to 1x, hold the middle
  button and drag = scroll, WASD/arrows = scroll, `F7` filter, `F8` turbo, `TAB` hold for turbo 4x, `F10` release the
  mouse, `Ctrl+F9` 2D/3D terrain, `Ctrl+F11` 3D point lights, `Ctrl+F12` HD terrain tiles.
- In 3D, `Ctrl+F7` cycles Auto → Noon → Sunset → Night → Off. Auto starts at noon and
  completes a cycle every 360 seconds by default. `Ctrl+F8` cycles Auto → Clear → Moderate
  → Storm → Off. Organic storms use lightning and Brown uses warm embers. Set the
  atmosphere defaults and water reflections in `gwrecomp.ini`
  using the keys in `gwrecomp.ini.example`.
- HD terrain tiles: `python tools\export_b32_tiles.py --out <folder of gwrecomp.exe>\hd_textures` exports the terrain
  banks of **your own** install (one folder per bank: tiles, atlas and `manifest.json` with the missions that use it);
  upscale them with your own tools, keep the names. Nothing of the game is stored in this repository.

### What you must provide (not distributed here)
Your own Gene Wars **1.1 (Europe)** install folder (11 files byte-identical to the retail disc, 2 from the 1.1 update, the installer's `CONFIG.INI`) and the `.cue` of your CD image, verified by SHA-256 (`python tools\rebuild\check_inputs.py` tells you which file differs and what role it has). A fresh installation with an empty `SAVE` directory is supported; **the symbol map and any save file are not needed** ([docs/SYMBOLS.md](docs/SYMBOLS.md), [docs/INPUTS.md](docs/INPUTS.md)). Not verified: that the 1.1 update files are obtainable by everyone, and any second machine.

## Tests

`scripts\test.ps1` classifies every module. After `setup.ps1` in a clean clone (no game files): of 467 modules, **95 pass**, **358 are blocked** by a named missing input (not failures), **14 are known failures** (triaged; they also fail with all private inputs present) and **0 fail unexpectedly**. See [docs/TEST_STATUS.md](docs/TEST_STATUS.md) and `scripts/test_triage.json`.

## Current limitations

See [PROGRESS.md](PROGRESS.md) and [ROADMAP.md](ROADMAP.md). In short: no verified end-to-end native boot from the original executable; the playable demo path resumes from a snapshot; Smacker audio, IRQ0/AIL timer path and exact state restoration after *Load* are unverified; the full campaign is untested; the clean rebuild (Level B/C) has been reproduced from a fresh clone only on the maintainers' machine (inputs were the maintainers' copies, but none created by them any more); the driver's replay/regression mode still needs maintainers' artifacts.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Good entry points are labelled in `docs/ISSUES_SEED.md` and in the repository's Issues.

## Credits and legal

See [PROVENANCE.md](PROVENANCE.md). Gene Wars is © Bullfrog Productions / Electronic Arts. **No game executables, data, videos, audio, disc images or extracted game code are distributed here.** This project is unaffiliated with and unendorsed by the rights holders. GWRecomp's own work in this directory is under the **[MIT license](LICENSE)**; its scope (what it does not cover: the game, code derived from `GW.EXE`, third-party material) is stated there and in PROVENANCE.md, section 4. The upstream re-implementation keeps the GPL-2.0-or-later notice of its file headers.
