# GWRecomp

**GWRecomp** is an experimental effort to run *Gene Wars* (Bullfrog Productions, 1996, v1.1 DOS4GW/Watcom LE executable) **natively on Windows, without DOSBox**, by statically lifting the original x86-32 code to C and running it on a modern host-platform layer (SDL2 video/audio/input, DOS/DPMI service emulation, a virtual SB16 for the original Miles mixer, CD-DA playback).

> **Status: research prototype.** It is *not* a finished port and the full campaign has not been tested. **It cannot run without original game files that you must provide yourself**, and one required input (a save file the maintainers created, `SAVE0.SAV`) cannot currently be reproduced by outside contributors. See [PROGRESS.md](PROGRESS.md) for what is and is not verified and [tools/rebuild/README_BUILD.md](tools/rebuild/README_BUILD.md) for the exact build levels.

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

### What you must provide (not distributed here)
Your own Gene Wars **1.1 (Europe)** install folder and the `.cue` of your CD image, verified by SHA-256 (`python tools\rebuild\check_inputs.py` tells you which file differs and what role it has). **The symbol map is no longer needed**: the build is independent of it and produces the same code with or without it ([docs/SYMBOLS.md](docs/SYMBOLS.md)). **The remaining blocker for independent Level B/C is `SAVE0.SAV`**, a test save the maintainers made, which the build pins by digest ([docs/INPUTS.md](docs/INPUTS.md)); until that is resolved, Levels B and C are reproducible only by the maintainers.

## Tests

`scripts\test.ps1` classifies every module. After `setup.ps1` in a clean clone (no game files): of 466 modules, **94 pass**, **358 are blocked** by a named missing input (not failures), **14 are known failures** (triaged; they also fail with all private inputs present) and **0 fail unexpectedly**. See [docs/TEST_STATUS.md](docs/TEST_STATUS.md) and `scripts/test_triage.json`.

## Current limitations

See [PROGRESS.md](PROGRESS.md) and [ROADMAP.md](ROADMAP.md). In short: no verified end-to-end native boot from the original executable; the playable demo path resumes from a snapshot; Smacker audio, IRQ0/AIL timer path and exact state restoration after *Load* are unverified; the full campaign is untested; the clean rebuild (Level B/C) has been reproduced from a fresh clone only on the maintainers' machine, using the maintainers' copies of the inputs.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Good entry points are labelled in `docs/ISSUES_SEED.md` and in the repository's Issues.

## Credits and legal

See [PROVENANCE.md](PROVENANCE.md). Gene Wars is © Bullfrog Productions / Electronic Arts. **No game executables, data, videos, audio, disc images or extracted game code are distributed here.** This project is unaffiliated with and unendorsed by the rights holders. **No license has been applied** to GWRecomp's original code yet (see PROVENANCE.md): until the authors choose one, default copyright applies. The upstream repository has no license file either.
