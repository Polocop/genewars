# GWRecomp

**GWRecomp** is an experimental effort to run *Gene Wars* (Bullfrog Productions, 1996, v1.1 DOS4GW/Watcom LE executable) **natively on Windows, without DOSBox**, by statically lifting the original x86-32 code to C and running it on a modern host-platform layer (SDL2 video/audio/input, DOS/DPMI service emulation, a virtual SB16 for the original Miles mixer, CD-DA playback).

> **Status: research prototype.** It is *not* a finished port, the full campaign has not been tested, and it **cannot run without original game files that you must provide yourself**. See [PROGRESS.md](PROGRESS.md) for what is and is not verified.

## Relationship to the original project

This directory lives in a fork of [mefistotelis/genewars](https://github.com/mefistotelis/genewars), an open-source *re-implementation* effort (hand-written interfaces/classes in C/C++). GWRecomp takes a different, complementary route: **static recompilation of the original binary** instead of re-writing it function by function. The two efforts are independent; GWRecomp does not modify any upstream file, and upstream's work (symbol/structure knowledge in particular) is valuable reference for the recompilation. All upstream credit belongs to mefistotelis and contributors.

## What is in this directory

| Path | Contents |
|---|---|
| `runtime/` | Host layer: DOS/DPMI/INT services, CD-ROM/ISO9660 view, PIT 8254, VBE provider, virtual SB16 (Miles), CD-DA player, x87 and CPU-context helpers (C and Python) |
| `src/le_loader.py` | Parser/loader for the DOS4GW LE executable format |
| `tools/` | Lifter driver, function-boundary/coverage analyzers, oracle guard, rebuild scripts, terrain renderer experiment, probes |
| `tests/` | Unit/contract tests and the SDL2 demo harness (`test_ifctitle_creature_probe.{c,py}`) |
| `docs/` | Architecture, provenance and issue seeds |

## What you must provide (not distributed here)

- A legitimate copy of **Gene Wars v1.1** (the `GENEWARS` install: `genewars-1_1.exe`, `DATA/`, CD image/cue for CD-DA).
- Several development inputs derived from that copy (guest memory snapshot / evidence inputs listed in `tools/rebuild/evidence_inputs.json` by SHA-256). **These are intentionally not in this repository.**

## Requirements (as used by the author; Windows 11)

- Python 3.13 with `unicorn==2.1.4` (see `tools/rebuild/toolchain.lock.json`)
- MSYS2 mingw32 GCC + SDL2, LLVM clang (VS 2022 Build Tools)
- External lifter dependency [`sp00nznet/pcrecomp`](https://github.com/sp00nznet/pcrecomp) (MIT) at commit `35548b8d…` plus `tools/rebuild/patches/P01_pcrecomp_local_mods.patch`

## Building

The documented procedure is `tools/rebuild/rebuild.ps1` (see [`tools/rebuild/README_BUILD.md`](tools/rebuild/README_BUILD.md)). **Known limitation:** compiler, SDL and install paths are currently hard-coded to the author's machine (`E:\GWRecomp`, `E:\msys64`, …) and the clean rebuild has *not* been reproduced outside it. Parameterising these paths is the first good contribution (see `docs/ISSUES_SEED.md`).

## Running

`play_genewars_interactive.ps1 -InstallRoot <your GENEWARS install>` launches the SDL2 interactive demo from a prepared build. It requires the build artifacts and guest image described above; they are not provided.

## Tests

See [docs/TEST_STATUS.md](docs/TEST_STATUS.md): of 466 test modules, 92 pass on a clean checkout, 364 need inputs that are not published, 10 need triage.

## Current limitations

See [PROGRESS.md](PROGRESS.md) and [ROADMAP.md](ROADMAP.md). In short: no verified end-to-end native boot from the original executable; the playable demo path resumes from a snapshot; Smacker audio, IRQ0/AIL timer path and exact state restoration after *Load* are unverified; the full campaign is untested.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Good entry points are labelled in `docs/ISSUES_SEED.md`.

## Credits and legal

See [PROVENANCE.md](PROVENANCE.md). Gene Wars is © Bullfrog Productions / Electronic Arts. **No game executables, data, videos, audio, disc images or extracted game code are distributed here.** This project is unaffiliated with and unendorsed by the rights holders. **No license has been applied** to GWRecomp's original code yet (see PROVENANCE.md): until the authors choose one, default copyright applies. The upstream repository has no license file either.
