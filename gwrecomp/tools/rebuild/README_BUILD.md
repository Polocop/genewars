# Building GWRecomp

GWRecomp lifts the original *Gene Wars* 1.1 executable to C and links it with the host runtime in this repository. The build has
three levels. Run them in order; each one states exactly what it needs.

| Level | Needs your game files? | What it does | Command |
|---|---|---|---|
| **A** | no | checks the toolchain, installs pcrecomp at the pinned commit with the documented patch, compiles all runtime C units, runs the independent tests | `scripts\setup.ps1`, `scripts\build.ps1 -Level A`, `scripts\test.ps1` |
| **B** | **yes** | lifts the executable, compiles and links the demo executable from a clean clone of the committed repository | `scripts\build.ps1 -Level B` |
| **C** | **yes** (+ a Level B build) | starts the native executable for a bounded smoke run | `scripts\build.ps1 -Level C` or `scripts\play.ps1` |

All commands are Windows PowerShell commands run from the `gwrecomp` directory. Because script execution is disabled by default on
many systems, start them with a process-scoped bypass (this changes no system setting):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup.ps1
```

The scripts find their own location, so the repository can live in any directory. Do not copy files into it from elsewhere.

## 1. Install the public dependencies

| Dependency | Reference version | How to get it |
|---|---|---|
| Git | any recent | https://git-scm.com/download/win |
| Python | 3.13.0 (3.10+ should work) | https://www.python.org/downloads/windows/ |
| Python packages | `capstone==5.0.9`, `unicorn==2.1.4` | installed by `scripts\setup.ps1` into `.venv` from `tools\rebuild\requirements.txt` |
| MSYS2 + mingw32 packages | gcc 16.2.0, SDL2 2.32.10, binutils 2.47, crt | install MSYS2 (https://www.msys2.org/), then `scripts\setup.ps1 -InstallMsys2Packages` (runs `pacman -S --needed mingw-w64-i686-gcc mingw-w64-i686-SDL2 mingw-w64-i686-binutils mingw-w64-i686-crt-git`) |
| LLVM / clang | 19.1.5 | `winget install --id LLVM.LLVM --version 19.1.5 -e`, or Visual Studio 2022 Build Tools with the LLVM component |
| pcrecomp (lifter, MIT) | commit `35548b8d0fd8aa853da67edcf7cd6134f6b9cdc7` + `patches\P01_pcrecomp_local_mods.patch` | cloned and patched (SHA-256 verified) by `scripts\setup.ps1` into `third_party\pcrecomp` |

`scripts\setup.ps1` never changes anything outside the repository directory except the MSYS2 packages when you pass
`-InstallMsys2Packages`. It is safe to re-run. The pinned versions are in `tools\rebuild\toolchain.lock.json`; `rebuild.ps1` reports
differences as warnings (errors with `-Strict`), because other compilers may build but are not guaranteed to be byte-identical.

### Where the tools are looked up
Resolution order for every location: explicit parameter, then environment variable, then `gwrecomp.local.json` (Git-ignored,
written by `setup.ps1 -Genewars...`), then auto-detection.

| Variable | Meaning | Auto-detection |
|---|---|---|
| `GWRECOMP_PYTHON` | python.exe | `.venv`, then `python` on PATH |
| `MSYS2_ROOT` | MSYS2 install with `mingw32` | gcc on PATH, then `C:\msys64` |
| `GWRECOMP_CLANG_X64`, `GWRECOMP_CLANG_X86` | clang for the large lifted unit / for linking | `clang` on PATH, VS 2022 LLVM, `Program Files\LLVM` |
| `PCRECOMP_ROOT` | pcrecomp checkout | `third_party\pcrecomp` |
| `GWRECOMP_WORK` | build output root | `build\` |
| `GENEWARS_INSTALL_DIR`, `GENEWARS_CUE`, `GENEWARS_MAP` (optional) | your game inputs (below) | none |

## 2. Level A: no game files

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1 -Level A
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test.ps1
```

`test.ps1` runs every `tests\test_*.py` module and sorts the outcome: **PASS**, **BLOCKED** (a named input is missing; not a failure),
**KNOWN_FAIL** (triaged, fails even with all private inputs; see `scripts\test_triage.json`) and **FAIL** (unexpected; exit code 1).
`docs\TEST_STATUS.md` has the current numbers.

## 3. Inputs you must supply (Levels B and C)

None of these are distributed here and none may be committed. `python tools\rebuild\check_inputs.py` (also run by `setup.ps1` and `build.ps1`) reports each as PASS / MISSING / MISMATCH against `tools\rebuild\inputs.json` and the version profile `tools\rebuild\profiles\gw11-europe.json`, and tags every install file with its role. Details and the reasoning are in [`docs/INPUTS.md`](../../docs/INPUTS.md).

| Input | Variable | Notes |
|---|---|---|
| Your Gene Wars **1.1 (Europe)** `GENEWARS` folder | `GENEWARS_INSTALL_DIR` | 15 files are hashed: 11 are byte-identical to files on the retail Europe disc, 2 (`GW.EXE`, `DATA/TEXT.DAT`) come from the 1.1 update, `CONFIG.INI` is written by the installer, `SAVE/SAVE0.SAV` is a maintainers' test save (see below) |
| `.cue` of your Gene Wars CD image | `GENEWARS_CUE` | accepted if it is the verified cue text, or any cue whose five track images match the SHA-256 recorded in the profile |
| Reference symbol map `genewars-1_1.map` | `GENEWARS_MAP` | **optional**. Not needed to build. Enables extra cross-checks only (see [`docs/SYMBOLS.md`](../../docs/SYMBOLS.md)) |

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup.ps1 -GenewarsInstall "<GENEWARS folder>" -GenewarsCue "<file.cue>"
```

### Open problem: `SAVE0.SAV`
The driver pins the digest of a save file the maintainers created while testing; it is not part of the game. Without a file with exactly that content, Level B stops while hashing it. Another user cannot produce it. This is currently the blocker for independent Level B/C reproduction (see `docs/INPUTS.md`, section 2). The symbol map, previously the main blocker, is no longer needed.

## 4. Level B: generate and build the recompiled executable

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1 -Level B
```

This calls `tools\rebuild\rebuild.ps1`, which works only on the **committed** state (commit or stash your edits first):

1. checks the toolchain against `toolchain.lock.json`
2. clones this repository into `<work>\src` at the exact commit
3. clones pcrecomp at the pinned commit and applies the patch (hash-verified)
4. copies `GW.EXE` (and the map, if you supplied one) from your configured locations and verifies their SHA-256
5. runs the driver `tests\test_ifctitle_creature_probe.py`: lifts the executable to C (about 60 MB), compiles it with clang, builds the
   runtime and harness, produces the guest image and install manifest
6. links `gw_demo_sdl2.det.exe` deterministically and writes `rebuild_manifest.json` with every phase and hash

Output goes to `build\rebuild-<timestamp>\` (a new directory every time). Useful options: `-Strict` (toolchain differences become
errors), `-Lift reuse`, `-ReuseObjectCacheId <id>` (see below).

### Opt-in reusable object cache
By default every build recompiles everything. To reuse compiler objects between builds, pass a stable cache id; builds with the same id
are serialized by a file lock:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\rebuild\rebuild.ps1 -Work build\candidates\try1 -ReuseObjectCacheId my-cache -DryRun
```
The cache lives under `<GWRECOMP_WORK>\reusable-object-cache\<id>`. The key covers compiler flags, source bytes, transitive headers and
compiler identity; a changed input is a miss. Nothing is pruned automatically. `-ObjectCacheDiagnostics` records the key inputs;
see `OBJECT_CACHE_ACCEPTANCE.md` for the maintainers' acceptance notes (Spanish).

## 5. Level C: run

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\play.ps1            # interactive
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1 -Level C  # bounded smoke run
```
`play.ps1` uses the newest `build\rebuild-*`. `-Backend terrain_modern` selects an experimental renderer.
Level C proves only that the executable starts and exits cleanly; it is not a gameplay test.

## 6. Known problems and how to diagnose them

| Symptom | Cause / action |
|---|---|
| "running scripts is disabled on this system" | use `-ExecutionPolicy Bypass` as shown (process scope only) |
| `MSYS2_ROOT is not configured` / gcc not found | install MSYS2 (default `C:\msys64`) or set `MSYS2_ROOT`; then `setup.ps1 -InstallMsys2Packages` |
| `clang not found` | install LLVM 19.1.5 or set `GWRECOMP_CLANG_X64` |
| `pcrecomp patch failed: pre-image mismatch` | the pcrecomp checkout is not at the pinned commit or line endings differ; delete `third_party\pcrecomp` and re-run `setup.ps1` (it sets `core.autocrlf=true` as the patch images require) |
| `input ... has SHA-256 X, expected Y` | your file is a different build/dump than the one the harness supports; see section 3 |
| `check_inputs.py` MISSING `SAVE/SAVE0.SAV` | see "Open problem: `SAVE0.SAV`" |
| toolchain warnings from `rebuild.ps1` | your versions differ from `toolchain.lock.json`; the build may still work; use `-Strict` to enforce |
| test shows BLOCKED | a named input is missing; not a bug. KNOWN_FAIL entries are tracked in `scripts\test_triage.json` |
| tests write into `evidence\`, `build\`, `cache\` | these are Git-ignored; delete them freely |
| Windows PowerShell shows `NativeCommandError` for compiler warnings | already handled in the scripts; if you write your own, set `$ErrorActionPreference='Continue'` around native calls |
| build output differs from `expected_v07.json` | that file describes the frozen v0.7 tree; the public sources were sanitised (see `PROVENANCE.md`). Do not "fix" it by regenerating it before deciding which binary should be validated (open issue) |

## 7. What is in git and what is not

| Piece | Where |
|---|---|
| Build driver, runtime, harness, tools | this repository |
| Lifter dependency pcrecomp | external: pinned commit + `patches\P01_pcrecomp_local_mods.patch` (+ `LICENSE-pcrecomp-MIT.txt`) |
| DOS environment fixture | `tools\rebuild\fixtures\dos_environment.json` (DOSBox defaults + BLASTER; no game data) |
| Game install and CD image | **yours**; names and hashes in `inputs.json` and the version profile. The symbol map is optional and also yours |
| Generated lift (`*.base.c`, ~60 MB), objects, executables, guest image | never committed; regenerated |

## 8. pcrecomp: pinned commit plus versioned patch
The original build used a local clone of `github.com/sp00nznet/pcrecomp` at `35548b8` with five uncommitted edits
(`runtime/recomp32/recomp_types.h`, `tools/disasm/disasm32.py`, `tools/lift/{difftest,lift32,lift32_cpu}.py`), preserved as
`patches\P01_pcrecomp_local_mods.patch` and pinned by SHA-256 in `P01_pcrecomp_local_mods.json`. To move to an own fork: fork pcrecomp,
check out `35548b8`, apply P01 with `apply_pcrecomp_patch.py`, commit, point `pcrecomp.repository`/`commit` in the lock file at the fork,
delete P01, rebuild and compare the results.
