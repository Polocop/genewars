# Portability: what is verified, and how to verify Levels B and C on your machine

## What has been verified where

| Check | Maintainers' machine | Independent clean Windows (GitHub-hosted `windows-2022` runner) |
|---|---|---|
| Setup (venv with pinned packages, pcrecomp at the pinned commit, patch hash-verified, pinned mingw32 toolchain) | OK | OK |
| Level A (all 14 runtime C units compile) | OK | OK |
| Self-contained tests | 467 modules: 95 pass, 358 blocked, 14 known failures, 0 unexpected | identical numbers |
| Levels B/C refuse to run without game files, naming the missing input | OK | OK (checked by the workflow) |
| Level B (lifter + build of the executable from your game files) | OK in a fresh clone, public mode | **Not run: needs game files, which must never be placed on a public runner** |
| Level C (bounded smoke run) | OK | **Not run, same reason** |

The workflow is `.github/workflows/gwrecomp-level-a.yml`. It uses commit-pinned actions, and the MSYS2 package list is pinned by SHA-256 in `tools/rebuild/msys2-mingw32-packages.json` (MSYS2 retired its i686 packages, so they are installed with `pacman -U` from the archive). The runner has newer Python (3.13.17) and clang (20.1.8) than the reference (3.13.0 / 19.1.5); those differences are printed in the job summary, not hidden. Level A and the tests do not depend on them.

## Not verified yet

Levels B and C on a **second machine**. The maintainers have no spare Windows installation or VM (Windows Sandbox and Hyper-V are unavailable on the development machine), and the game files cannot go to a public CI runner. Until someone runs the procedure below, B and C are verified on one machine only.

## Verify Levels B and C on a second Windows installation

You need your own legitimate Gene Wars 1.1 files: the `GENEWARS` folder (contains `GW.EXE` and `DATA\`) and the `.cue` of your CD image. Nothing is uploaded anywhere.

1. Install Git, Python 3.10+ (reference 3.13), MSYS2 (https://www.msys2.org/) and LLVM clang (reference 19.1.5).
2. Clone the repository and run, from the `gwrecomp` folder:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-clean-machine.ps1 -InstallMsys2Packages -GenewarsInstall "<your GENEWARS folder>" -GenewarsCue "<your .cue file>"
```

3. It runs setup, Level A, the tests, then B and C, and writes `build\verify-report.md` (tool versions, exit codes, test counts and SHA-256 values of the build outputs; no paths, user names or game data).
4. Compare with `tools/rebuild/expected_levelB.json`:
   - the lifted-C and `closure.c` hashes must match whatever your compiler is (they depend only on the lifter and its inputs); a difference means the lifter or its inputs differ and is worth reporting;
   - the executable hash is expected to match only with the reference toolchain.
5. Paste the report into Issue #1 or a new issue, stating the Windows version and whether it was a clean install or a VM.

Without game files the script runs only setup, Level A and the tests and says so in the report.

## Using CI with game files

Do not. Hosted runners are public infrastructure. If you want CI for Levels B/C, use a self-hosted runner on a private machine of your own, keep the game files outside the repository, and never upload the resulting executable, maps, logs or artifacts.
