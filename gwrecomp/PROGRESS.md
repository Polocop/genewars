# GWRecomp progress

Evidence levels used below:

- **Verified (source)** – recorded in committed code/docs/commit messages; automated tests exist or the artifact hash is pinned.
- **Reported (manual)** – observed by the maintainer during manual play; not reproducible from this repository alone.
- **Partial / Experimental / Pending / Unverified** – as named.

The test harness results and the interactive demo are *different things*: many checks run bounded harnesses on a resumed snapshot, not the stock executable booting from scratch.

## Status matrix

| Area | Status | Notes |
|---|---|---|
| LE parsing, function boundaries, x86-32 lifting to C | Verified (source) | Lifter driver + differential suites; upstream project state (2026-10-15) reported 6386 functions found, 250 lifts, legacy differential suites 78/0 and a 120-case semantic corpus passing. Figures come from the internal task queue, not published here |
| Native execution of lifted code on Windows | Verified (source) | v0.7 demo executable built deterministically (`tools/rebuild/expected_v07.json`, SHA-256 pinned) |
| Boot from the original entry point to the menu, natively | **Not achieved** | Internal gate status at the last generated state report: startup reaches `setup_game`; menu/`playintro` not reached by the pure original-byte path. Demo paths resume from a snapshot |
| First mission playable | Reported (manual) | Demo path with a snapshot; acceptable performance per maintainer. Not independently reproducible here |
| Unit movement, building, research | Reported (manual) | Manual tests only |
| Specialist-creature commands | **Partial** | Selection confirmed; the picker gate was causally traced but a creature order was *not yet accepted* in the last recorded run |
| Audio: Miles mixer through virtual SB16 | Partial | Original Miles mixer runs; V20.4 recorded 1,107 mixer invocations and 2,267,136 PCM bytes queued without observed failures; audible per maintainer; background hiss unexplained |
| CD-DA music | Experimental | Separate host path (`runtime/gw_cdda_audio.c`) |
| Smacker video | Experimental | Video via the original code with a silent BIOS-clock path (V13, fine clock V18.1); Smacker **audio**, IRQ0 and AIL timer path unimplemented |
| Save / load | Partial | Added V15/V16 (save integrity); manual load worked in tests; exact guest-state restoration after Load unverified |
| ESC menu access | Reported (manual) | |
| Transition intros → menu → game | Under investigation | State-difference analysis ongoing; first-click-lost after a screen change is a known bug |
| Rendering | Experimental | Terrain-renderer helper and bit-exactness investigations (`tools/terrain_renderer/`) |
| Full campaign | **Untested** | |

## Timeline (from Git history, 2026)

History below is from the maintainer's private working repository (24 commits, 26 Oct – 2 Nov). That history is not published as-is because it embeds game-derived evidence; see PROVENANCE.md.

| Date | Milestone |
|---|---|
| 26 Oct | Baseline of lifter, runtime, tools and evidence pointers |
| 27 Oct | Second specialist-creature picker gate documented; IFCTitle text regression made deterministic |
| 28 Oct | Opt-in write census / instruction watch diagnostics; function coverage analyzer |
| 1 Nov | v0.7 demo sources brought under version control (Krell harness, Smacker V13/V18.1, save/load V15/V16, CD-DA); reproducible rebuild procedure and acceptance data |
| 2 Nov | Miles mixer dispatch verified; virtual SB16 sink; opt-in reusable object cache; build fixes |

## Alpha 0.1 (2026-11-12): the game can be played from the menus

The most advanced playable code (the candidate called fix4: original `setup_game` -> intro videos -> title menu -> game loop) was
ported onto the public driver sources and checked on a clean-clone Level B build with real mouse and keyboard events on the
real window: title menu, new game, mission 1, select and move a specialist, ESC menu, save, load, sound. 12 of 12 scenario steps
pass (`tools/interactive/playtest.ps1`). Building a structure and loading a save through the debrief and galaxy map into
mission 2 were played with the same tools on an earlier build of the same code. `scripts/play.ps1` now starts the real-time
play mode (CD music when `GENEWARS_CUE` is set). Creature orders (breed, select, move) and the genetic engineer's order on a creature were exercised in mission 2 (2026-11-12, see ALPHA.md and Issue #8); research progress and long play are not verified. Details, evidence kinds and
known issues: [docs/ALPHA.md](docs/ALPHA.md). The start still uses the locally generated title snapshot (provisional).

## Reproducible build (verified 2026-11-11)

Levels B and C have been verified on the maintainers' machine only; they have not been run on a second machine because they need game files that must not go to public runners. How to verify them yourself: [docs/PORTABILITY.md](docs/PORTABILITY.md).

Procedure: `git clone` of the repository, then `scripts\setup.ps1`, `scripts\build.ps1 -Level A|B|C`, `scripts\test.ps1` (see `tools/rebuild/README_BUILD.md`). Inputs for B/C were the maintainers' own copies, read from their locations through the documented variables.

| Level | Result | What this does and does not show |
|---|---|---|
| A (no game files) | **Achieved** in a fresh clone: setup (venv with pinned packages, pcrecomp cloned from GitHub at `35548b8` with the patch hash-verified), all 14 runtime C units compiled, test suite run | Also reproduced on a clean GitHub-hosted Windows runner (CI): setup, Level A and the tests with identical counts. See [docs/PORTABILITY.md](docs/PORTABILITY.md) |
| B (game inputs) | **Achieved** in a fresh clone: all 8 phases exit 0, lifted C generated, 16 objects compiled, executable linked. A second clean build produced identical lifted C and 16/16 identical objects. The lifted C is byte-identical to the maintainers' latest generated file | Same machine, same toolchain, same inputs. The symbol map input is not obtainable by outsiders, so independent reproduction is currently impossible |
| C (smoke) | **Achieved**: the built executable opens the intro file through the virtual file system, initialises the virtual SB16 and runs the native game loop to the harness' own bound (Turn 420, 120 frames), exit code 0 | A bounded smoke run, not a gameplay test; nothing about the rest of the game |

Tests in a clean clone after setup (maintainers' machine and the hosted CI runner alike): 467 modules, 95 pass, 358 blocked by a named missing input, 14 known failures (triaged; they also fail with every private input present), 0 unexpected. One module passes only when files written by an earlier test run exist, which is a test-hygiene issue.

## Symbol map independence (verified 2026-11-11, on the maintainers' machine)

The build no longer needs `genewars-1_1.map` (details and numbers: [docs/SYMBOLS.md](docs/SYMBOLS.md)). Boundaries of lifted functions never came from the map; it supplied names, 23 cross-check evaluations and report labels. Identifiers are now address-based and the map is optional.

| Check | Result |
|---|---|
| New lifter in legacy-name mode vs previous lifter | byte-identical output |
| Lifter output with vs without the map | byte-identical |
| Old (map-named) vs new output after rewriting 538 identifiers | same multiset of lines, same 2176 function definitions in the same order; only the order of 1355 forward declarations differs |
| Level B, new code with vs without the map | identical lifted C, 16/16 identical objects, identical executable |
| Previously published build vs new build | every PE section identical (`.text` 26,383,360 bytes included); the files differ only in the symbol table |
| Level C smoke run of the build made without the map | exit 0, same bounded stop |

At that point the remaining blocker for independent Level B/C was `SAVE0.SAV`, a save the maintainers created; it was removed in the next section. Nothing was verified on a second machine or VM.

## Save-file independence (verified 2026-11-11, on the maintainers' machine)

`SAVE0.SAV` (a maintainers' test save) is no longer required: it was only a pre-flight digest check plus an assertion and evidence fields of the replay mode; the replay mode is not part of Levels B/C. The driver now has two explicit profiles, `no-saves` and `reference-save`, and refuses anything else ([docs/INPUTS.md](docs/INPUTS.md)).

| Check | Result |
|---|---|
| Level B, `reference-save` vs `no-saves` (same commit, public mode) | identical lifted C, 16/16 objects, guest image and executable (all PE sections); only the install manifest differs, by one line (the save's digest) |
| Level C smoke run of both | exit 0; same trace apart from values that vary between two runs of one build |
| Original game without a save (replay with the original OPTIONS plug-in) | probes `SAVE0.SAV` twice, DOS file-not-found, reads nothing; the 14 probes of slots 1-7 unchanged |
| Replay screen captures, 16 files | 14 identical; 2 differ in a few pixels (below) |
| Replay mode as a whole | **not completed in either profile** outside the maintainers' machine: it needs `evidence/genewars_11_titlescreen_dac6.raw` (oracle capture, unpublished) and a capture file from an earlier run; the pre-change driver stops at the same points |
| Tests | `tests/test_save_profiles.py` (9 self-contained tests; the suite is now 467 modules: 95 pass, 358 blocked, 14 known failures, 0 unexpected, measured on the fresh clone) |

Residual differences between the profiles, replay captures: the OPTIONS screen differs in 38 of 307,200 pixels (a 5x11 area) and the post-confirmation screen in 235 (a 14x31 area at the bottom left, where the specialist portrait is drawn). Two runs of the same profile give byte-identical captures (0 of 12 differ), so these two differences are deterministic and caused by the profile. In the OPTIONS screen the reference-save run draws a dark 4x11 marker that the no-saves run does not (a save-slot indicator, judging from the pixels); the cause of the portrait-area difference was not determined. Nothing was forced to match.

## What this document does not claim

The game is not complete. Not every item marked *Reported (manual)* has been re-verified for this publication, and the clean rebuild has not been reproduced outside the maintainer's machine.
