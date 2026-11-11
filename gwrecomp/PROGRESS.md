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

## What this document does not claim

The game is not complete. Not every item marked *Reported (manual)* has been re-verified for this publication, and the clean rebuild has not been reproduced outside the maintainer's machine.
