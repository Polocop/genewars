# Alpha 0.1: what plays, what is provisional, what is not verified

GWRecomp can now be started in a real-time play mode and driven with the mouse and keyboard through the original
menus, the first missions and the original save/load screens. This is **not** a finished port: it needs your own copy of
the game, it starts from a locally generated snapshot (below) and large parts of the game have not been played yet.

## How to run it (needs your own Gene Wars 1.1 files)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup.ps1 -GenewarsInstall "<GENEWARS folder>" -GenewarsCue "<disc .cue>"
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1 -Level B     # about 7 minutes, once
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\play.ps1                # the game
```

`play.ps1` without `-SmokeFrames` is the Alpha play mode: real-time window, digital sound effects (virtual SB16) and, when
`GENEWARS_CUE` is set, CD music from your own disc image. Without the cue there is no music. Intro videos play first;
ESC or a click skips each one. Saved games are written next to the build (`work\dos_vfs_overlay\SAVE`), never into your
game folder.

## Provisional start (stated plainly)

The game does not start from the original entry point yet. Level B generates, from your files, a memory snapshot taken
after the original `setup_game` has run; the native code resumes from it, then runs the original intro videos, the original
title menu and everything after. The snapshot is built locally, is derived from your game files and is never published or
shipped. Removing this dependency (starting from the original entry point) is a separate goal and does not block the
Alpha.

## What has been exercised, and how

Test method: the real executable, real OS mouse and keyboard events (`tools/interactive/`), and the frame the game
presents, read from the game itself (`GW_FRAME_DUMP_DIR`), because screen capture of the SDL window is black on the
machine used. Sound is checked through a PCM capture of the virtual SB16 and the Windows audio-session level.
"Scripted" below means the interactive scenario drove the real window; "manual with the scripted tools" means the same input
tools were used step by step (looking at the presented frames), on an earlier build of the same code. Neither is a
replay-harness result, and no person other than the tool driver played these sessions.

| Area | Status | Evidence kind |
|---|---|---|
| Start, intro videos, original title menu | works (intro runs ~3 min; each video can be skipped, see Known issues) | scripted, 12/12 scenario steps |
| New game -> mission 1 landing -> map | works | scripted |
| Select and move a specialist | works | scripted |
| Build a structure (extractor): placement, cost, construction | works (done in an earlier build of the same code, by hand with the scripted tools) | manual with the scripted tools |
| ESC options menu, save, load (state returns to the saved one) | works | scripted |
| Load a save from the end of mission 1 -> debrief -> galaxy map -> mission 2 briefing -> mission 2 | works (earlier build of the same code) | manual with the scripted tools |
| Sound effects | reach the audio device (7 MB of PCM in the scenario) | scripted + PCM capture |
| CD music | works when `GENEWARS_CUE` is set | log + audio level |
| Breed a creature (mission 2: extractor, distributor and genetic pod built by hand, then the pod's breed button) | works: goop drops by the creature's cost (75), a mule appears next to the pod | manual with the scripted tools |
| Select a creature, order it to move | works: the original picker commits it, the click selects it, the ground click emits an action packet and the creature walks there (several runs, three different creatures) | manual with the scripted tools + read-only trace |
| Save and load with a creature present | works: a creature's record in guest memory (position-like pairs, path waypoints) is identical at save and after load, and different after it was ordered elsewhere in between (one run, one creature, see Research and save/load below) | manual with the scripted tools + guest-memory dumps |
| Genetic engineer (Jon) studies a creature | works: with the creature selected first, then Jon, then the creature as his target, the pod percentage went from 45% to 50% (the pod's cap) within about 10 s and goop did not change (986 before and after). Seen twice, in two sessions | manual with the scripted tools + frames |
| Research (progress, cost, result) | partly verified, see "Research" below: the percentage is the species' research level (mule), starts at 43%, +1% per bred creature, capped at 50% by the genetic pod; Jon's study takes it to the cap at no goop cost. Not verified: what a higher level changes, hybrids, the pod's second button, the exact memory cell | manual with the scripted tools + frames |
| `tools/interactive/creatures.ps1` (breed, select, ground order, Jon's order) | passes 4/4 against a live mission 2 (two runs, after fixes to the script) | scripted |
| Long sessions | 17 minutes idle in a mission: memory (114 MB) and handles constant, frames keep changing. Not tested with play or for hours | scripted sampler (`tools/interactive/soak.ps1`) |
| Steady background loop during missions | present (period 0.85 s, 1-6 kHz, about half of full scale); not yet classified as original ambience or a mixer defect | PCM analysis (`pcm_stats.py`) |
| Output clipping in sound bursts | observed (peaks at full scale); cause unknown | PCM analysis |

The scenario is `tools/interactive/playtest.ps1` (12 steps: window, title, new game, select, move, ESC menu, save, OK, load,
stability, sound). On the clean-clone Level B build of this commit all 12 pass.

## Creature orders (Issue #8)

In the earlier recorded run a creature was selected but never accepted an order, because the picker rejected it at one test of
`MapDisplay+0x1C` bit 0. In the Alpha, played from the start, that bit is set for most frames of a running mission (about 79% of
2.3e5 sampled frames in one session), the picker commits the creature to `MapDisplay+0x18` on hover, and orders are emitted. So
the gate is a legitimate game state that the old turn-725 snapshot did not have, not a defect of the recompilation; no code
change was needed for creatures. Because the picker recomputes its candidate every game tick, a click must land while the creature
is under the cursor; creatures wander, so a click made a second after hovering can miss (this looked like "creatures do not
accept orders" in several test runs and was the test timing, not the game). The read-only trace (`GW_ORDER_TRACE=<file>`)
records selected unit, picker candidate, `MapDisplay` fields and the 11-byte action packet. `tools/interactive/creatures.ps1`
automates the creature steps and has now been run end-to-end against a live mission 2 (4/4 steps, twice; the first runs exposed
script problems, not game problems: it ignored the pod when a unit was selected, took specialists' red clothes for the creature and
clicked stale positions, all fixed).

## Research (genetic pod, mission 2)

What the original game says (its own text, `DATA/TEXT.DAT`, Spanish build): the genetic engineer "studies new creatures, making their
future production possible"; the genetic pod "allows creature research levels of up to 50%" (the genetic machine up to 75%, the lab
full research); pods cannot breed hybrids until upgraded. What was measured in the running game, in three sessions:

- The number under the creature picture in the pod panel is the research level of that species. It starts at 43% for the mule.
- Each creature bred raises it by 1% (43, 44, 45, 46, 47; seven mules, goop 1136 to 611, gave exactly 50%). Breeding costs 75 goop each.
- It stops at 50% with the pod: further breeds left it at 50%.
- Jon (genetic engineer): selecting the creature first, then Jon, then clicking the creature, took the level from 45% to 50% within
  about 10 s, goop unchanged. Two earlier orders to a creature without selecting it first changed nothing visible in 3 minutes, so
  the order of clicks seems to matter; that was not investigated further.
- Saved games contain the level: a save made at 44% loaded back as 44% after the level had reached 50%.
- Guest memory (dumps with `GW_MEM_DUMP`): the percentage is not stored as a plain integer (no cell of 43/44/50 or scaled forms was
  found); at Jon's study several bytes of the creature's record move to 200. The cell behind the displayed percentage was **not** found.
- The pod panel's second round button (green) did nothing visible and emitted no packet; the original text says hybrids need an
  upgraded pod. Not tested: upgrading, hybrids, what a higher level changes (displayed stats stayed 7/4/9/2 while the level moved).

## Save and load with a creature

One run, one bred creature in a fresh mission 2: it was ordered to a spot, the game saved, the creature was ordered elsewhere, the
game loaded. Words of its record in guest memory (position-like pairs and the path waypoints) were equal at save and after load
(also 5 s later) and different in between. Screen-position measurements of the creature were too noisy to use (it wanders and
the diff picks up other red sprites).

## Known issues found while testing

- In runs where the intro videos were skipped with ESC, the intro sometimes started again right after the title appeared.
  It was not seen when the intro played to the end. The cause was not determined; some of those runs also had input
  misdirected by the test tool (below), so it may be partly an artefact.
- A click right after a screen change can be lost if it arrives before the new screen is running; a person clicking when the
  screen is visible does not hit it. (Several apparent "lost clicks" during this work were the test tool talking to a stale
  window or to a window hidden behind another application; the game recreates its window between the intro and the title.)
- On a machine with a high-DPI second monitor the game window came up larger than the screen and clicks landed off-screen (the
  intro then seemed to loop). `gwctl.ps1` now shrinks such a window before computing coordinates (`Fit-Window`). In mission 2 the
  creatures were not drawn while specialists stood on the pod's exit; the camera scrolls only with the cursor at the very edge and
  is fast. A creature may also disappear from view quickly: it wanders.
- The window cannot be captured by desktop screen capture on the test machine while it is covered; the tools read frames from
  the game instead.

## Known limits

- Needs the locally generated snapshot (above); needs your own game files for every step.
- Music needs a `.cue` image; there is no music from the install folder alone.
- The window must be a normal desktop window; it has only been used at 1200x900 and scaled by Windows.
- Anything not in the table above has not been played. Nothing here was tested on a machine other than the development one.
