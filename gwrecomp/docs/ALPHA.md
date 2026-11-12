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
| Save and load with creatures present | the saved game loads and shows the creatures; whether every creature returns to its exact saved position was **not measured** | manual |
| Genetic engineer (Jon) used on a creature | accepted: an action packet is emitted with Jon selected, he walks to the creature and an icon appears over it. What the action *does* to research was **not verified** | manual with the scripted tools |
| Research (progress, cost, result) | **not verified**: the pod panel shows a percentage that rose from 43% to 50% while creatures were bred and Jon was used, but what it measures was not established | |
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
automates the creature steps; it was written after the manual runs and has **not** been run end-to-end as a script.

## Known issues found while testing

- In runs where the intro videos were skipped with ESC, the intro sometimes started again right after the title appeared.
  It was not seen when the intro played to the end. The cause was not determined; some of those runs also had input
  misdirected by the test tool (below), so it may be partly an artefact.
- A click right after a screen change can be lost if it arrives before the new screen is running; a person clicking when the
  screen is visible does not hit it. (Several apparent "lost clicks" during this work were the test tool talking to a stale
  window or to a window hidden behind another application; the game recreates its window between the intro and the title.)
- The window cannot be captured by desktop screen capture on the test machine while it is covered; the tools read frames from
  the game instead.

## Known limits

- Needs the locally generated snapshot (above); needs your own game files for every step.
- Music needs a `.cue` image; there is no music from the install folder alone.
- The window must be a normal desktop window; it has only been used at 1200x900 and scaled by Windows.
- Anything not in the table above has not been played. Nothing here was tested on a machine other than the development one.
