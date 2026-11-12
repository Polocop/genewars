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
"Manual" below means a person (the maintainer) played it in earlier sessions; "scripted" means the interactive scenario
below drove the real window; neither is a replay-harness result.

| Area | Status | Evidence kind |
|---|---|---|
| Start, intro videos (skippable), original title menu | works | scripted |
| New game -> mission 1 landing -> map | works | scripted |
| Select and move a specialist | works | scripted |
| Build a structure (extractor): placement, cost, construction | works | scripted |
| ESC options menu, save, load (state returns to the saved one) | works | scripted |
| Load a save from the end of mission 1 -> debrief -> galaxy map -> mission 2 briefing -> mission 2 | works | scripted |
| Sound effects | reaches the audio device | scripted + PCM capture |
| CD music | works when `GENEWARS_CUE` is set | scripted (log + level) |
| Creature selection and orders | **not tested** | |
| Research | **not tested** | |
| Long sessions | see PROGRESS.md for the latest soak figures | scripted sampler |
| Lost first click after a screen transition | **not reproduced** on title/mission/load/menu; may exist elsewhere | |
| Steady background loop during missions | present; not yet classified as original ambience or a mixer defect | PCM analysis |
| Output clipping in sound bursts | observed (peaks at full scale); cause unknown | PCM analysis |

## Known limits

- Needs the locally generated snapshot (above); needs your own game files for every step.
- Music needs a `.cue` image; there is no music from the install folder alone.
- The window must be a normal desktop window; it has only been used at 1200x900 and scaled by Windows.
- Anything not in the table above has not been played.
