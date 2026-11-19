# GWRecomp v1.0 — Gene Wars, natively on Windows

<p align="center">
  <img src="gwrecomp/docs/screenshots/widescreen.png" alt="Mission 1 in widescreen 854x480: an extractor built on the GOOP field and the translucent placement ghost of the next one" width="100%">
  <br><em>Mission 1 (Exceland) in widescreen 854×480: an extractor on the GOOP field, the next one being placed, animated sea</em>
</p>

**GWRecomp** runs *Gene Wars* (Bullfrog Productions, 1996, version 1.1) as a native Win32 program, without DOSBox.
The original x86-32 DOS4GW executable is statically lifted to C and runs on a modern host layer (SDL2 video, audio
and input, DOS/DPMI services, a virtual Sound Blaster for the game's own Miles mixer, CD-DA playback). The game logic,
AI and mixer are the original code; the host only replaces the hardware and DOS around it.

It needs **your own copy of Gene Wars 1.1**: no game files are included (see [Legal](#legal)).

## Screenshots

<table>
  <tr>
    <td width="50%"><img src="gwrecomp/docs/screenshots/zoomout.png" alt="Zoom Out on the 1152x640 canvas at 0.87x"></td>
    <td width="50%"><img src="gwrecomp/docs/screenshots/classic.png" alt="Classic 640x480"></td>
  </tr>
  <tr>
    <td align="center"><em>Zoom Out: the 1152×640 map canvas at 0.87×, sharp scaling</em></td>
    <td align="center"><em>Classic 640×480, as in 1996</em></td>
  </tr>
  <tr>
    <td width="50%"><img src="gwrecomp/docs/screenshots/launcher-play.png" alt="Native launcher: mission selection"></td>
    <td width="50%"><img src="gwrecomp/docs/screenshots/launcher-display.png" alt="Native launcher: display options"></td>
  </tr>
  <tr>
    <td align="center"><em>Native launcher: start, continue or pick any of the 24 missions</em></td>
    <td align="center"><em>Display options: view mode, resolution, 60/120 FPS, filter, water and GOOP</em></td>
  </tr>
  <tr>
    <td colspan="2" align="center"><img src="gwrecomp/docs/screenshots/planet.png" alt="Planet system screen" width="60%"><br><em>The original planet-system screen, with its sounds</em></td>
  </tr>
</table>

The source lives in [`gwrecomp/`](gwrecomp/README.md). This repository is a fork of
[mefistotelis/genewars](https://github.com/mefistotelis/genewars), whose engine re-implementation is kept unchanged
[below](#upstream-genewars-engine-re-implementation).

## Features

- **Native Win32/SDL2 build** of the original executable: one `gwrecomp.exe` plus `SDL2.dll`, no DOSBox, no emulator.
- **Deterministic regression check:** the A/B suite renders 56 frame captures at four points of mission 1 (after
  the landing, before a creature is ready, during construction, extractor selected) and compares them with reference
  hashes; v1.0 matches all 56 bit for bit. The presentation extras (interpolation, water, audio) never write game
  memory, so they cannot change these frames.
- **Three view modes:**
  - Classic `640×480` (the original frame),
  - Widescreen `854×480`,
  - Zoom Out on a `1152×640` map canvas (wheel zoom 0.87×–2×, Home returns to 1×).
- **Sharp scaling to any window or monitor:** supersampled sharp-bilinear (pixel interiors stay solid, only the seams
  blend), exact nearest when the window is a whole multiple; F7 switches sharp / EPX / CRT.
- **120 FPS presentation** with camera scroll interpolation; the simulation keeps the game's own tick rate.
- **Animated water and GOOP:** sea ripples and drifting glints, soft highlights on GOOP, on ground pixels only and in
  the presented frame only (units, buildings and HUD are never touched).
- **Complete audio:**
  - Smacker video sound,
  - the original Miles sound effects through a virtual SB16,
  - automatic CD-DA music from your own `.cue` image,
  - stereo panning and distance fade calibrated to the visible map width,
  - subtle ±4.5 % pitch variation on effects (never on voices),
  - music ducking while a voice speaks.
- **Native graphical launcher:** mission selector 1–24, Continue, view/resolution/filter/audio options, all saved
  in `gwrecomp.ini`.

## Installation (English)

1. Have **Gene Wars 1.1 (European edition)** installed: the `GENEWARS` folder created by the original installer
   (`DATA`, `LEVELS`, `SOUND`, `INTRO`, `ANIMS`, `LDATA`, `S`, `SPEECH`, `SAVE` and the loose files such as `GW.EXE`).
   GWRecomp checks them with SHA-256 and only reads them.
2. Unzip `GWRecomp-v1.0-win32.zip` anywhere you can write (saves and logs go next to the program).
3. Double-click `gwrecomp.exe`. In the launcher press **CAMBIAR** and choose your `GENEWARS` folder; the four marks
   DATA / LEVELS / SOUND / INTRO turn green.
4. Start the game, continue the last game, or pick a mission.

**First start:** the first time you enter the game, `gwrecomp.exe` prepares two files in `work\` from *your* `GW.EXE`
(checked by SHA-256). It takes a moment and happens once. Those files come from your copy of the game: do not share
them.

**`gwrecomp.ini`** (the launcher writes it; `gwrecomp.ini.example` documents every key):

| Key | Meaning |
|---|---|
| `mode` | `classic`, `widescreen` or `zoomout` |
| `resolution`, `fullscreen` | window size (`auto`, `1080p`, `1440p`, `2160p`, `WxH`), borderless fullscreen |
| `fps` | presentation rate, `60` or `120` |
| `filter` | `sharp`, `epx` or `crt` (also F7 in game) |
| `water_effects` | animated water and GOOP (`1`/`0`) |
| `enhanced_audio` | calibrated panning, pitch variation, music ducking (`1`/`0`) |
| `cd_cue` | path to your own Gene Wars CD image `.cue`, for the CD music |
| `data_dir` | your `GENEWARS` folder (the launcher fills it in) |

In game: F7 filter, F8 turbo 1×/2×/4×, mouse wheel zoom, Home zoom 1×, F10 release the mouse, WASD / arrows / middle
button scroll the map, ESC game options.

Building from source (Windows, MSYS2 mingw32, Python, LLVM clang) is described in
[gwrecomp/README.md](gwrecomp/README.md) and [gwrecomp/tools/rebuild/README_BUILD.md](gwrecomp/tools/rebuild/README_BUILD.md).

## Instalación (español)

1. Ten instalado **Gene Wars 1.1 (edición europea)**: la carpeta `GENEWARS` que crea el instalador original
   (`DATA`, `LEVELS`, `SOUND`, `INTRO`, `ANIMS`, `LDATA`, `S`, `SPEECH`, `SAVE` y los archivos sueltos como `GW.EXE`).
   GWRecomp los comprueba con SHA-256 y solo los lee.
2. Descomprime `GWRecomp-v1.0-win32.zip` en una carpeta donde puedas escribir (ahí se guardan partidas y registros).
3. Haz doble clic en `gwrecomp.exe`. En el lanzador pulsa **CAMBIAR** y elige tu carpeta `GENEWARS`; las cuatro
   marcas DATA / LEVELS / SOUND / INTRO se ponen en verde.
4. Inicia el juego, continúa la última partida o elige una misión.

**Primer arranque:** la primera vez que entras al juego, `gwrecomp.exe` prepara dos archivos en `work\` a partir de
*tu* `GW.EXE` (comprobado por SHA-256). Tarda un momento y solo ocurre una vez. Salen de tu copia del juego: no los
compartas.

**Opciones:** todo lo que cambias en el lanzador se guarda en `gwrecomp.ini` (modo de vista, resolución, pantalla
completa, 60/120 FPS, filtro, `water_effects`, `enhanced_audio`). Para la música del CD añade
`cd_cue = C:\ruta\a\tu\imagen\genewars.cue` con tu propia imagen del CD. `gwrecomp.ini.example` explica cada clave.

## Legal

*Gene Wars* is © Bullfrog Productions / Electronic Arts. GWRecomp is unaffiliated with and unendorsed by the rights
holders.

- **This repository** contains no game executable, data, video, audio, disc image or extracted game code. It contains
  the host layer, the lifter and the tools that translate *your* `GW.EXE` at build time, plus a few screenshots in
  `gwrecomp/docs/screenshots/` that show the game's graphics for illustration only.
- **A built `gwrecomp.exe`** is that translation compiled: it contains native code derived from the original Gene
  Wars program. It contains none of the game's data (graphics, sounds, videos, levels, speech), which are always read
  from your own `GENEWARS` folder. Whether a prebuilt binary may be redistributed is a question for the rights
  holders; this project does not grant any such right.
- No license has been applied to GWRecomp's own code yet (see [gwrecomp/PROVENANCE.md](gwrecomp/PROVENANCE.md));
  default copyright applies. Third-party components keep their licenses ([THIRD_PARTY_NOTICES](gwrecomp/THIRD_PARTY_NOTICES.md);
  SDL2: zlib).

---

## Upstream: Genewars engine re-implementation


This is re-implementation of the game binary for Genewars produced by Bullfrog
and released in 1996.

At the moment it is incomplete, and it's hard to tell if it will ever be.
But it's a good start if you want to work on the game, by either continuing
the re-implementation, or understanding how the game mechanics work, or
maybe write tools or patches for the game.

## What it does, if you run it?

Nothing. It's not implemented to the point where it would display anything.

If you're just a player, and not a programmer / researcher, then this is not
a project for you.

## What is there, and what is not?

All the interfaces from the game are defined. But most functions are not
implemented. So this contains little code, mostly interfaces and organization
for the code - classes, structs, enumerations, declarations of functions and
methods.

All the files can be compiled and linked using a modern version of GCC/G++.

## Building.

To generate build scripts, use autotools:

```
autoreconf -ivf
```

Then, to build the 32-bit executable on Linux:


```
mkdir -p release; cd release
CFLAGS="-m32" LDFLAGS="-m32" PKG_CONFIG_PATH="/usr/lib/i386-linux-gnu/pkgconfig" ../configure
make V=1
```

To build 32-bit executable on Windows using MinGW32 from MSYS2:

```
mkdir -p release; cd release
PATH="/mingw32/bin:$PATH" CFLAGS="-m32" LDFLAGS="-m32" ../configure
PATH="/mingw32/bin:$PATH" make V=1
```

