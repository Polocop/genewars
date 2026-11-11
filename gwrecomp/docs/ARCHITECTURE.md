# Architecture overview

Pipeline: `genewars-1_1.exe` (DOS4GW LE) → **parse** (`src/le_loader.py`) → **function boundaries & symbol matching** (tools, `bflib_match.py`) → **x86-32 lifting to C** (pcrecomp-based lifter driven by `tools/lift_entry_path.py`) → **link with runtime** → native Windows executable.

## Runtime (`runtime/`)

- `recomp_context.*`, `recomp_x87.*`, `recomp_types.h`: CPU context/flags/x87 state used by lifted code.
- `gw_segments.*`: guest address space, selectors and segment bounds.
- `gw_dos_services.*`, `gw_interrupts.*`, `dos_*.py`: DOS INT 21h/INT 2Fh (MSCDEX), DPMI INT 31h, file system view, ISO9660/CD image access.
- `gw_pit8254.*`: timer; `gw_vbe_provider.*`: video mode provider.
- `gw_vsb16.*`: virtual SB16 for the game's Miles AIL3DIG mixer (see `runtime/gw_vsb16.md`).
- `gw_cdda_audio.*`: CD-DA playback.
- `gw_camera_interpolation.*`: render-side interpolation experiment.

## Harness (`tests/test_ifctitle_creature_probe.{c,py}`)

The SDL2 demo harness: Python lifts and compiles, the C harness hosts the guest image, drives the game loop, input and presentation. It resumes from a prepared guest image supplied locally.

## Tools (`tools/`)

Lifter driver, coverage analyzers, `oracle_guard.py` (bounded execution guard for reference runs), `rebuild/` (reproducible rebuild procedure), `terrain_renderer/` (renderer experiment), `probes/`.

## Guest state vs. host state

Lifted C code operates on a guest memory image; host services are exposed at trap points that mirror DOS/DPMI/Miles calls. Fidelity claims require same-run guest evidence, not host substitution.
