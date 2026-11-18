# Virtual SB16 adapter for the original Miles mixer

## Scope

`gw_vsb16.c` supplies the small external-driver contract used by GeneWars' linked Miles AIL 3.03 AIL3DIG driver. The guest retains the original Miles sample handles, WAVE loading, format conversion, mixing, volume, pan, rate, and loop handling. The host adapter handles the verified driver calls through the existing INT 66h service boundary, reads the guest DMA double buffer, converts it to signed 16-bit stereo for SDL, and closes its audio device on driver shutdown or process exit.

This is a virtual driver profile, not a general SB16, DMA-controller, PIC, or IRQ emulator. The original mixer service routine at guest VA `0x000CA560` is run by the existing simulation worker between guest ticks when the output queue needs more PCM. This preserves single-threaded guest execution, but it is not a restoration of the hardware IRQ0/AIL timer contract. IRQ0 and Smacker's Miles audio path remain unimplemented.

## Runtime boundary

- `gw_vsb16_driver_call` accepts only the handled AIL3DIG function IDs documented in `gw_vsb16.h`; unknown IDs return unhandled.
- Guest DMA ranges, offsets, frame alignment, and lengths are checked before reading. A rejected DMA range, failed allocation, SDL queue error, or repeated guest mixer failure stops the pump and is recorded; the adapter does not clear Miles' guest reentrancy guard.
- The DMA halves are copied and converted before queueing. The SDL audio callback does not enter guest code.
- The original guest mixer is invoked synchronously by the simulation worker between ticks using a private register context and stack. Guest memory effects persist; guest execution is not concurrent with the game loop.
- Replay mode remains silent; the adapter is enabled only by the interactive demo path.

## Configuration

- `GW_VSB16=0` disables the virtual digital-audio adapter. In the interactive demo it is enabled by default.
- `GW_VSB16_LOG=<path>` writes adapter diagnostics to a local file in addition to stderr.
- `GW_VSB16_CAPTURE=<path>` optionally captures the converted host PCM as signed 16-bit stereo at the negotiated guest mix rate. This is diagnostic output, not a distributable game resource.

The caller must direct logs and captures to a private writable directory. No original game resource is changed.

## Smacker and CD audio

The two original Smacker `GetSoundDriver_` callsites at `0x000AE32D` and `0x000AE4FD` pass through `gw_smk_mss_gate`, which returns zero. This keeps the already verified silent BIOS-clock video path and prevents entering the unverified AIL-timer path. The gate is limited to those two callsites. No indirect MSS callback targets are admitted by the stable V20 build. CD-DA uses its separate existing host path.

## Evidence and limits

V20.4 recorded an interactive Miles session with 1,107 mixer-service invocations, 2,267,136 queued PCM bytes, 383 non-silent DMA halves, zero observed service/queue/DMA/allocation/underrun failures, a maximum SDL queue of 10,240 bytes, and clean device shutdown. These are historical V20.4 observations, not a fresh V20.5 run. The user previously confirmed that effects were audible. The source still records diagnostic counters and sample-state observations; the background hiss has not been attributed and requires human A/B listening. Smacker audio, IRQ0, and the exact guest-state restoration check after Load remain unverified.
