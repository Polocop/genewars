# Inputs of the build: which are needed, which only verify, which a user cannot reproduce

`python tools/rebuild/check_inputs.py` reports every input as PASS / MISSING / MISMATCH. The expected values live in `tools/rebuild/inputs.json` (digests) and `tools/rebuild/profiles/gw11-europe.json` (the **version profile**: digests plus the role of each file). Nothing in this table is distributed by this repository.

## 1. The 15 install files

I compared each with the files of the retail Europe disc (extracted by the maintainers). Result:

| Role | Files | Meaning |
|---|---|---|
| `retail-disc` (11) | `DATA/FILEEN.DAT`, `FILESCR.ANB`, `FILESCR.GLA`, `FILESCR.PAL`, `FONT2.DAT`, `FONT2.TAB`, `IFTITLE.ANB`, `MAIN.GLA`, `TITLESCR.DAT`, `TITLESCR.PAL`, `INTRO/BIOINTRO.SMK` | byte-identical to the same path on the disc. Anyone with the same disc can verify them against it |
| `patch-1.1` (2) | `GW.EXE`, `DATA/TEXT.DAT` | not on the disc in this form. The disc's `GW.EXE` is the 1.0 build (1,265,994 bytes); `TEXT.DAT` differs from all six per-language `TEXT.DAT` files on the disc. They belong to the 1.1 update |
| `local-config` (1) | `CONFIG.INI` | written by the game installer (130 bytes; language and drive choices). Absent from the disc |
| `local-fixture` (1, optional) | `SAVE/SAVE0.SAV` | a save game created by the maintainers while testing. Absent from the disc. **Not required** since the `no-saves` profile (section 2) |

The target executable is the 1.1 `GW.EXE` (SHA-256 `2a0a51a5...`). The 1.1 files cannot be derived from the disc; where a user obtains them is outside this repository (the update is a separate download).

### Which ones does the build really need?
- **`GW.EXE` 1.1**: yes; the whole project is about this binary.
- **the other `retail-disc` files, `TEXT.DAT`, `BIOINTRO.SMK`**: the driver loads them through the virtual file system and pins their digests, so that every claim it makes is about an exact, known input. They are verification *and* runtime inputs.
- **`CONFIG.INI`**: input to the replays; its content depends on the installer's choices, so a different language or drive gives a different digest. The driver already treats its digest as optional (`if EXPECTED_CONFIG_INI and ...`); it is still listed because the harness reads it.
- **`SAVE0.SAV`**: optional; see 2.

I did not remove or relax any digest check.

## 2. Save games: the `no-saves` and `reference-save` profiles

### What `SAVE0.SAV` was used for
It is not part of the game or the retail disc; it is a save the maintainers created while testing (343,958 bytes). In the build driver it appears in three places only:
1. a **pre-flight digest check** (it was in the mandatory resource table);
2. an **assertion in the OPTIONS replay** ("the original OPTIONS plug-in read SAVE0.SAV and reported the slot count"), which belongs to the driver's regression/replay mode;
3. fields of the evidence JSON written by that replay.

It plays no part in lifting or compiling: the driver's interactive build mode (`GWRECOMP_BUILD_SDL2_INTERACTIVE=1`, what `rebuild.ps1` uses for Levels B and C) returns after building the executable and never reaches the replay. So the dependency was a pre-flight gate, not an input to the recompiled code.

### Profiles
The driver now detects the state of the installation's `SAVE` directory:

| Profile | `SAVE` directory | Use |
|---|---|---|
| `no-saves` | empty or absent (what a fresh installation has) | the supported profile for anyone; no private file |
| `reference-save` | exactly `SAVE0.SAV` with the maintainers' reference content (digest in `inputs.json`) | regression profile: keeps the original assertions and evidence |
| anything else | another save, a changed `SAVE0.SAV`, several saves | **refused** (the replays validate one of the two states above and no other) |

`check_inputs.py` applies the same rule and prints the profile. No digest of any other resource was touched; `tests/test_save_profiles.py` checks that.

### What the original game does without saves (measured, not assumed)
In the replay with the original OPTIONS plug-in, an installation without `SAVE0.SAV` gave: the original code probes `SAVE0.SAV` (2 probes), the virtual file system answers DOS file-not-found (AX=2) as the real DOS would, and no save is read. The 14 probes of slots 1 to 7 (two each) are unchanged. The `reference-save` run behaves as before (the save is read). That expectation was written only after observing it, and the replay stops later in both profiles for a reason unrelated to saves (see below).

### Comparison of the two profiles
Two builds from the same commit, one with the reference save and one without (public mode, no symbol map):
- identical lifted function set (2241), `base.c`, `closure.c`, 16 of 16 compiled objects, guest image, deterministic executable (`6bbc5de6...`) and default executable (all sections identical);
- the only file that differs is the install manifest, by exactly one line: the digest of `save/save0.sav`;
- the bounded smoke run of both executables gives the same trace except values that also vary between two runs of the same build (timer-dependent registers).
- In the replay, 14 of 16 screen/palette captures are identical; two differ in a handful of pixels (see the section on residual differences in `PROGRESS.md`).

### What still stops the replay mode outside the maintainers' machine
Independent of saves (the pre-change driver stops at the same points with the reference install): the replay needs `work/lbdataload_compressed_capture.bin` (written by an earlier maintainers' run; here a copy of `DATA/IFTITLE.ANB` was supplied and accepted) and `evidence/genewars_11_titlescreen_dac6.raw`, a palette reference captured from an oracle run that is not published. So the replay/regression mode is **not** reproducible externally; Levels B and C (the executable and its bounded smoke run) are.

## 3. The CD image

The build derives the CD-DA layout (sector ranges compiled into the harness) from the cue sheet, asserts the derived MSCDEX values (5 tracks, lead-out `(1,5,60,38,59)`, track table) and checks the cue digest. The text of a cue sheet depends on how the disc was ripped (file names, line endings); it says nothing about the audio itself, and the old check never hashed the track images.

Now the driver and `check_inputs.py` accept the original cue digest **or** a cue whose five track images match the SHA-256 and size recorded in the profile. Tested: the original cue passes; a cue with a different text and absolute paths passes; a cue with one track replaced is refused. The derived-layout assertions are unchanged. The profile's track hashes are those of the maintainers' image of the Europe disc; I could not compare them with a public database from here, so they are an identity check for "this image", not a claim about other dumps.

## 4. Other editions and languages

Variants (other discs, other language installs, other 1.x builds) are not supported. A variant needs its own profile (`tools/rebuild/profiles/<id>.json`) with verified digests and an explicit statement of what differs; the build would then select it. I did not add profiles I cannot verify (I only have the Spanish-language install of this disc), and the profile is not a way to bypass a mismatch.

## 5. Snapshots and evidence used by tests

The 358 BLOCKED test modules need maintainers' artifacts: evidence JSON from original-code runs (146 modules), guest snapshots, a DOSBox-X oracle sandbox, a task queue, `third_party` clones. None are needed to build. They embed instruction bytes from the executable and were not published. Regenerating them would need the oracle sandbox (a DOSBox-X build and a 16 GiB virtual disk) and was not attempted.

## 6. Summary for an outside developer

| Needed for | What |
|---|---|
| Level A | nothing from the game |
| Level B / C | the 1.1 install (11 files from the retail disc, 2 from the 1.1 update), the disc image, `CONFIG.INI` as written by the installer (its digest is in the profile; other language/drive choices need their own verified profile). **No save file, no symbol map, no maintainers' file** |
| Replay / regression mode (not needed to build) | maintainers' artifacts (see section 2), or the `reference-save` profile for the original assertions |
