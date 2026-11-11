# Inputs of the build: which are needed, which only verify, which a user cannot reproduce

`python tools/rebuild/check_inputs.py` reports every input as PASS / MISSING / MISMATCH. The expected values live in `tools/rebuild/inputs.json` (digests) and `tools/rebuild/profiles/gw11-europe.json` (the **version profile**: digests plus the role of each file). Nothing in this table is distributed by this repository.

## 1. The 15 install files

I compared each with the files of the retail Europe disc (extracted by the maintainers). Result:

| Role | Files | Meaning |
|---|---|---|
| `retail-disc` (11) | `DATA/FILEEN.DAT`, `FILESCR.ANB`, `FILESCR.GLA`, `FILESCR.PAL`, `FONT2.DAT`, `FONT2.TAB`, `IFTITLE.ANB`, `MAIN.GLA`, `TITLESCR.DAT`, `TITLESCR.PAL`, `INTRO/BIOINTRO.SMK` | byte-identical to the same path on the disc. Anyone with the same disc can verify them against it |
| `patch-1.1` (2) | `GW.EXE`, `DATA/TEXT.DAT` | not on the disc in this form. The disc's `GW.EXE` is the 1.0 build (1,265,994 bytes); `TEXT.DAT` differs from all six per-language `TEXT.DAT` files on the disc. They belong to the 1.1 update |
| `local-config` (1) | `CONFIG.INI` | written by the game installer (130 bytes; language and drive choices). Absent from the disc |
| `local-fixture` (1) | `SAVE/SAVE0.SAV` | a save game created by the maintainers while testing. Absent from the disc |

The target executable is the 1.1 `GW.EXE` (SHA-256 `2a0a51a5...`). The 1.1 files cannot be derived from the disc; where a user obtains them is outside this repository (the update is a separate download).

### Which ones does the build really need?
- **`GW.EXE` 1.1**: yes; the whole project is about this binary.
- **the other `retail-disc` files, `TEXT.DAT`, `BIOINTRO.SMK`**: the driver loads them through the virtual file system and pins their digests, so that every claim it makes is about an exact, known input. They are verification *and* runtime inputs.
- **`CONFIG.INI`**: input to the replays; its content depends on the installer's choices, so a different language or drive gives a different digest. The driver already treats its digest as optional (`if EXPECTED_CONFIG_INI and ...`); it is still listed because the harness reads it.
- **`SAVE0.SAV`**: see 2.

I did not remove or relax any digest check.

## 2. `SAVE0.SAV` is the one input another user cannot produce

It is dated after the install, not on the disc, and it is the maintainers' own save file (343,958 bytes). The driver hashes it and several of its replays assert that the original OPTIONS plug-in read it and reported the slot count. An experiment with an install copy without `SAVE0.SAV` fails at once in the driver (`FileNotFoundError` while hashing it). Making it optional requires making those replays accept "no save slots", and the resulting build would be verified differently; I did not do that without being able to validate it, and a synthetic save would be an invented input.

Not published: a save game contains game-state data in the original format; whether it can be redistributed has not been reviewed. **Status: blocker for independent Level B.** Options, in order of preference: (1) a documented, validated "no save" profile of the replays; (2) a procedure that makes a bit-identical save on another machine (none exists); (3) publishing the file after a legal review.

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
| Level B / C, today | the 1.1 install files (11 from the retail disc, 2 from the 1.1 update), the disc image, **and `SAVE0.SAV` (unobtainable: open blocker)**, and `CONFIG.INI` with the maintainers' installer choices |
| not needed any more | the symbol map |
