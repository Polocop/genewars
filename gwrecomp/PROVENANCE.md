# Provenance, redistribution and licensing

## Upstream

This branch is built on a fork of <https://github.com/mefistotelis/genewars>. No upstream file is changed except a pointer added to the root `README.md`. The upstream repository contains no license file at the time of writing; nothing here grants any license to upstream's work either.

## What is published

Original GWRecomp work: host/runtime layer, LE loader, lifter driver and analysis tools, test harnesses, build scripts and documentation, imported from the maintainer's private repository at its tip (commit `e51f2bb`).

## What is deliberately NOT published

| Excluded | Reason |
|---|---|
| `evidence/`, `run-evidence/`, `reports/` | JSON evidence embeds guest memory bytes and instruction-level extracts of the original executable |
| `snapshots/`, guest images, `build/`, `cache/`, generated lifted C (`*.base.c`, `closure.c`) | Derived directly from the proprietary executable / large artifacts |
| Original executable, data, Smacker videos, audio, disc images, the original `.map`/IDA data | Copyright of Bullfrog/EA |
| `third_party/` clones (DOSBox variants, pcrecomp, others) | Not ours; fetch from their upstreams |
| Internal agent task queue, coordination files, CI workflows | Machine-specific, noisy; the workflows target the maintainer's runner |
| Private Git history | Every commit carries the excluded evidence; publishing this branch as a clean snapshot avoids republishing it. The history remains in the maintainer's repository |
| Two test sources with raw byte arrays of original code (`test_recomp_batch.c`, `test_recomp_cfg_leaf_work3.c`) | Embedded extracted machine code |

## Review of open items

Nothing below has been cleared legally. This section records what was found, what was changed and what remains. Method: every published text file was scanned for hex byte runs (C arrays, spaced hex, contiguous hex, `bytes.fromhex`) of 8 or more bytes, and each run was searched verbatim in the maintainer's own copies of `GW.EXE`, the other game executables and all Miles `*.DIG` drivers. "From the game" below means "found verbatim in those files"; it does not by itself say who owns the bytes.

### 1. Original-code byte vectors

Findings in the first public import (commit `26420e6`):

| Where | What | Origin (verified) |
|---|---|---|
| `tests/test_ifctitle_creature_probe.c`, `tests/test_ifctitle_plugin_load_at.c` | six arrays each (87, 96, 40, 24, 17, 21 bytes = 285 bytes of array data; reported earlier as 279) | **Found verbatim in the Miles `SB16.DIG` driver** (all six), several also in the other `*.DIG` drivers. Third-party driver code, not author-written stubs |
| `tests/test_ifctitle_creature_probe.py`, `tests/test_ifctitle_plugin_load_at.py` | ~20 `bytes.fromhex` literals of 8 to 32 bytes, plus the `target_bytes` and `ghidra_bytes_64` evidence strings | Found in `GW.EXE` (code) or code with relocations applied (not verbatim, but extracted from it) |
| `tests/test_native_ifctitle_ctor.py`, `tools/w3_178/179/181_*_runner.py`, `tools/w3_125_*`, `tests/test_fault_context_work2.py`, `tests/test_setup_game_this_null_work1.py`, `tests/test_cd_present_gate_work3.py`, `tests/test_startup_gate_classification_work3.py`, `tests/test_mscdex_return_context_work3.py` | 12 to 64 byte code snippets used as expected values | `GW.EXE` code |
| `tests/test_native_dpmi_success_path_work2.py`, `tests/test_setup_game_this_provenance_work3.py` | 26 to 44 byte console messages of the game | Game text |
| `tests/test_w3_197_ecdfollow_static.py` | 26 bytes used as a decoder input described as "synthetic" | Actually `GW.EXE` code |
| `tests/test_unicorn_services.py`, `tools/rea_le_pe_carrier.py` (+ its test), `tests/test_w3_159_wscreen_call_cfg.py`, `tools/probes/unicorn_int21.py` | short stubs | **Author-written / synthetic** (not found in game files); kept as they are |
| 40-hex-digit strings (e.g. in `tools/w3_*_capture_runner.py`) | Git commit SHA-1 hashes, not bytes | Not game material |

Changes made in the sanitised history:

- C: the six arrays in each harness file were replaced by `gw_hashed_region` records (length + SHA-256) and a `gw_region_sha256_matches()` helper (Windows CNG, already used by the harness). The checks run against the guest image built from the user's own driver, with the same offsets and lengths as before. Verified: the helper compiled stand-alone accepts the real `SB16.DIG` handler region at driver offset `0x7ed` and rejects other data; both files pass `gcc -fsyntax-only` as before. The full harness was **not** rebuilt or run.
- Python: each literal of 8 or more bytes in the two harness drivers, and of 12 or more bytes elsewhere, was replaced by `_OrigDigest(sha256, length)`, an object whose equality compares the SHA-256 of the supplied bytes (or hex string). Identical behaviour is expected when the user's files are present; confirmed for `tests/test_native_ifctitle_ctor.py` against the real executable in a throwaway copy (the comparison passes and execution proceeds to the next step, which needs a compiler setup that was not available there).
- `tests/test_w3_197_ecdfollow_static.py` now decodes an author-written instruction sequence of identical instruction sizes instead of game bytes; it passes with and without the change.
- Test results before and after the sanitisation are identical for all 466 modules (see [docs/TEST_STATUS.md](docs/TEST_STATUS.md)).

Residual, **not resolved** and not changed: the last scan still finds 58 literals of 8 to 13 bytes that occur in the game files, in 18 files: about 33 short opcode patterns (6 to 9 bytes) in `tools/lift_entry_path.py`, one-instruction capture patterns in `tools/w3_*`, MSCDEX packet bytes (protocol structures), an ASCII path (`data/text.dat`), and a few short instruction prefixes in the harness drivers. They are individual instructions or protocol data rather than extended code, which is the reason they were left, but that is a judgement, not a legal conclusion. Also unchanged: original function names and addresses (`FUN_xxxxxxxx`, names taken from the original symbol map; upstream mefistotelis/genewars uses many of the same names) and `capstone`-style mnemonic text in a few tools.

### 2. Third-party patches

- `tools/rebuild/patches/P01_pcrecomp_local_mods.patch` modifies `sp00nznet/pcrecomp` (MIT, "Copyright (c) 2026 sp00nz"). The license text now sits next to the patch (`LICENSE-pcrecomp-MIT.txt`) and in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). pcrecomp is not vendored. The patch is also hash-pinned by the build, so it is kept byte-exact.
- `tools/dosboxx_oracle/patches/first_vga_palette_event.patch` (48 lines) modifies DOSBox-X, GPL-2.0. Only the patch is included; the GPL-2.0 text now sits next to it (`LICENSE-DOSBox-X-GPL-2.0.txt`). It is treated as GPL-2.0 material. No DOSBox-X source or binary is included.
- Both patches were reviewed as text: they contain third-party context lines but no game data. Whether shipping them is acceptable under each license beyond the notices above has not been reviewed by counsel. `runtime/w2_031.patch` is the project's own.

### 3. Hashes of original files

`tools/rebuild/toolchain.lock.json` and several tests list SHA-256 digests of original game files, and now also of the byte regions above. Digests do not reproduce the content, but small regions can be brute-forced; that is accepted here only because the alternative (embedding the bytes) is worse.

### 4. License of GWRecomp itself

No license has been chosen. Do not add one until items 1 to 3 are settled.

### 5. Consequences for reproducibility

The sanitised sources differ from the frozen v0.7 tree, so the pinned executable hash in `tools/rebuild/expected_v07.json` no longer applies to a build of this repository. It must be regenerated by whoever reproduces the build.

## Sanitisation applied

The maintainer's local install path was replaced by the placeholder `<GENEWARS_HDD_ROOT>` / `<GENEWARS_INSTALL_DIR>` in published copies. These scripts therefore need that placeholder replaced with your own path. No credentials or tokens were found in the published tree.

## Trademark

Gene Wars is a trademark of its respective owners. This project is unofficial.

## History rewrite of `gwrecomp-native-port`

The first public import (`6904a79`, then `26420e6`) contained the byte vectors described above. With the maintainer's explicit authorisation the branch was replaced, using `--force-with-lease` on that branch only, by a single commit on top of upstream `72ec4c4` that does not contain them. `main`, the other branches and the upstream repository were not touched.

Checked on a fresh clone of the new branch: one commit above `72ec4c4`; none of the removed byte strings, nor the maintainer's local install path, appear in any commit of the branch; no `.pyc`, executables or driver files are tracked.

**The old commits are still publicly reachable.** After the rewrite, the old tip `26420e6` (and its parent) can still be fetched by SHA from `Polocop/genewars` and also through the upstream repository (`mefistotelis/genewars`), because forks share one object store; the API, the web commit page and `raw.githubusercontent.com` all answered `200` without authentication. Pull Request #9 now shows only the new commit. Removing the old objects is not possible from our side: it needs a request to GitHub Support (sensitive data removal: purge of dangling commits and cached views across the fork network, including the PR refs), or deleting and recreating the fork (which loses Issues and the PR and does not by itself guarantee removal from the shared network). Treat the bytes as having been public until GitHub confirms removal. A local backup of the previous state is kept by the maintainer outside this repository.
