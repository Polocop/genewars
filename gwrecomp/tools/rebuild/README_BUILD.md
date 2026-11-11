# Rebuilding the GWRecomp v0.7 demo executable

`tools/rebuild/rebuild.ps1` rebuilds `gw_demo_sdl2.exe` (v0.7) from a clean checkout of this repository. It does not read any
historical project tree: sources come from git; everything else is an explicit, hash-verified dependency.

```powershell
powershell -NoProfile -File tools\rebuild\rebuild.ps1 -Work E:\some\new\dir [-Commit <sha|ref>] [-Lift regenerate|reuse] [-Audit]
```
Output (`<Work>\src\bin\`): `gw_demo_sdl2.exe` (default link; PE TimeDateStamp/CheckSum vary per link) and
`gw_demo_sdl2.det.exe` (**deterministic link**, `-Wl,--no-insert-timestamp`). The deterministic executable of the validated
toolchain has SHA-256 `6d1b20b5cccd0afafb4daceff46b56e1ab4163ec361fade52617eec7cffd29e5` (see `expected_v07.json`,
checked by `verify_rebuild.py`). `<Work>\rebuild_manifest.json` records every phase, hash and tool.

## Opt-in reusable object cache

The command above remains the default and retains a fresh object directory per build. To reuse only compiler objects, assign a stable, unique cache ID to each branch/agent pair and continue to use a new `-Work` path for every build:

```powershell
# Inspect the plan without creating a cache or starting a build.
powershell -NoProfile -File tools\rebuild\rebuild.ps1 `
  -Work E:\GWRecomp\build\candidates\creature-v21 `
  -ReuseObjectCacheId gameplay-creature-agent1 -DryRun

# Explicitly opt in to the reusable object cache.
powershell -NoProfile -File tools\rebuild\rebuild.ps1 `
  -Work E:\GWRecomp\build\candidates\creature-v21 `
  -ReuseObjectCacheId gameplay-creature-agent1
```

The cache lives at `E:\GWRecomp\build\reusable-object-cache\<id>\objects`. Builds with the same ID are serialized by an exclusive OS file lock; concurrent agents must use distinct IDs. The object key includes compiler arguments, normalized checkout-relative paths, source bytes, Clang-discovered transitive dependencies, effective compiler command, compiler identity and compile-relevant environment. The per-invocation `CODEX_TOOL_CALL_ID` is excluded because it is runner metadata and does not affect Clang output. A cache hit also verifies the object's SHA-256 against its stamp. A changed input or toolchain key creates a separate content-addressed object entry; old entries are not replaced or pruned. The toolchain lock pins compiler and external dependency versions. A miss recompiles that object. Executables, build manifests, logs and test evidence remain in each unique `-Work` tree. No cache pruning or old-work cleanup is performed.

For a bounded key audit, use the explicit `-ObjectCacheDiagnostics` switch below. The usage manifest then includes normalized flags, source/dependency hashes, compiler identity and per-environment-variable value hashes. It does not record raw environment values and does not change the cache key. The switch survives `rebuild.ps1` clearing inherited `GWRECOMP_*` variables for isolation.

```powershell
powershell -NoProfile -File tools\rebuild\rebuild.ps1 `
  -Work E:\GWRecomp\build\candidates\cache-diagnostic `
  -ReuseObjectCacheId gameplay-creature-agent1 -ObjectCacheDiagnostics
```

This option does not reuse lifted C, dependency clones, temporary directories or evidence. `-Lift reuse` keeps its existing meaning and still requires the matching pristine lift/report in that build's own checkout; the object-cache option does not broaden lift reuse. It is opt-in and can be abandoned without changing historical build behavior.

When validating this uncommitted cache branch, `-UseCurrentObjectCacheSources` explicitly overlays only `tests/test_ifctitle_creature_probe.py` and `tools/rebuild/object_cache.py` onto the exact clean `-Commit` checkout. Their SHA-256 values are written to that build's `rebuild_manifest.json`. This switch is for controlled branch validation; it is off by default.

## What is in git and what is not
| Piece | Where |
|---|---|
| Build driver, runtime and harness sources of v0.7 | this repository (`tests/test_ifctitle_creature_probe.{c,py}`, `runtime/`, `tools/`, `src/`) |
| Lifter dependency `pcrecomp` | **external**: commit `35548b8d0fd8aa853da67edcf7cd6134f6b9cdc7` + `patches/P01_pcrecomp_local_mods.patch` (5 files) |
| 4 canonical evidence inputs | **external**, SHA-256 in `evidence_inputs.json` (`E:\GWRecomp\evidence\...`) |
| Original game install, CUE | **external**, read-only, SHA-256 in `toolchain.lock.json` |
| Compilers/libraries/Python | **external**, versions and hashes in `toolchain.lock.json` (verified in phase 1) |
| Generated lift (`*.base.c`, 62 MB), `closure.c`, objects, executables | **never committed**; regenerated, bit-identical |

## Line endings
Only the files that need it are pinned in `.gitattributes`: the four patched sources are CRLF in the working tree
(blob stays LF), the two CD-DA sources are LF; `tools/rebuild/patches/*.patch` are `-text`. Phase 3 of the script fails if a
checkout does not honour this. No repository-wide renormalisation.

## pcrecomp: pinned commit + versioned patch (decision for V19.2)
v0.7 was built with a local clone of `github.com/sp00nznet/pcrecomp` at `35548b8` carrying five uncommitted edits
(`runtime/recomp32/recomp_types.h`, `tools/disasm/disasm32.py`, `tools/lift/{difftest,lift32,lift32_cpu}.py`). They are preserved
as `patches/P01_pcrecomp_local_mods.patch`, pinned by SHA-256 in `P01_pcrecomp_local_mods.json` together with the pre/post image hash
of every file. `rebuild.ps1` clones the original pcrecomp repository (read-only), checks out `35548b8`, applies the patch,
verifies the result, and only then runs the lifter. The original clone and its local changes are never modified.
(The build reads three of the five patched files: `recomp_types.h`, `disasm32.py`, `lift32.py`.)

### Migrating to an own fork later
1. Fork `sp00nznet/pcrecomp`; check out `35548b8`; apply `P01` (`apply_pcrecomp_patch.py` does it and verifies hashes); commit.
2. Replace the pinned commit (`$PCRE_COMMIT` in `rebuild.ps1`, `base_commit` in the json) by the fork commit and point `-PcrecompSource` at the fork.
3. Delete `P01` and `apply_pcrecomp_patch.py`, keep a hash check of the five resulting files in `toolchain.lock.json`.
4. Rebuild and require the same `closure.c` (`23bafcc3…`), the 15 objects and the deterministic executable hash.

## Known limits
Compiler/linker/SDL/instalation paths are hard-coded in the python driver and therefore tied to this machine; they are pinned and
verified, not parameterised. `title_unjugador_after_biolose` (first click lost after a screen change) is a pending issue, unrelated to the build.

## Note for the public repository (sanitised sources)
In the public branch the harness sources no longer contain original-driver or original-code bytes (they are checked by SHA-256 against the user's own files; see `PROVENANCE.md`). The sources therefore differ from the frozen v0.7 tree, and the executable hash in `expected_v07.json` does not apply to a build of this repository until it is regenerated.
