# The symbol map: what it is, what the build needs, what was done

Short version: **the build does not need `genewars-1_1.map`.** It only supplied function *names*, a few cross-checks and report labels. Boundaries of lifted functions never came from it. The map is now optional. A build without it produces the same lifted C, the same objects and an executable whose code and data are byte-identical to the build that used it.

## 1. The file

`genewars-1_1.map` is a text file in the layout of a Watcom linker map (`Start/Length/Name/Class` segment table, then `Publics by Value`, then `Program entry point`). It was exported by a disassembler, not written by the Watcom linker: it contains the disassembler's own labels.

| Class (by the shape of the name) | Entries | Where the information comes from |
|---|---|---|
| `aCamelCase` string labels | 917 | disassembler, from C strings at that address (916 of 917 confirmed from `GW.EXE`) |
| `jpt_XXXX` / `def_XXXX` | 112 / 93 | disassembler switch-table analysis (all 112 tables start a run of fixup-backed slots; all 93 default labels lie in code) |
| `nullsub_N`, `unknown_libname_N`, `loc_`/`sub_` | 25 | disassembler |
| Watcom/C names (trailing `_`, C library, Bullfrog library, Smacker, Miles) | 858 | external names transferred onto the 1.1 binary (see 2) |
| `W?name$...` Watcom-mangled C++ names | 252 | external names transferred onto the 1.1 binary (see 2) |
| **Total** | **2257** | 1069 in the code segment, 1184 in data, 4 elsewhere |

Measured by `tools/rebuild/symbols/measure_reference_map.py` (aggregate counts only): **1121 of 2257 entries (49.7%) can be confirmed mechanically from `GW.EXE` alone.** That figure counts addresses checked against the executable (fixup-backed tables, code ranges, printable strings); it does not mean the names could be reconstructed, because the other half (names) is not in the executable at all: `GW.EXE` contains no symbol or debug information.

## 2. Where the names come from

The retail Europe disc contains `GAME/MAIN.MAP`: a genuine **Watcom Linker 10.5** map of the 1.0 build (created 1996-08-09) with demangled C++ signatures, 3348 distinct symbols. Against it (counts only):

- 593 of the 858 C-style names occur verbatim in it;
- at least 105 of the 252 mangled C++ names correspond to a demangled signature in it (a lower bound: the comparison was a simple string match).

So the names are, in large part, the vendor's own link map shipped on the media, transferred from the 1.0 binary to the 1.1 binary by function matching (the repository has the matchers, `tools/match_relocation_aware.py` and `tools/bflib_match.py`). I did not re-run that transfer. For the remaining names (265 C-style and the rest of the mangled ones) the file itself does not say whether they come from the disc map, from library recognition or from manual naming; that cannot be determined from the repository.

Consequences: (a) the map is not a leaked or unknown-origin artifact, but it *is* derived from proprietary media, so it is not published; (b) any user with the retail disc already has the raw material.

## 3. What reads it, and what each use needs

| Consumer | Use | Needed to build? |
|---|---|---|
| `tools/lift_entry_path.py` | identifier of each lifted function (`gw_partial_<name>`, 538 renamed of 2176); a validation of expected roots (full-closure mode only); a check of the Smacker table symbols; labels in the JSON report | **No.** Identifiers are now address-based |
| `tests/test_ifctitle_creature_probe.py` (build driver) | 23 cross-check evaluations of reverse-engineering assumptions against the map (symbol identity at known addresses, absence of a symbol at others, `jpt_` anchors) | **No.** Run only when a map is supplied; otherwise skipped, counted and printed (`TRACE reference_map absent cross_checks_skipped=23`) |
| `tests/test_ifctitle_creature_probe.{c,py}` | referred to 67 lifted functions *by name* | **No** since they refer to them by address |
| about 80 tools and tests under `tools/`, `tests/` | analysis, audits | not part of the build; those tests stay BLOCKED without the map |

Function boundaries come from the explicit roots (`--partial-root 0x...`, listed in the driver) plus the lifter's own closure traversal over direct calls, LE fixups and verified indirect targets. The map never defined them.

## 4. Three ways to remove the dependency

| | A: regenerate from the user's own files | B: publish a minimal manifest | C: hybrid |
|---|---|---|---|
| Idea | rebuild a map from the user's disc (`MAIN.MAP`) and `GW.EXE` by matching | ship address/name pairs for what the build needs | ship nothing derived; keep names optional and local |
| Accuracy | boundaries: not needed. Names: depend on matching quality; the matchers exist but their precision against this map has not been measured | exact | exact where it matters, since the build uses no names |
| Reproducibility | needs the user's disc and a deterministic matcher | fully reproducible | fully reproducible |
| Maintenance | matcher and disc-map parsing to maintain | manifest to maintain | none |
| Fidelity to the executable | machine code unaffected | unaffected | **verified identical** |
| Redistribution | nothing derived is distributed | would distribute names and addresses derived from proprietary media: **not done** | nothing derived is distributed |

**Implemented: C in its simplest form.** The build was made independent of names rather than supplying them (a minimal manifest of the 67 needed names would have been unnecessary and would still have republished derived names). A (regenerating a name overlay for human use) remains a possible future tool; it is no longer on the path of anyone's build.

## 5. Validation (all on the maintainers' machine, with the private map as the reference)

1. **Behaviour preserved**: the patched lifter with `GWRECOMP_SYMBOL_STEMS=map` reproduces the previous lifter output byte for byte (same SHA-256).
2. **Independence from the map**: lifter output with the map present equals lifter output without it (same SHA-256).
3. **Equivalence to the old output**: after rewriting the 538 map-derived identifiers to their address form, the old and new files have the same multiset of lines, the same function definitions (2176) in the same order and the same bodies. The only differing lines (1355) are the *order* of forward `extern` declarations, which followed alphabetical names before. (`tools/rebuild/symbols/compare_lift_outputs.py`)
4. **Full build, three ways** (`scripts\build.ps1 -Level B`, fresh clones): previously published code with the map; new code with the map; new code without the map.
   - new code with and without the map: identical `base.c`, identical `closure.c`, 16 of 16 identical objects, identical deterministic executable (`6bbc5de6079a37e3...`);
   - previously published build (`3a93b7186ffcee19...`) vs new build: **every section identical** (`.text` 26,383,360 bytes, `.data`, `.rdata`, `.eh_frame`, `.idata`, `.reloc`, `.bss` size) and identical headers apart from the symbol-table fields. The files differ by 7010 bytes, all of it the symbol table. (`tools/rebuild/symbols/compare_executables.py`)
5. **Smoke run (Level C)** of the new executable built without the map: exit 0, same bounded stop as before.

The executable hash changed (`3a93...` to `6bbc...`) only because symbol names changed; code and data did not.

## 6. What the skipped cross-checks mean

Without a map, 23 driver cross-check evaluations are skipped. They compared assumptions encoded in the driver (for example "a switch table is recorded at this address") with the map; the same code paths also verify the exact LE fixups, byte digests and code layout, which still run. Skipping is reported in the build output and is not a pass. With a map supplied (`GENEWARS_MAP`, hash `30e06c20...`), they run exactly as before.

## 7. Optional: using a reference map

Set `GENEWARS_MAP` (or run `setup.ps1 -GenewarsMap`) to enable the cross-checks and the analysis tools that read it. `GWRECOMP_SYMBOL_STEMS=map` additionally restores the old identifiers, only useful for comparing with output produced before this change; the build-path harness no longer matches those names.

## 8. Not done

- No tool that rebuilds a readable name overlay from the user's own `MAIN.MAP`. Feasible (the matchers exist); not needed to build.
- The ~14 literal map lines in the driver's cross-checks (names and addresses used as anchors) and the older, non-build harnesses (`test_authentic_*`, `test_ifctitle_plugin_load_at.*`, ...) still contain map-derived names. They were already public; see `PROVENANCE.md`.
