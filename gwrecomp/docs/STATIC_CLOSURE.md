# Static closure inventory (what is not lifted yet)

Produced without playing: `tools/static_closure_inventory.py` reads the user's own `genewars-1_1.exe` (SHA-256 checked), its link map and the closure report that a Level B build writes (`ifctitle_creature_probe_closure_closure.json`), finds every function entry it can prove statically, and lists the ones outside the lifted ranges in [`STATIC_CLOSURE_REMAINING.tsv`](STATIC_CLOSURE_REMAINING.tsv) (addresses, names, group, and why).

```
python tools/static_closure_inventory.py --exe <genewars-1_1.exe> --map <genewars-1_1.map> \
    --closure <build>\src\gwrecomp\evidence\ifctitle_creature_probe_closure_closure.json --src <build>\src \
    --out docs/STATIC_CLOSURE_REMAINING.tsv
```

## Result (2026-11-13), closure report of the Level B build of commit c84e57b (later commits change no lifted code)

| | functions |
|---|---:|
| function entries found (map symbols, entry point, data-table pointers, direct-call targets by recursive descent) | 2803 |
| inside the lifted ranges | 2294 |
| **not lifted** | **509** (about 99 KB of the 912 KB code object) |
| of these: Group A, game logic (`bio/`) | 44 |
| of these: Group B, engine support (bflibrary, bfmydraw, smacklib, bfsoundlib) | 67 |
| of these: Group C, DOS / DPMI / IPX / hardware handlers / Watcom runtime and start-up, replaced by the host layer | 392 |
| of these: unclassified (named, no evidence either way) | 6 |

Reading the numbers:

* The closure report of the build has no `missing_or_unsupported` and no unresolved direct call, and none of the 509 entries is called by lifted code (`called_from_lifted_not_lifted = 0`). The remainder is code that no lifted function reaches directly.
* 80 of the 509 are pointed to by data tables (vtables, callback arrays). These are the ones that can become reachable from play; they are the first candidates to lift.
* Group A is small and concentrated: `Drone`/`Building`/`Creature`/`Effect` `InitArray` helpers, `PlSpec::DoShepherd`, `TopoGrid::InterpolateAlts`/`Fractalize`/`Create`, `TopoMorpher`, `IFCCustom::PlugIn`, `MapDisplay::SelectAmbientSound`, `find_mapxy` pieces, `setup_stuff`, `reset_game`, `InfoRequester::Create`, `SoundManager::KillAllSounds`.
* Most of Group C is the Watcom C runtime in the last 0x30000 bytes of the code object (exception handling, floating point, string and time routines) plus IPX/network and DOS hardware handlers. They are excluded because the host layer replaces them or they are only reachable from such code, not because they were proven dead.

## Limits (read before relying on the groups)

* The group of an entry is a classification aid. Names come from the link map (the exact symbol, otherwise the nearest preceding symbol, flagged `name_basis`); the group of a name comes from the public source tree. Group C also uses an address rule (everything from `__save_8087_` onwards is library code). The `group_basis` column shows which rule decided each row.
* Function entries are found by recursive descent plus pointer tables; indirect calls whose target the closure report does not list, and code reached only through jump tables of unlifted code, can hide further entries. The count is a lower bound for "entries not lifted" and not a proof of 100 % coverage once lifted.
* Nothing here says an entry is needed for play. The closure report only covers what is reachable from the roots of the current build.
