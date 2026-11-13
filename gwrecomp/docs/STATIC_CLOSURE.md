# Static closure inventory (what is not lifted yet)

Produced without playing: `tools/static_closure_inventory.py` reads the user's own `genewars-1_1.exe` (SHA-256 checked), its link map and the closure report that a Level B build writes (`ifctitle_creature_probe_closure_closure.json`), finds every function entry it can prove statically, and lists the ones outside the lifted ranges in [`STATIC_CLOSURE_REMAINING.tsv`](STATIC_CLOSURE_REMAINING.tsv) (addresses, names, group, and why).

```
python tools/static_closure_inventory.py --exe <genewars-1_1.exe> --map <genewars-1_1.map> \
    --closure <build>\src\gwrecomp\evidence\ifctitle_creature_probe_closure_closure.json --src <build>\src \
    --out docs/STATIC_CLOSURE_REMAINING.tsv
```

## Batch 2 (2026-11-13, commit b339626): group B

| | functions |
|---|---:|
| function entries found | 2803 |
| inside the lifted ranges | 2420 |
| **not lifted** | **383** |
| Group A / unclassified | 0 / 0 |
| Group B | 3 (refused by the lifter, see below) |
| Group C | 379 (includes 16 engine entries moved here as host-replaced) |
| Group X, not code | 1 (`lbSqrTable`, a lookup table reached by a code pointer) |

* 47 of the 67 group B entries are lifted as roots.
* 16 are reclassified **C, host-replaced** and deliberately not lifted, because they program DOS hardware or drivers
  that the host layer replaces: Miles `_TIME_callback`, `_AIL_set_USE16_ISR`, `_AIL_API_set_USE16_ISR`, the seven
  real-mode vector thunks, `_AIL_API_disable_interrupts`, `_AIL_API_set_timer_frequency`, `_DLL_size`/`_DLL_load`, and the
  two `SMACKSOUNDUSEMSS` pieces (the host forces `GetSoundDriver_` to 0 at the Smacker call sites).
* 3 stay in group B because the lifter refuses them: `prop_text` reads 0x1B0000, and `LbSpriteDrawUsingScalingData_` and
  `LbSpriteSetScalingData_` read 0x1B034C. No fixup resolves either address, so it has to be identified before they can be lifted.
* The host hooks (Smacker video/clock, `gw_vsb16` Miles entries, RAD clock) are inserted at instruction markers that must
  occur exactly once in the generated C; the build checks this, and it passed.
* Indirect dispatch: `tools/lift_entry_path.py` now also registers in `gw_partial_dispatch` (used by `recomp_lookup`)
  every fixup-backed indirect target that has a lifted body and lies below 0xAE000 (game logic and drawing). Before
  this, 65 targets passed the indirect-call allowlist but had no lookup entry; in play mode such a call returned EAX=0
  without running anything. That included the vtable/callback entries of batch 1. Targets at or above 0xAE000
  (Smacker, Miles, runtime) are unchanged: they are either hand-registered in the harness or still fail closed.
* `LbNetworkSetupIPXAddress_` (0xABC94): its only caller (0x94198, inside `main_`) is in a block the lifter does not emit,
  so no lifted path can call it. If a later batch made it reachable, the link would fail instead of running IPX code.
* Batches 1 and 2 were built, not played: no replay or play test was run on this build.

## Batch 1 (2026-11-13, commit 73c725d): groups A and U lifted

The 44 Group A and 6 unclassified entries below are now extra roots of the lifter (`tests/test_ifctitle_creature_probe.py`,
`GWRECOMP_STATIC_BATCH1=0` leaves them out). The Level B build compiles and links cleanly. Inventory of that build:

| | functions |
|---|---:|
| function entries found | 2803 |
| inside the lifted ranges | 2369 (+75: the 50 roots and 25 Group C entries they reach) |
| **not lifted** | **434** |
| Group A | 0 |
| Group B | 67 |
| Group C | 367 |
| unclassified | 0 |

One Group C entry, `LbNetworkSetupIPXAddress_` (0xABC94, IPX network set-up), is now called directly by lifted code. It is
left unlifted on purpose: the host has no IPX network. Nothing calls the batch-1 functions at run time yet, so this batch
only checks that they translate and compile. They were not run, and their register contracts were not checked beyond what the lifter itself enforces.

`STATIC_CLOSURE_REMAINING.tsv` now lists the 434 entries of this build. The table below is the earlier state.

## Result before batch 1 (2026-11-13), closure report of the Level B build of commit c84e57b

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
