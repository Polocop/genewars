#!/usr/bin/env python3
"""Apply conceptual correction to LOCAL `this` reports (W3-048/W3-051).

`this=0` before the guest is ALSO true for the ORIGINAL bytes under Unicorn
(W3-048), so it is NOT a native-vs-original divergence and does NOT establish
a missing initializer or a native bug. L-THISSLOTS / L-THISGATE-PROBE
previously over-asserted that. This script re-frames the over-asserting
conclusion/note/verdict fields, preserving all valid facts:
  - no-CD exit AH=4Ch/AL=0 = legitimate guest exit
  - do NOT create artificial DATA/TEXT.DAT alias
  - 0 direct-absolute stores to 0x114CA8 in the closures analysed
  - setup_game: 42 direct callees, 0 ICALLs
  - entry path has 0 INT10; first known INT10 at 0xA3A91/0xA3AB7 (post-gate)
First native-vs-original divergence in setup_game `this` = W1-033.
"""
import json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

CONCL = {
"local_this_global_xrefs": {
  "path":"evidence/local_this_global_xrefs.json",
  "field":"determination.conclusion",
  "new":("FACT (batch, preserved): 0 DIRECT-ABSOLUTE stores to 0x114CA8 in the analysed closures "
         "(entry_path / entry_closure / broad_282); setup_game only READS it (5 sites in entry_path). "
         "CONCEPTUAL CORRECTION (W3-048 / W3-051): this does NOT demonstrate a native bug nor a "
         "missing initializer in the closure. W3-048 shows the ORIGINAL bytes under Unicorn also arrive "
         "with this=00000000 before the guest runs (first access = read at 0x194b51), so this=0 is not a "
         "native-vs-original divergence. W3-051's scan (400 direct-absolute refs, 0 writes) has a scope "
         "limit: it finds only direct absolute operands in the LE code range and does NOT exclude "
         "register/alias-based writes or not-reached sites. The fault at 0x194b5a is a write to this[i] "
         "(memcpy) with this=NULL and occurs identically in original and native (not a divergence). The "
         "first native-vs-original divergence in setup_game this is measured by W1-033.")
},
"local_this_gate_probe": {
  "path":"evidence/local_this_gate_probe.json",
  "field":"verdict.correction_w3_048",
  "new":("CORRECTION (W3-048 / W3-051): this=0 before the guest is also true for the ORIGINAL bytes under "
         "Unicorn (initial_bytes_before_guest=00000000, first access = read at 0x194b51). It is therefore NOT "
         "a native-vs-original divergence and does NOT establish a missing initializer or a native bug. "
         "closure_has_writer=false covers DIRECT-ABSOLUTE stores only (W3-051 scope); it does not exclude "
         "register/alias writes or not-reached sites. The 0x194b5a fault is a write to this[i] (memcpy) with "
         "this=NULL, identical in original and native. First native-vs-original divergence: W1-033."),
  "extra_note_replacement": ("verdict.process_exit_no_cd.note",
     "no-CD path terminates by design (legitimate AH=4Ch/AL=0 guest exit) before MENU; the CD-present path is "
     "the one that faults on this=NULL at 0x194b5a (write to this[i], memcpy) - but this=0 also occurs for the "
     "original bytes (W3-048), so it is not by itself a native bug/missing-initializer"),
},
"local_setup_game_callees": {
  "path":"evidence/local_setup_game_callees.json",
  "field":"determination.note",
  "new":("FACT (preserved): setup_game is a straight-line initialiser: 42 direct callees, 0 ICALL slots. The "
         "`this` read at 0x94B51 feeds a memcpy into this[i] (0x94B58); with this=NULL that write faults at "
         "0x194b5a. CONCEPTUAL CORRECTION (W3-048): this=0 also holds for the ORIGINAL bytes under Unicorn, so "
         "this is not a native-vs-original divergence; and L-THISSLOTS's 0-stores covers direct-absolute operands "
         "only (W3-051 scope), so no missing-initializer / native-bug inference follows. First native-vs-original "
         "divergence in setup_game this: W1-033.")
},
}

XREFS_MD = """# Static xref/store inventory of setup_game `this` global (L-THISSLOTS)

Complementary to WORK3 W3-048 (live initializer trace). Batch, deterministic, read-only, link-VA based.

Global: setup_game `this` at link VA 0x94CA8 (folded 0x114CA8).

## entry_path  (build/entry_path_combined.c)
- total global references: 10  (reads=5, writes=0, other=5)
- direct-absolute writing instructions: **NONE**

## entry_closure  (build/entry_path_closure.c)
- total global references: 158  (reads=5, writes=0, other=153)
- direct-absolute writing instructions: **NONE**

## broad_282  (build/recomp_282.c)
- total global references: 230  (reads=115, writes=0, other=115)
- direct-absolute writing instructions: **NONE**

## Valid facts (preserved)
- 0 direct-absolute stores to 0x114CA8 in all three analysed closures.
- setup_game only READS `this` (5 sites in entry_path); the "other" bucket is duplicate asm-comments of those same reads.
- No write to the `this` pointer is present inside setup_game (the write is a local `MEM(this[i])` memcpy).

## CONCEPTUAL CORRECTION (W3-048 / W3-051)
This inventory measures only DIRECT-ABSOLUTE operands (W3-051 scope_limit). It does **not** demonstrate a native
bug nor a missing initializer in the closure:

1. **W3-048** (original-byte Unicorn oracle, `setup_game_this_provenance_work3.json`): the ORIGINAL bytes arrive
   with `this` = `00000000` **before the guest runs** (`initial_bytes_before_guest=00000000`), and the first access
   is a **read** at EIP 0x194b51. So `this=0` is present in the original execution too - it is NOT a
   native-versus-original divergence.
2. **W3-051** (`this_global_full_code_scan_work3.json`): 400 direct-absolute refs, 0 writes - but its scope limit
   finds only direct absolute operands within the pinned LE code range and does **not** exclude register/alias-based
   writes or not-reached sites.
3. The fault at 0x194b5a is a write to `this[i]` (the memcpy) with `this=NULL`; it occurs identically in original
   and native and is therefore not, by itself, a native defect.

## Determination
- direct-absolute write in entry-path closure: **False**
- direct-absolute write in any closure: **False**
- `this=0` / "no direct-absolute writer" is **NOT** evidence of a native bug or a missing initializer. It does not
  establish a native-vs-original divergence (W3-048). The first native-vs-original divergence in setup_game `this`
  is measured by **W1-033**; do not seed a pointer without that measured writer.
"""

PROBE_MD = """# Gate-verification probe for the setup_game `this` global (L-THISGATE-PROBE)

Reproducible read-only log-parsing probe over the WORK1/WORK3/LOCAL artifacts. No replay, no core runtime.

## `this` global
- link VA: 0x00114ca8  | runtime: 0x00214ca8  | object 3
- initial bytes before guest: `00000000`
- initial value: 0x0
- `this` NULL before guest: **True**

## First access & fault
- first access: read @ EIP 0x00194b51 (linear 0x00214ca8) value `00000000`
- fault: 20 @ EIP 0x00194b5a, address=0x00000000, edi=0x00000000, after 7,771,728 instructions

## Closure writers (direct-absolute stores only)
- W3-050 audit: entry_path 0 / entry_closure 0 / broad_282 0 / closure_has_writer False
- LOCAL L-THISSLOTS: entry_path 0 / entry_closure 0 / broad_282 0
- setup_game this read/write in func: read=True write=False

## Valid facts (preserved)
- `this` = 0x00000000 before the guest (original bytes, W3-048).
- First access is a **read**; the fault is a **write** to `this[i]` (memcpy) at 0x194b5a with edi=0.
- 0 direct-absolute stores to 0x114CA8 in the analysed closures (W3-050 / L-THISSLOTS).
- no-CD path terminates by legitimate AH=4Ch/AL=0 guest exit before MENU (not the MENU gate).

## CONCEPTUAL CORRECTION (W3-048 / W3-051)
`this=0` before the guest is **also true for the ORIGINAL bytes under Unicorn** (W3-048). Therefore:
- it is **NOT** a native-versus-original divergence;
- it does **NOT** establish a missing initializer in the native closure nor a native bug.
The closure_has_writer=false figure covers **direct-absolute stores only** (W3-051 scope limit) and does not
exclude register/alias-based writes or not-reached sites. The 0x194b5a write-to-`this[i]` fault is identical in
original and native and is not, by itself, a native defect. The first native-versus-original divergence in
setup_game `this` is measured by **W1-033** (next gate in PROJECT_STATE); do not seed a pointer without it.

## GATE VERDICT
- `this` NULL before guest: **CONFIRMED** (original bytes, W3-048) - a property of the game state, not a native bug.
- Direct-absolute writer in closures: **NONE** (W3-050 / L-THISSLOTS, direct-absolute scope only).
- Native-vs-original divergence: **NOT established** by `this=0` (W3-048). Open: W1-033 (first measured divergence).
- MENU NOT reached on the CD-present path (stops at the 0x194b5a write with this=NULL); this probe re-verifies the
  same facts read-only and will be re-run once W1-033 pins a measured writer/first-divergence.
"""

def set_path(d, dotted, val):
    keys = dotted.split(".")
    cur = d
    for k in keys[:-1]:
        cur = cur.setdefault(k, {})
    cur[keys[-1]] = val

def main():
    for name, spec in CONCL.items():
        p = spec["path"]
        d = json.load(open(p, encoding="utf-8"))
        set_path(d, spec["field"], spec["new"])
        d["conceptual_correction_source"] = (
            "W3-048 (setup_game_this_provenance_work3.json) + W3-051 (this_global_full_code_scan_work3.json)")
        if "extra_note_replacement" in spec:
            fp, fnote = spec["extra_note_replacement"]
            set_path(d, fp, fnote)
        json.dump(d, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("patched", p)

    open("reports/LOCAL_THIS_GLOBAL_XREFS.md", "w", encoding="utf-8").write(XREFS_MD)
    open("reports/LOCAL_THIS_GATE_PROBE.md", "w", encoding="utf-8").write(PROBE_MD)
    print("rewrote reports/LOCAL_THIS_GLOBAL_XREFS.md")
    print("rewrote reports/LOCAL_THIS_GATE_PROBE.md")
    print("ALL CORRECTIONS APPLIED")

if __name__ == "__main__":
    main()