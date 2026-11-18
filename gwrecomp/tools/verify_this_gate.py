#!/usr/bin/env python3
"""L-THISGATE-PROBE — Reproducible gate-verification probe for the setup_game `this` global.

The MENU gate is the W1-028/W3-048 `this`=NULL fault: the original -k path
reaches setup_game (gw_entry_W_setup_game_n_v), reads `this` (link 0x114CA8 /
runtime 0x214CA8) at 0x194B51, and faults on the memcpy write at 0x194B5A
because `this` is 0. WORK3 W3-048 proved the global is 0x00000000 BEFORE the
guest executes a single instruction (the initializer never ran / is not in the
linked native closure), and W3-050 confirmed there is no writer in any of the
three lifted closures.

This tool is a read-only LOG-PARSING probe: it loads the existing WORK1/WORK3
artifacts (no replay, no core runtime) and emits a structured GATE VERDICT:

    - initial_bytes_before_guest  (0x00000000 == bug signature)
    - first_access (VA + kind + value)
    - fault (EIP, address, edi)
    - closure writer counts (entry_path / entry_closure / broad_282)
    - GATE: "this"=NULL  -> BLOCKED on initializer (gate NOT cleared)
            "this"!=NULL -> gate cleared, MENU reachable

Re-running it after WORK1 links the initializer (so the initial bytes are no
longer 0x00000000) flips the verdict to CLEARED. This is the reproducible
acceptance test for W1-028/W2-076.

Produces:
    evidence/local_this_gate_probe.json
    reports/LOCAL_THIS_GATE_PROBE.md
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Source artifacts (read-only). All already committed by WORK1/WORK3/LOCAL.
SOURCES = {
    # W3-048: live this-pointer provenance (initial bytes, first access, fault)
    "provenance": "evidence/setup_game_this_provenance_work3.json",
    # W3-050: closure writer audit (reconciled against lifted assembly)
    "audit": "evidence/this_global_assembly_audit_work3.json",
    # LOCAL L-THISSLOTS: independent closure xref/store inventory
    "local_xrefs": "evidence/local_this_global_xrefs.json",
    # LOCAL L-SETUPGAME-CALLEES: setup_game callee + this-usage map
    "local_callees": "evidence/local_setup_game_callees.json",
    # LOCAL L-EXITBR: process-exit / gate classification
    "local_exit": "evidence/local_process_exit_classification.json",
}


def load(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def b32(hexstr):
    """Interpret a 4-byte hex string as a little-endian u32."""
    if not hexstr:
        return None
    b = bytes.fromhex(hexstr)
    if len(b) < 4:
        b = b.ljust(4, b"\x00")
    return int.from_bytes(b[:4], "little")


def main():
    prov = load(SOURCES["provenance"])
    audit = load(SOURCES["audit"])
    xrefs = load(SOURCES["local_xrefs"])
    callees = load(SOURCES["local_callees"])
    exitc = load(SOURCES["local_exit"])

    out = {"task": "L-THISGATE-PROBE", "role": "LOCAL", "sources": {}}
    for k, rel in SOURCES.items():
        out["sources"][k] = "present" if load(rel) is not None else "MISSING"

    # --- this global facts (from W3-048) ---
    tg = (prov or {}).get("this_global", {})
    initial_hex = tg.get("initial_bytes_before_guest")
    initial_u32 = b32(initial_hex)
    first = (prov or {}).get("first_events", [{}])[0] if prov else {}
    fault = (prov or {}).get("first_unsupported") or {}
    regs = fault.get("registers", {})

    # --- closure writer counts ---
    def audit_writes(a):
        d = (a or {}).get("determination", {})
        return {
            "entry_path": d.get("entry_path_writes"),
            "entry_closure": d.get("entry_closure_writes"),
            "broad_282": d.get("broad_282_writes"),
            "closure_has_writer": d.get("closure_has_writer"),
        }
    aw = audit_writes(audit)
    # cross-check with the independent LOCAL xref inventory
    lx = {}
    if xrefs:
        for name, key in [("entry_path", "entry_path"),
                          ("entry_closure", "entry_closure"),
                          ("broad_282", "broad_282")]:
            c = xrefs.get("closures", {}).get(name, {})
            if not c.get("missing"):
                lx[name] = c.get("writes", 0)

    this_is_null = (initial_u32 == 0)
    initial_bytes = "NULL (0x00000000)" if this_is_null else "non-NULL (%s)" % hex(initial_u32)

    verdict = {
        "this_global": {
            "map_link_va": tg.get("map_link_va"),
            "runtime_address": tg.get("runtime_address"),
            "object_index": (tg.get("object") or {}).get("index"),
        },
        "initial_bytes_before_guest": initial_hex,
        "initial_value": hex(initial_u32) if initial_u32 is not None else None,
        "this_is_null_before_guest": this_is_null,
        "first_access": {
            "eip": first.get("eip"),
            "kind": first.get("kind"),
            "linear": first.get("linear"),
            "value_bytes": first.get("value") or first.get("old_bytes"),
        },
        "fault": {
            "eip": fault.get("eip"),
            "access": fault.get("access"),
            "address": fault.get("address"),
            "edi": regs.get("edi"),
            "executed_instructions": (prov or {}).get("executed_instruction_count"),
        },
        "closure_writers": {
            "w3_050_audit": aw,
            "local_thisxrefs": lx,
        },
        "setup_game_this_read_in_func": (callees or {}).get("this_read_in_func"),
        "setup_game_this_write_in_func": (callees or {}).get("this_write_in_func"),
        "process_exit_no_cd": {
            "stop_kind": "process_exit (clean exit(0) @ 0x1afc33)",
            "note": "no-CD path terminates by design before MENU; the CD-present "
                    "path is the one that faults on `this`=NULL",
        } if exitc else None,
    }

    # --- GATE VERDICT ---
    writers = aw if aw.get("closure_has_writer") is not None else {}
    any_writer = (
        writers.get("closure_has_writer") is True
        or any((v or 0) > 0 for v in lx.values())
    )
    if this_is_null and not any_writer:
        gate = "BLOCKED"
        reason = ("`this` is 0x00000000 before the guest runs and NO closure "
                  "contains a writer, so the initializer never ran in the native "
                  "closure. setup_game reads `this` at 0x194B51 and faults on the "
                  "memcpy write at 0x194B5A (address 0, edi 0). MENU is NOT "
                  "reachable until WORK1 links the initializer function (W1-028) "
                  "and WORK2 re-runs the CD-present replay (W2-076).")
    elif not this_is_null:
        gate = "CLEARED"
        reason = ("`this` is non-NULL before the guest runs (%s) — the initializer "
                  "has been linked/executed. The W1-028 fault is resolved; re-run "
                  "the CD-present replay (W2-076) to advance toward MENU." % hex(initial_u32))
    else:
        gate = "INCONCLUSIVE"
        reason = ("`this` is NULL but a closure writer exists — verify ordering "
                  "(the writer must run BEFORE setup_game) in W1-028/W2-076.")
    verdict["gate"] = gate
    verdict["gate_reason"] = reason

    out["verdict"] = verdict

    ev = os.path.join(ROOT, "evidence", "local_this_gate_probe.json")
    with open(ev, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("wrote", os.path.relpath(ev, ROOT))

    v = verdict
    lines = ["# Gate-verification probe for the setup_game `this` global (L-THISGATE-PROBE)\n"]
    lines.append("Reproducible read-only log-parsing probe over the WORK1/WORK3/LOCAL "
                 "artifacts. No replay, no core runtime. Re-run after WORK1 links the "
                 "`this` initializer: the verdict flips BLOCKED -> CLEARED.\n")
    lines.append("## `this` global")
    lines.append("- link VA: %s  | runtime: %s  | object %s"
                 % (v["this_global"]["map_link_va"], v["this_global"]["runtime_address"],
                    v["this_global"]["object_index"]))
    lines.append("- initial bytes before guest: `%s`" % v["initial_bytes_before_guest"])
    lines.append("- initial value: %s" % v["initial_value"])
    lines.append("- `this` NULL before guest: **%s**" % v["this_is_null_before_guest"])
    lines.append("")
    lines.append("## First access & fault")
    fa = v["first_access"]
    lines.append("- first access: %s @ EIP %s (linear %s) value `%s`"
                 % (fa["kind"], fa["eip"], fa["linear"], fa["value_bytes"]))
    f = v["fault"]
    lines.append("- fault: %s @ EIP %s, address=%s, edi=%s, after %s instructions"
                 % (f["access"], f["eip"], f["address"], f["edi"],
                    format(f["executed_instructions"], ",")))
    lines.append("")
    lines.append("## Closure writers")
    lines.append("- W3-050 audit: %s" % v["closure_writers"]["w3_050_audit"])
    lines.append("- LOCAL L-THISSLOTS: %s" % v["closure_writers"]["local_thisxrefs"])
    lines.append("- setup_game this read/write in func: read=%s write=%s"
                 % (v["setup_game_this_read_in_func"], v["setup_game_this_write_in_func"]))
    lines.append("")
    lines.append("## GATE VERDICT: **%s**" % v["gate"])
    lines.append("")
    lines.append(v["gate_reason"])
    rp = os.path.join(ROOT, "reports", "LOCAL_THIS_GATE_PROBE.md")
    with open(rp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote", os.path.relpath(rp, ROOT))
    print("\nGATE:", v["gate"])


if __name__ == "__main__":
    main()