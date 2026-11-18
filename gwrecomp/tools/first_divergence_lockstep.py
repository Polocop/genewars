"""Backend-neutral checkpoint comparator for first-divergence v1."""
import argparse, json, re
from pathlib import Path

ORDER = ["eip", "eax", "ax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
         "eflags", "cf", "cs", "ds", "es", "ss", "fs", "gs", "descriptors",
         "event", "dirty_memory", "call_context"]
REGS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
SEGS = ("cs", "ds", "es", "ss", "fs", "gs")

def number(v):
    if v is None: return None
    if isinstance(v, int): return v
    if isinstance(v, str):
        try: return int(v, 0)
        except ValueError: return v
    return v

def normalize(cp, *, original_eip_delta=0, original_stack_delta=0, original_memory_delta=0):
    out = {"checkpoint": cp.get("checkpoint"), "function": cp.get("function"),
           "va": number(cp.get("va")), "state": {}}
    if out["va"] is not None: out["va"] += original_eip_delta
    state = out["state"]
    state["eip"] = number(cp.get("eip"))
    if state["eip"] is not None: state["eip"] += original_eip_delta
    regs = cp.get("registers") or {}
    for reg in REGS:
        val = number(regs.get(reg))
        if val is not None and reg in ("ebp", "esp"): val += original_stack_delta
        state[reg] = val
    state["ax"] = (state["eax"] & 0xFFFF) if state["eax"] is not None else number(cp.get("ax"))
    flags = cp.get("flags") or {}
    state["eflags"] = number(flags.get("eflags"))
    cf = flags.get("cf")
    if cf is None and state["eflags"] is not None: cf = bool(state["eflags"] & 1)
    state["cf"] = bool(cf) if cf is not None else None
    segs = cp.get("segments") or {}
    for seg in SEGS: state[seg] = number(segs.get(seg))
    state["descriptors"] = cp.get("descriptors")
    state["event"] = cp.get("event")
    dirty = cp.get("dirty_memory")
    if dirty is not None:
        dirty = [dict(r) for r in dirty]
        for r in dirty:
            for key in ("start", "address", "end"):
                if key in r and number(r[key]) is not None:
                    r[key] = number(r[key]) + original_memory_delta
    state["dirty_memory"] = dirty
    state["call_context"] = cp.get("call_context")
    return out

def _shared_measured_fields(a, b):
    return [field for field in ORDER
            if a["state"].get(field) is not None and b["state"].get(field) is not None]

def _diagnostic_fields(a, b):
    av, bv = a["state"], b["state"]
    return {
        "register_deltas": {k:{"original":av[k],"native":bv[k]} for k in REGS
                             if av.get(k) is not None and bv.get(k) is not None and av[k] != bv[k]},
        "segment_deltas": {k:{"original":av[k],"native":bv[k]} for k in SEGS
                            if av.get(k) is not None and bv.get(k) is not None and av[k] != bv[k]},
        "flags_deltas": {k:{"original":av[k],"native":bv[k]} for k in ("eflags","cf")
                          if av.get(k) is not None and bv.get(k) is not None and av[k] != bv[k]},
    }

def first_difference(original, native, *, original_eip_delta=0, original_stack_delta=0, original_memory_delta=0):
    a = normalize(original, original_eip_delta=original_eip_delta, original_stack_delta=original_stack_delta, original_memory_delta=original_memory_delta)
    b = normalize(native)
    if a["checkpoint"] != b["checkpoint"]:
        return {"status":"FIRST_DIVERGENCE", "function":original.get("function") or native.get("function"),
                "va":a.get("va"), "field":"checkpoint_alignment", "original":a["checkpoint"], "native":b["checkpoint"],
                "memory_range":None,"call_context":{"original":a["state"].get("call_context"),"native":b["state"].get("call_context")}}
    compared_fields = _shared_measured_fields(a, b)
    for field in ORDER:
        av, bv = a["state"].get(field), b["state"].get(field)
        if av is None or bv is None: continue
        if field == "dirty_memory":
            # Ranges are compared byte-for-byte only when both backends recorded them.
            if av != bv:
                return {"status":"FIRST_DIVERGENCE","function":original.get("function") or native.get("function"),
                        "va":a.get("va"),"field":field,"original":av,"native":bv,
                        "memory_range":{"original":av,"native":bv},"call_context":{"original":a["state"].get("call_context"),"native":b["state"].get("call_context")},"compared_fields":compared_fields}
            continue
        if av != bv:
            return {"status":"FIRST_DIVERGENCE","function":original.get("function") or native.get("function"),
                    "va":a.get("va"),"field":field,"original":av,"native":bv,"memory_range":None,
                    "call_context":{"original":a["state"].get("call_context"),"native":b["state"].get("call_context")},"compared_fields":compared_fields}
    return {"status":"COMPARABLE_FIELDS_EQUAL","function":original.get("function") or native.get("function"),
            "va":a.get("va"),"field":None,"original":None,"native":None,"memory_range":None,
            "call_context":{"original":a["state"].get("call_context"),"native":b["state"].get("call_context")},
            "compared_fields":compared_fields,
            "note":"Equality applies only to fields present on both sides; unknown fields are not treated as equal."}

def _candidate_report(d, *, original=None, native=None, index=None, previous_match=None,
                      original_eip_delta=0, original_stack_delta=0, original_memory_delta=0):
    original = original or {}
    native = native or {}
    a = normalize(original, original_eip_delta=original_eip_delta,
                  original_stack_delta=original_stack_delta, original_memory_delta=original_memory_delta)
    b = normalize(native)
    delta = _diagnostic_fields(a, b)
    memory_diff = d.get("memory_range")
    contexts = d.get("call_context") or {"original":a["state"].get("call_context"),"native":b["state"].get("call_context")}
    caller = {"original":contexts.get("original"),"native":contexts.get("native")}
    return {
        **d,
        "FIRST_DIVERGENCE_CANDIDATE": {"checkpoint":d.get("checkpoint"),"checkpoint_index":index,
                                        "function":d.get("function"),"va":d.get("va"),"field":d.get("field")},
        "PREVIOUS_MATCH":previous_match,
        "FUNCTION":d.get("function"),"VA":d.get("va"),"CALLER":caller,
        "FIELD":d.get("field"),"ORIGINAL":d.get("original"),"NATIVE":d.get("native"),
        "MEMORY_DIFF":memory_diff,
        "SEGMENT_DIFF":delta["segment_deltas"],"FLAGS_DIFF":delta["flags_deltas"],
        **delta,
        "CONFIDENCE":"checkpoint mismatch only; causal origin and instruction-level first divergence are not established",
    }

def compare_runs(original, native, *, original_eip_delta=0, original_stack_delta=0, original_memory_delta=0):
    """Compare ordered block/function checkpoints and stop at the earliest mismatch."""
    oc = original.get("checkpoints", [original]); nc = native.get("checkpoints", [native])
    nmap = {c.get("checkpoint"): c for c in nc}
    previous_match = None
    comparable_checkpoints = 0
    for index, o in enumerate(oc):
        key = o.get("checkpoint")
        if key not in nmap:
            d={"status":"FIRST_DIVERGENCE", "function":o.get("function"), "va":number(o.get("va")),
               "checkpoint_index":index,"checkpoint":key,"field":"checkpoint_alignment","original":key,"native":None,
               "memory_range":None,"call_context":{"original":o.get("call_context"),"native":None}}
            return _candidate_report(d,original=o,index=index,previous_match=previous_match,
                                     original_eip_delta=original_eip_delta,original_stack_delta=original_stack_delta,
                                     original_memory_delta=original_memory_delta)
        d = first_difference(o,nmap[key],original_eip_delta=original_eip_delta,
                             original_stack_delta=original_stack_delta,original_memory_delta=original_memory_delta)
        if d["status"] == "FIRST_DIVERGENCE":
            d["checkpoint_index"] = index; d["checkpoint"] = key
            return _candidate_report(d,original=o,native=nmap[key],index=index,previous_match=previous_match,
                                     original_eip_delta=original_eip_delta,original_stack_delta=original_stack_delta,
                                     original_memory_delta=original_memory_delta)
        if d.get("compared_fields"):
            comparable_checkpoints += 1
            previous_match = {"checkpoint":key,"checkpoint_index":index,"function":o.get("function"),
                              "va":number(o.get("va")),"compared_fields":d["compared_fields"]}
    extra=[c.get("checkpoint") for c in nc if c.get("checkpoint") not in {x.get("checkpoint") for x in oc}]
    if extra:
        c=nmap[extra[0]]
        d={"status":"FIRST_DIVERGENCE","function":c.get("function"),"va":number(c.get("va")),
           "checkpoint_index":len(oc),"checkpoint":extra[0],"field":"checkpoint_alignment","original":None,"native":extra[0],
           "memory_range":None,"call_context":{"original":None,"native":c.get("call_context")}}
        return _candidate_report(d,native=c,index=len(oc),previous_match=previous_match,
                                 original_eip_delta=original_eip_delta,original_stack_delta=original_stack_delta,
                                 original_memory_delta=original_memory_delta)
    if not comparable_checkpoints:
        return {"status":"INSUFFICIENT_DATA","checkpoint_count":len(oc),"previous_match":None,
                "note":"No checkpoint had any shared measured fields; unknown-only checkpoints are not matches."}
    return {"status":"COMPARABLE_FIELDS_EQUAL","checkpoint_count":len(oc),
            "note":"Only common measured fields were compared; unknown fields are not equal by assumption."}

def rationalalloc_corpus(root):
    root=Path(root)
    original=json.loads((root/"evidence/cd_present_gate_work3.json").read_text(encoding="utf-8"))
    native=json.loads((root/"evidence/native_w1_037_es_ah49.json").read_text(encoding="utf-8"))
    contract=json.loads((root/"evidence/native_dpmi_0501_frontier_work1.json").read_text(encoding="utf-8"))
    # This pair is the exact function-level INT 31h checkpoint already captured on both backends.
    oe=next(e for e in original["runtime_service_tail"] if e.get("eip")=="0x001c3cc1" and e.get("registers",{}).get("eax")=="0x00000501" and e.get("registers",{}).get("ecx")=="0x00008000")
    o48=next(e for e in original["interrupt_tail"] if e.get("eip_int_opcode_assumption")=="0x001c3d21")
    o49=next(e for e in original["interrupt_tail"] if e.get("eip_int_opcode_assumption")=="0x001c3d46")
    ng=native["native_generated_c_progress"]["dpmi_linear_allocation"]
    nr=ng["pre_trap_state"]
    orig_regs=dict(oe["registers"]); orig_regs["eip"]="0x001c3cc1"
    nat_regs={k:ng.get("request_"+k) for k in ("eax","ebx","ecx","edx","esi","edi","ebp","esp")}; nat_regs["eip"]=ng["instruction_va"]
    # Native lazy flags expose CF only here; preserve unknown full EFLAGS.
    orig_cp={"checkpoint":"RationalAlloc_:INT31_AX0501:before","function":"RationalAlloc_","va":"0x001c3ca9","eip":"0x001c3cc1","registers":orig_regs,
             "flags":{"eflags":oe["registers"].get("eflags"),"cf":None},"segments":{"cs":None,"ds":None,"es":None,"ss":None},
             "descriptors":oe.get("dos4gw_pointer_alias"),"event":{"kind":"guest_interrupt","vector":49,"ax":"0x0501"},
             "dirty_memory":oe.get("guest_writes"),"call_context":None}
    native_cp={"checkpoint":"RationalAlloc_:INT31_AX0501:before","function":"RationalAlloc_","va":"0x000c3ca9","eip":ng["instruction_va"],"registers":nat_regs,
               "flags":{"eflags":None,"cf":bool(number(nr.get("flag_cf")))},"segments":{k:nr.get(k) for k in ("cs","ds","es","ss")},
               "descriptors":None,"event":{"kind":"guest_interrupt","vector":49,"ax":"0x0501"},"dirty_memory":None,
               "call_context":contract["closure"]["dynamic_backtrace_guest_chain"]}
    result=first_difference(orig_cp,native_cp,original_eip_delta=-0x100000,original_stack_delta=-0x100000)
    bisection=compare_runs({"checkpoints":[orig_cp]},{"checkpoints":[native_cp]},
                           original_eip_delta=-0x100000,original_stack_delta=-0x100000)
    return {"task":"W1-042","target_sha256":native["target_sha256"],"function":"RationalAlloc_","function_va":"0x000C3CA9",
            "fixture_parity":{"command_tail_original":original["fixture_mode"]["command_tail"],"command_tail_native":native["command_tail"]["text"],
                               "original_cue_sha256":original["fixture_mode"]["cue_sha256_before"],"native_cd_fixture":native["native_generated_c_progress"]["cd_fixture_preflight"],
                               "full_cpu_runtime_seed_parity":False,"interpretation":"Checkpoint mismatch is measured, but does not establish first instruction divergence or common full seed."},
            "address_normalization":{"original_eip_delta":-0x100000,"original_stack_register_delta":-0x100000,"basis":"measured original/link rebase in native W1-036 evidence"},
            "first_checkpoint_comparison":result,"first_divergence_diagnostic":bisection,
            "unknown_fields":["original full descriptor table at AX=0501","native full EFLAGS","native dirty-memory ranges","original call/return chain at matching checkpoint"],
            "additional_RationalAlloc_frontiers":{"native":{"dpmi_ax0501":"0x000C3CC1","dos_ah48":"0x000C3D21","ah48_retry":"0x000C3D35","segment_fault":"0x000C3D42","ah49":"not reached; selector 0x004C rejected"},
                                                   "original":{"dos_ah48":"0x001C3D21","ah48_state":o48.get("registers"),"ah48_alias":o48.get("dos4gw_pointer_alias"),"dos_ah49":"0x001C3D46","ah49_state":o49.get("registers"),"es_at_ah49":o49.get("es"),"descriptor_contract":"raw trace detail is available; W3-059 owns interpretation/validated mapping"},
                                                   "instruction_sites":{"CF/EAX/AX":"0x000C3CC3 after AX=0501; CF captured on both, full native EFLAGS unavailable","EBX":"preserved by current DPMI callback evidence","ES_push":"0x000C3D41 push es","ES_load":"0x000C3D42 mov es,eax; native precise fault on selector 0x004C","AH48":"0x000C3D21 and retry 0x000C3D35; captured on both backends","AH49":"0x000C3D46; original reaches it, native currently does not","ES_pop":"0x000C3D4C; native not reached after selector fault","return":"RationalAlloc return not paired in current snapshots","touched_memory":"original event has no guest-write range; native range snapshot absent"}},
            "authority":"original guest bytes at pinned target; Open Watcom source was not copied or substituted","selector_mapping_changes":[]}

def main():
    p=argparse.ArgumentParser();p.add_argument("--original");p.add_argument("--native");p.add_argument("--out");p.add_argument("--original-eip-delta",type=lambda x:int(x,0),default=0);p.add_argument("--original-stack-delta",type=lambda x:int(x,0),default=0);p.add_argument("--original-memory-delta",type=lambda x:int(x,0),default=0);p.add_argument("--rationalalloc",action="store_true");a=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    if a.rationalalloc: out=rationalalloc_corpus(root)
    else:
        if not a.original or not a.native:p.error("provide --original and --native")
        o=json.loads(Path(a.original).read_text());n=json.loads(Path(a.native).read_text());out=compare_runs(o,n,original_eip_delta=a.original_eip_delta,original_stack_delta=a.original_stack_delta,original_memory_delta=a.original_memory_delta)
    if a.out:Path(a.out).write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
    else:print(json.dumps(out,indent=2))
if __name__=="__main__":main()


