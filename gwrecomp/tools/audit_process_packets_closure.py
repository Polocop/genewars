#!/usr/bin/env python3
"""Verify the GeneWars 1.1 process_packets switch and bounded closure evidence."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/"evidence"/"genewars-1_1.exe"
EXPECTED="2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
TARGET_MAP=ROOT/"evidence"/"genewars-1_1.map"
CLOSURE=ROOT/"evidence"/"ifctitle_creature_probe_closure_closure.json"
OUT=ROOT/"evidence"/"native_process_packets_static_closure.json"

def main() -> None:
    sys.path[:0]=[str(ROOT/"src"),str(ROOT/"third_party"/"pcrecomp")]
    from le_loader import load_le
    from tools.disasm.disasm32 import Disassembler
    from tools.pe.pe_analyze import Section
    digest=hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if digest!=EXPECTED:
        raise SystemExit(f"canonical GeneWars 1.1 executable hash mismatch: {digest}")
    closure=json.loads(CLOSURE.read_text(encoding="utf-8"))
    if closure.get("target_sha256")!=EXPECTED:
        raise SystemExit("closure evidence belongs to another target")
    image=load_le(TARGET,object_rebases={1:0x1EB000,3:0x1DA000})
    code_obj=image.objects[0]
    dis=Disassembler(bytes(image.object_data(1)),0,
        [Section(".text",code_obj.base,code_obj.virtual_size,0,code_obj.virtual_size,0x20000020)])
    switch=next((row for row in closure.get("indexed_code_jump_tables",[])
        if row.get("instruction")=="0x0009358B"),None)
    if not switch or switch.get("table_link")!="0x00092F7C" or switch.get("count")!=35:
        raise SystemExit("the active process_packets switch is not the admitted 35-entry table")
    entries=[]
    for row in switch["fixup_slots"]:
        source=int(row["source_link"],16)
        fix=next((f for f in image.fixups if f.source_link==source),None)
        target=int(row["target_link"],16)
        if (fix is None or fix.source_type!=0x07 or fix.target_object!=1 or
                code_obj.base+fix.target_offset!=target or row.get("target_object")!=1):
            raise SystemExit(f"switch entry {row.get('index')} is not corroborated by its canonical LE fixup")
        if not (code_obj.base<=target<code_obj.end):
            raise SystemExit(f"switch entry {row.get('index')} leaves object 1")
        decoded=list(dis.disassemble_at(target,max_bytes=0x40))
        entries.append({"index":row["index"],"packet_code":row["index"],
            "table_slot_link":f"0x{source:08X}","target_link":f"0x{target:08X}",
            "target_symbol_map":None,"fixup":{"source_type":"SRC_OFFSET32",
                "target_object":fix.target_object,"target_offset":f"0x{fix.target_offset:08X}",
                "target_flags":f"0x{fix.target_flags:02X}"},
            "entry_instructions":[{"link":f"0x{x.address:08X}","bytes":bytes(x.bytes).hex(),
                "mnemonic":x.mnemonic,"operands":x.op_str} for x in decoded[:8]]})
    symbols={}
    for line in TARGET_MAP.read_text(encoding="latin-1",errors="replace").splitlines():
        m=re.match(r"\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+(.+?)\s*$",line)
        if m:
            va=int(m.group(2),16)
            symbols.setdefault(va,m.group(3).strip())
    for row in entries:
        row["target_symbol_map"]=symbols.get(int(row["target_link"],16))
    # The closure metadata records decoded functions and their direct-call
    # edges. Use it to give a reproducible, conservative reachability count.
    functions={int(row["address"],16):row for row in closure.get("lifted",[])
        if isinstance(row.get("address"),str)}
    # Handler entries are basic blocks inside the lifted process_packets body,
    # so include that containing root when following the recorded direct calls.
    reachable=set(); work=[0x93010]+[int(row["target_link"],16) for row in entries]
    while work:
        va=work.pop()
        if va in reachable or va not in functions: continue
        reachable.add(va)
        for call in functions[va].get("calls_to",[]):
            if isinstance(call,str) and call.startswith("0x"):
                work.append(int(call,16))
    def in_handler_range(value):
        try: n=int(value,16) if isinstance(value,str) else int(value)
        except (TypeError,ValueError): return False
        return 0x75000<=n<0x78000
    virtuals=[row for row in closure.get("verified_le_vtable_calls",[])
        if in_handler_range(row.get("callsite"))]
    jump_tables=[row for row in closure.get("indexed_code_jump_tables",[])
        if in_handler_range(row.get("instruction"))]
    deferred=[row for row in closure.get("deferred_indirect_call_sites",[])
        if in_handler_range(row)]
    report={"schema":"gw-native-process-packets-static-closure/v1",
        "target_sha256":EXPECTED,"authority":"canonical LE + complete LE fixup records; closure metadata from the native 1.1 lift",
        "dispatch":{"function_link":"0x00093010","table_link":"0x00092F7C",
            "index_instruction_link":"0x0009358B","entry_count":35,
            "all_entries_src_offset32_object1_fixup_verified":len(entries)==35,
            "entries":entries},
        "handler_subtree_summary":{"lifted_function_records":len(functions),
            "reachable_lifted_functions_from_dispatch_targets":len(reachable),
            "call_edges_followed":"only direct calls listed in lifted closure metadata",
            "indirects_in_0x75000_0x78000":{"verified_LE_vtable_call_records":len(virtuals),
                "indexed_jump_tables":len(jump_tables),"deferred_sites":deferred,
                "vtable_calls":virtuals,"jump_tables":jump_tables},
            "runtime_guard_policy":"fail closed for any dynamic target not covered by an exact runtime guard"},
        "known_limit":"This is a static admission/census of the recorded lift closure. It does not claim every package handler's full dynamic subtree has executed or that every deferred target is resolved.",
        "sources":{"closure_json":str(CLOSURE.relative_to(ROOT)),"canonical_map":str(TARGET_MAP.relative_to(ROOT))}}
    OUT.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(f"PASS process_packets switch: 35/35 fixups verified; reachable lifted roots={len(reachable)}; saved {OUT}")

if __name__=="__main__": main()
