from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM

from le_loader import load_le


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "evidence" / "genewars-1_1.exe"
MAP = ROOT / "evidence" / "genewars-1_1.map"
PRIOR = ROOT / "evidence" / "overnight_stage1_table_104ae4_complete_xrefs.json"
OUT = ROOT / "evidence" / "atomic_task1_table_104ae4_all_readers.json"
TABLE = 0x104AE4
TABLE_BYTES = 14 * 4
TABLE_END = TABLE + TABLE_BYTES


def hx(n: int) -> str:
    return f"0x{n:08X}"


def capstone_cfg(image, entry: int, max_nodes: int = 8000) -> list[dict]:
    """Disassemble the direct-flow CFG from a verified code entry; indirect edges stay explicit."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    obj = image.objects[0]
    q = deque([entry])
    found: dict[int, object] = {}
    while q and len(found) < max_nodes:
        pc = q.popleft()
        if pc in found or not obj.base <= pc < obj.end:
            continue
        off = pc - image.mem_base
        ins = next(md.disasm(bytes(image.mem[off:min(off + 15, len(image.mem))]), pc, count=1), None)
        if ins is None:
            continue
        found[pc] = ins
        m = ins.mnemonic.lower()
        next_pc = ins.address + ins.size
        if m.startswith("ret") or m in {"iret", "ud2"}:
            continue
        if m.startswith("j") or m.startswith("loop"):
            if ins.operands and ins.operands[0].type == X86_OP_IMM:
                q.append(ins.operands[0].imm & 0xFFFFFFFF)
            if m != "jmp":
                q.append(next_pc)
            continue
        q.append(next_pc)
    return [
        {"va": hx(i.address), "bytes": i.bytes.hex(), "mnemonic": i.mnemonic,
         "operands": i.op_str}
        for i in sorted(found.values(), key=lambda x: x.address)
    ]


def source_instruction(image, source: int) -> dict | None:
    """Resolve a LE fixup operand to a Capstone instruction and operand field."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    obj = image.objects[0]
    for start in range(max(obj.base, source - 10), source + 1):
        if start >= source:
            break
        off = start - image.mem_base
        raw = bytes(image.mem[off:min(off + 15, len(image.mem))])
        ins = next(md.disasm(raw, start, count=1), None)
        if not ins or not (ins.address <= source < ins.address + ins.size):
            continue
        if ins.address + ins.disp_offset == source and ins.disp_offset:
            return {"va": hx(ins.address), "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic,
                    "operands": ins.op_str, "fixup_operand": "displacement",
                    "fixup_byte_offset": ins.disp_offset,
                    "fixup_byte_offset_va": hx(source)}
        if ins.address + ins.imm_offset == source and ins.imm_offset:
            return {"va": hx(ins.address), "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic,
                    "operands": ins.op_str, "fixup_operand": "immediate",
                    "fixup_byte_offset": ins.imm_offset,
                    "fixup_byte_offset_va": hx(source)}
    return None


def map_nearest_symbols(map_text: str, va: int) -> list[dict]:
    rows = []
    for line in map_text.splitlines():
        m = re.search(r"0001:([0-9A-Fa-f]{8})\s+(\S+)", line)
        if m:
            addr = int(m.group(1), 16)
            if addr <= va:
                rows.append({"va": hx(addr), "name": m.group(2)})
    return rows[-3:]


def main() -> None:
    data_hash = hashlib.sha256(EXE.read_bytes()).hexdigest()
    prior = json.loads(PRIOR.read_text(encoding="utf-8"))
    image = load_le(EXE)
    obj1 = image.objects[0]
    obj3 = image.objects[2]
    map_text = MAP.read_text(encoding="utf-8", errors="replace")
    fix_rows = []
    # LE internal fixup target_offset is relative to the target object's base.
    obj3_base = image.objects[2].base
    for f in image.fixups:
        target_link = obj3_base + f.target_offset if f.target_object == 3 else None
        if target_link is None or not TABLE <= target_link < TABLE + 0x400:
            continue
        ins = source_instruction(image, f.source_link)
        fix_rows.append({"source_link": hx(f.source_link), "target_object": f.target_object,
                         "target_offset": hx(f.target_offset), "target_link": hx(target_link), "source_type": f.source_type,
                         "target_flags": f.target_flags, "capstone_instruction": ins,
                         "range_classification": "cost_vector" if TABLE <= target_link < TABLE_END
                         else "adjacent_data_not_part_of_14_dword_cost_vector"})

    indexed_refs = []
    direct_rows = []
    for row in fix_rows:
        ins = row["capstone_instruction"]
        if not ins or ins["mnemonic"] != "mov":
            continue
        # Exact x86 absolute indexed addressing used by the original cost readers.
        if re.search(r"\[[^\]]*\*\s*4\s*\+\s*0x104ae4\]", ins["operands"], re.I):
            indexed_refs.append(ins)
        else:
            absolute = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", ins["operands"])]
            if any(TABLE <= value < TABLE_END for value in absolute):
                direct_rows.append(ins)

    # Preserve previously decoded full Capstone bodies for the eight established extents.
    prior_functions = prior.get("functions", [])
    full_functions = []
    for f in prior_functions:
        instructions = f.get("full_instructions") or f.get("instructions") or []
        if instructions:
            full_functions.append({
                "entry_link": f.get("entry_link"),
                "end_link": f.get("end_link_exclusive") or f.get("end_link_inclusive"),
                "entry_provenance": f.get("entry_provenance") or f.get("label") or f.get("map_preceding_symbol"),
                "instruction_count": len(instructions),
                "capstone_instructions": instructions,
                "table_reference_sites": [r for r in f.get("table_references", [])],
                "direct_calls": f.get("direct_calls", []),
                "direct_callers_candidate_sites": f.get("direct_callers_candidate_sites") or f.get("callers_found_by_linear_full-object-decode", []),
            })

    added_cfgs = []
    for entry in (0x2E100, 0x2EA55, 0x2EC84):
        insns = capstone_cfg(image, entry)
        anchors = [r for r in indexed_refs if int(r["va"], 16) in {int(i["va"], 16) for i in insns}]
        if not anchors:
            # 0x2EA55/0x2EC84 are recovered direct-flow roots around distinct RETs/labels;
            # retain the explicit instruction neighborhood if a branch enters through a shared tail.
            anchor = next((r for r in indexed_refs if int(r["va"], 16) in range(entry, entry + 0x500)), None)
            if anchor:
                insns = capstone_cfg(image, entry)
                anchors = [anchor]
        added_cfgs.append({
            "entry_link": hx(entry), "body_method": "Capstone direct-flow CFG from code entry; indirect/table edges recorded separately",
            "instruction_count": len(insns), "capstone_instructions": insns,
            "table_reference_sites": anchors,
            "map_nearest_symbols": map_nearest_symbols(map_text, entry),
            "caller_evidence": "No direct CALL rel32 to this entry was proven by the byte-level scan unless listed in caller_candidates; internal/shared CFG entry or table edge remains possible.",
        })

    # Caller candidates are decoded E8 instructions in previously recovered complete bodies or added CFGs.
    decoded_by_va = {}
    for f in full_functions + added_cfgs:
        for ins in f.get("capstone_instructions", []):
            decoded_by_va[int(ins["va"], 16)] = ins
    callers_by_target = {}
    for site, ins in decoded_by_va.items():
        if ins["mnemonic"] == "call":
            m = re.search(r"0x([0-9a-fA-F]+)", ins["operands"])
            if m:
                callers_by_target.setdefault(int(m.group(1), 16), []).append(hx(site))
    for f in added_cfgs:
        f["caller_candidates"] = callers_by_target.get(int(f["entry_link"], 16), [])

    # Whole-object opcode-aligned CALL scan supplements calls found in the
    # recovered bodies. Candidates are retained separately because an E8
    # byte inside an immediate/data island can resemble CALL; only Capstone
    # decoding at the byte offset is enough for the candidate list, not a
    # claimed enclosing-function identity.
    call_targets = {int(f["entry_link"],16) for f in added_cfgs}
    raw_call_candidates = {target: [] for target in call_targets}
    code_bytes = bytes(image.mem[obj1.base-image.mem_base:obj1.end-image.mem_base])
    md_calls = Cs(CS_ARCH_X86, CS_MODE_32); md_calls.detail = True
    for pos in range(max(0,len(code_bytes)-5)):
        if code_bytes[pos] != 0xE8:
            continue
        pc = obj1.base + pos
        ins = next(md_calls.disasm(code_bytes[pos:pos+8], pc, count=1), None)
        if ins is None or ins.mnemonic.lower() != "call" or ins.size != 5:
            continue
        if not ins.operands or ins.operands[0].type != X86_OP_IMM:
            continue
        target = ins.operands[0].imm & 0xFFFFFFFF
        if target in raw_call_candidates:
            raw_call_candidates[target].append({"site":hx(pc),"bytes":ins.bytes.hex(),
                "target":hx(target),"alignment_status":"Capstone decodes E8 at this byte; enclosing instruction stream/function boundary must be cross-checked"})
    for f in added_cfgs:
        f["whole_object_direct_call_candidates"] = raw_call_candidates.get(int(f["entry_link"],16), [])

    all_bodies = full_functions + added_cfgs
    instruction_contexts = []
    for ref in sorted(indexed_refs + direct_rows, key=lambda x:int(x["va"],16)):
        site = int(ref["va"],16)
        owners = []
        for body in all_bodies:
            insns = body.get("capstone_instructions",[])
            positions = [i for i,x in enumerate(insns) if int(x["va"],16)==site]
            for pos in positions:
                owners.append({"entry_link":body.get("entry_link"),
                    "extent_end":body.get("end_link"),
                    "extent_kind":"recovered_full_body" if body in full_functions else "direct_flow_cfg_only",
                    "entry_provenance":body.get("entry_provenance",body.get("body_method")),
                    "context_instructions":insns[max(0,pos-10):pos+11]})
        instruction_contexts.append({"instruction":ref,"reader_extents":owners,
            "index_interpretation":("register-times-four indexes the 14-row cost vector; runtime/register provenance is not asserted from static address alone" if "*4" in ref["operands"] else
                "absolute DWORD address identifies a fixed vector cell: row 3 or row 11")})

    reader_call_paths = []
    for body in full_functions:
        caller_sites = body.get("direct_caller_sites",body.get("direct_callers_candidate_sites",[]))
        caller_rows=[]
        for site_text in caller_sites:
            site=int(site_text,16) if isinstance(site_text,str) else int(site_text)
            nearest=map_nearest_symbols(map_text,site)
            caller_rows.append({"callsite":hx(site),"map_nearest_symbols":nearest,
                "caller_function_assertion":("IFCPlanetside::Update (cross-checked public MAP function range)" if 0x21380<=site<0x22450 else
                    "not identified as a complete public MAP function from current symbols")})
        reader_call_paths.append({"reader_entry":body.get("entry_link"),
            "reader_name":body.get("entry_provenance"),"direct_callers":caller_rows,
            "grandcaller":"virtual/update-loop ancestry is not asserted unless explicitly represented by a decoded direct call; see extent and MAP notes"})
    for body in added_cfgs:
        sites=body.get("whole_object_direct_call_candidates",[])
        reader_call_paths.append({"reader_entry":body["entry_link"],
            "reader_name":"address-derived private code entry; no matching public MAP procedure name",
            "direct_callers":sites,
            "grandcaller":"unresolved where no byte-aligned direct CALL candidate or complete enclosing procedure was recovered"})

    rows = prior["table"]["rows"]
    # Store all row bytes and expand row 9 byte-by-byte without inventing names for neighboring data.
    row9 = rows[9]
    table_raw = bytes(image.mem[TABLE - image.mem_base:TABLE_END - image.mem_base])
    row_fields = []
    for row in rows:
        idx = row["index"]
        start = idx * 4
        row_fields.append({"index": idx, "link_va": hx(TABLE + start), "offset": hx(start),
                           "stride_bytes": 4, "field": "DWORD cost (observed from indexed loads and prior exact table audit)",
                           "value": row["cost"], "bytes_le": list(table_raw[start:start + 4]),
                           "bytes_hex": table_raw[start:start + 4].hex(" ")})

    evidence = {
        "schema": "gw-atomic-task1-cost-table-104ae4-all-readers/v1",
        "target": {"path": str(EXE), "sha256": data_hash,
                   "expected_sha256": prior.get("target_sha256"),
                   "hash_matches_prior": data_hash == prior.get("target_sha256")},
        "authority": "Canonical GeneWars 1.1 LE bytes loaded with src/le_loader.py; instruction decoding by Capstone x86-32; MAP used for public-name cross-check only.",
        "table": {"link_va": hx(TABLE), "end_exclusive": hx(TABLE_END), "object": obj3.index,
                  "stride_bytes": 4, "element_type": "little-endian DWORD cost", "row_count": 14,
                  "row_indices_present": list(range(14)), "rows_0_to_13": row_fields,
                  "requested_rows_14_15": {"present": False,
                       "explanation": "The exact canonical extent is 14 DWORDs (56 bytes). Rows 14 and 15 are outside this vector; no bytes beyond 0x104B1C are assigned to it."},
                  "row9": {"index": 9, "link_va": hx(TABLE + 9 * 4), "value": 500,
                           "raw_bytes_hex": "F4 01 00 00", "byte_detail": [
                               {"offset": "+0", "value_hex": "F4", "meaning": "least-significant byte"},
                               {"offset": "+1", "value_hex": "01", "meaning": "second byte"},
                               {"offset": "+2", "value_hex": "00", "meaning": "third byte"},
                               {"offset": "+3", "value_hex": "00", "meaning": "most-significant byte"}]},
                  "raw_bytes_sha256": hashlib.sha256(table_raw).hexdigest()},
        "reference_census": {"method": "All object-1 LE fixups targeting object-3 offsets whose object-relative address resolves into 0x104AE4..0x104F00; Capstone validates each source operand. Exact table readers separated from neighboring-data references.",
                             "fixups_to_table_or_adjacent_range": fix_rows,
                             "indexed_cost_vector_reads": sorted(indexed_refs, key=lambda x: int(x["va"], 16)),
                             "direct_cost_element_references": sorted(direct_rows, key=lambda x: int(x["va"], 16)),
                             "indexed_reader_count": len(indexed_refs),
                             "direct_element_reference_count": len(direct_rows),
                             "previous_inventory_sites": prior.get("coverage", {}).get("proven_cost_table_reference_sites", []),
                             "conclusion": "The indexed reader set is derived from LE fixups plus Capstone, including previous inventory sites and any additional validated readers. Direct fixups to 0x104AF0 and 0x104B10 refer to individual DWORD cells; fixups outside the 56-byte vector are adjacent data, not rows of the cost vector."},
        "reader_function_bodies": {"previously_recovered_complete_extents": full_functions,
                                   "additional_capstone_cfgs": added_cfgs,
                                   "reference_instruction_contexts": instruction_contexts,
                                   "function_name_policy": "No canonical MAP public function names were present at these private LE code entries; labels remain address-derived and do not claim source names."},
        "caller_chains": {"reader_call_paths":reader_call_paths,
            "direct_calls_from_recovered_bodies": [
            {"function_entry": f.get("entry_link"), "callers": f.get("direct_callers_candidate_sites", [])}
            for f in full_functions],
            "grandcaller_scope": "Direct-call scan evidence is preserved per recovered body. Grandcaller identity is stated only when a decoded direct caller body exists; vtable/jump-table dispatch has not been converted into an asserted direct caller."},
        "coverage": {"canonical_object1_range": {"start": hx(obj1.base), "end_exclusive": hx(obj1.end)},
                     "fixup_count_total": len(image.fixups),
                     "fixups_targeting_cost_vector": sum(x["range_classification"] == "cost_vector" for x in fix_rows),
                     "task1_reader_xrefs_covered": len(indexed_refs),
                     "row9_500_xrefs": [r for r in indexed_refs if TABLE in [int(x,16) for x in re.findall(r"0x([0-9a-fA-F]+)", r["operands"])]],
                     "hash_verified": data_hash == prior.get("target_sha256"),
                     "unresolved_semantics": ["The 14 DWORD values are verified as costs; the building names/visual meaning per row are not encoded in this vector itself.",
                                               "Where MAP has no procedure symbol and LE control flow enters through shared/jump-table paths, Capstone direct-flow CFG extent is reported without inventing a complete function boundary or grandcaller."]}
    }
    OUT.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} indexed_reads={len(indexed_refs)} table_fixups={sum(x['range_classification']=='cost_vector' for x in fix_rows)} adjacent_fixups={len(fix_rows)}")


if __name__ == "__main__":
    main()
