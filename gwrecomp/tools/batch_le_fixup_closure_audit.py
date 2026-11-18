#!/usr/bin/env python3
"""Inventory LE-fixup-backed pointer tables and indirect sites in the current game closure.

This is an evidence tool, not a blanket allowlist generator.  Candidate tables
are reported only when every dword has an internal Object-1 SRC_OFFSET32 LE
fixup and resolves to decoded executable bytes.  Table semantics (vtable vs
switch vs callback array) remain a classification hint until a callsite
connects the table to code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "third_party" / "pcrecomp")]
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section

TARGET = ROOT / "evidence" / "genewars-1_1.exe"
EXPECTED_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
DEFAULT_CLOSURE = ROOT / "evidence" / "ifctitle_creature_probe_closure_closure.json"
DEFAULT_BASELINE = ROOT / "evidence" / "ifctitle_plugin_load_at_closure_closure.json"


def h(value: int) -> str:
    return f"0x{value:08X}"


def disassembler_for(image, object_index: int):
    obj = image.objects[object_index - 1]
    data = bytes(image.object_data(object_index))
    section = Section(f"LE object {object_index}", obj.base, obj.virtual_size,
                      0, obj.virtual_size, 0x20000020 if obj.executable else 0x40000040)
    return Disassembler(data, 0, [section]), data


def contiguous_fixup_runs(image, object_index: int, min_slots: int = 2):
    rows = defaultdict(list)
    for fix in image.fixups:
        owner = image.object_containing(fix.source_link)
        if owner and owner.index == object_index:
            rows[fix.source_link].append(fix)
    good = {}
    for source, fixes in rows.items():
        # Ambiguous duplicate source records are deliberately excluded.
        if len(fixes) == 1:
            fix = fixes[0]
            if (fix.source_type == 0x07 and fix.target_object == 1 and
                    (fix.target_flags & 0x03) == 0):
                target = image.objects[0].base + fix.target_offset
                owner = image.object_containing(target)
                if owner and owner.index == 1 and owner.executable:
                    good[source] = fix
    runs = []
    for source in sorted(good):
        if runs and source == runs[-1]["end"]:
            runs[-1]["fixups"].append(good[source])
            runs[-1]["end"] += 4
        else:
            runs.append({"start": source, "end": source + 4,
                         "fixups": [good[source]]})
    # Validate code destination instruction decoding and remove suspicious
    # runs that point into padding/traps. No claimed function boundary here.
    dis, _ = disassembler_for(image, 1)
    out = []
    for run in runs:
        if len(run["fixups"]) < min_slots or run["start"] & 3:
            continue
        slots = []
        valid = True
        for index, fix in enumerate(run["fixups"]):
            target = image.objects[0].base + fix.target_offset
            insn = next(dis.disassemble_at(target, max_bytes=16), None)
            if insn is None or insn.address != target or insn.mnemonic.lower() in ("int3", "ud2"):
                valid = False
                break
            slots.append({"index": index, "source_link": h(fix.source_link),
                          "target_link": h(target), "target_offset": h(fix.target_offset),
                          "target_flags": f"0x{fix.target_flags:02X}",
                          "first_instruction": f"{insn.mnemonic} {insn.op_str}".strip()})
        if valid:
            out.append({"object": object_index, "start_link": h(run["start"]),
                        "end_link_exclusive": h(run["end"]),
                        "slot_count": len(slots),
                        "candidate_kind": "code-resolving-pointer-table" if object_index == 3 else "code-resolving-code-table",
                        "semantic_classification": "candidate vtable/callback table; requires callsite/context confirmation" if object_index == 3 else "candidate switch/callback table; requires instruction/context confirmation",
                        "slots": slots})
    return out


def closure_functions(path: Path, expected_sha: str):
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("target_sha256") != expected_sha:
        raise ValueError(f"closure report hash mismatch: {data.get('target_sha256')}")
    return data, data.get("lifted", [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure", type=Path, default=DEFAULT_CLOSURE)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "evidence" / "batch_le_fixup_closure_inventory.json")
    parser.add_argument("--baseline-closure", type=Path, default=DEFAULT_BASELINE)
    args = parser.parse_args()
    raw = TARGET.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != EXPECTED_SHA:
        raise SystemExit(f"canonical LE SHA mismatch: {sha}")
    image = load_le(TARGET)
    object1_dis, _ = disassembler_for(image, 1)
    closure, lifted = closure_functions(args.closure, sha)
    baseline = {}
    if args.baseline_closure.is_file():
        baseline, _ = closure_functions(args.baseline_closure, sha)
    data_tables = contiguous_fixup_runs(image, 3)
    code_tables = contiguous_fixup_runs(image, 1)
    table_index = defaultdict(list)
    for table in data_tables:
        base = int(table["start_link"], 16)
        for slot in table["slots"]:
            table_index[int(slot["index"])].append((base, table, slot))

    indirect_sites = []
    seen_funcs = set()
    for row in lifted:
        entry_text = row.get("address")
        if not entry_text:
            continue
        entry = int(entry_text, 16)
        if entry in seen_funcs:
            continue
        seen_funcs.add(entry)
        fn = object1_dis.disassemble_function(entry)
        if fn is None:
            continue
        for block in fn.blocks.values():
            for insn in block.instructions:
                if insn.mnemonic.lower() not in ("call", "jmp") or not insn.operands:
                    continue
                op = insn.operands[0]
                if op.type not in (2, 3):  # Capstone X86_OP_IMM / X86_OP_MEM / REG vary; filter below by type name fallback
                    typ = getattr(op, "type", None)
                if op.type == 1:  # immediate
                    continue
                mem = op.mem if op.type == 3 else None
                reg_indirect = op.type ==  register_type()
                if mem is not None:
                    disp = mem.disp & 0xFFFFFFFF
                    slot = (mem.disp // 4) if not mem.index and mem.disp >= 0 and mem.disp % 4 == 0 else None
                    connected_tables = table_index.get(slot, []) if insn.mnemonic.lower() == "call" and slot is not None else []
                    matching_code = [t for t in code_tables if int(t["start_link"], 16) == disp]
                    indirect_sites.append({"callsite_link": h(insn.address), "function_entry_link": h(entry),
                        "mnemonic": insn.mnemonic.lower(), "operand": insn.op_str,
                        "operand_kind": "memory-indirect", "base_register": object1_dis.md.reg_name(mem.base) if mem.base else None,
                        "index_register": object1_dis.md.reg_name(mem.index) if mem.index else None,
                        "scale": mem.scale, "displacement": h(disp),
                        "candidate_vtable_tables_for_slot": [t[0] for t in connected_tables],
                        "candidate_vtable_targets": sorted({s["target_link"] for _, _, s in connected_tables}),
                        "candidate_code_switch_tables_at_operand_base": matching_code,
                        "classification": ("vtable-slot-call candidates from LE fixup tables" if connected_tables else
                            "indexed code table candidate" if matching_code else
                            "indirect memory call/jump requiring contextual contract")})
                elif reg_indirect:
                    indirect_sites.append({"callsite_link": h(insn.address), "function_entry_link": h(entry),
                        "mnemonic": insn.mnemonic.lower(), "operand": insn.op_str,
                        "operand_kind": "register-indirect", "classification": "runtime value must be validated against LE-backed executable target set"})

    indirect_sites.sort(key=lambda r: (int(r["callsite_link"], 16), r["operand"]))
    target_count = len({slot["target_link"] for table in data_tables + code_tables for slot in table["slots"]})
    def vtable_pairs(report):
        return {(row.get("callsite"), row.get("vtable_link"), row.get("selected_target_link"))
                for row in report.get("verified_le_vtable_calls", [])}
    current_pairs = vtable_pairs(closure)
    baseline_pairs = vtable_pairs(baseline)
    new_pairs = current_pairs - baseline_pairs
    new_call_sites = {site for site, _table, _target in new_pairs if site}
    jump_tables = closure.get("indexed_code_jump_tables", [])
    call_tables = closure.get("indexed_code_call_tables", [])
    matched_code_tables = {table["start_link"] for row in indirect_sites
                           for table in row.get("candidate_code_switch_tables_at_operand_base", [])}
    result = {
        "schema": "gw-batch-le-fixup-closure-inventory/v1",
        "target_sha256": sha,
        "source_closure_report": str(args.closure.relative_to(ROOT)) if args.closure.is_relative_to(ROOT) else str(args.closure),
        "scope": "all internal object-1 SRC_OFFSET32 code-pointer runs in object 1 and object 3; indirect sites decoded from hash-bound lifted function entries",
        "classification_caveat": "Fixups prove relocated code pointers, not semantic table identity. Table and function boundaries remain candidates until matched to call instructions and CFG/index guards.",
        "counts": {"closure_functions_scanned": len(seen_funcs),
                   "data_pointer_tables": len(data_tables), "code_pointer_tables": len(code_tables),
                   "unique_fixup_backed_code_targets": target_count,
                   "indirect_calls_and_jumps_in_closure": len(indirect_sites),
                   "memory_indirect_calls_with_vtable_slot_candidates": sum(bool(r.get("candidate_vtable_targets")) for r in indirect_sites),
                   "indirect_sites_resolved_by_this_audit": len(new_call_sites),
                   "batch_vtable_call_table_target_pairs_added_vs_baseline": len(new_pairs),
                   "fixup_code_table_candidates_referenced_by_indirect_sites": len(matched_code_tables),
                   "indexed_code_jump_tables_in_closure": len(jump_tables),
                   "indexed_code_call_tables_in_closure": len(call_tables),
                   "runtime_fail_closed_indirect_sites_retained": len(closure.get("runtime_fail_closed_frontiers", []))},
        "table_runs": {"object3_vtable_callback_candidates": data_tables,
                       "object1_switch_callback_candidates": code_tables},
        "indirect_sites": indirect_sites,
        "closure_counts_from_lift_report": {"lifted_functions": len(lifted),
            "runtime_fail_closed_frontier_count": len(closure.get("runtime_fail_closed_frontiers", [])),
            "existing_verified_indirect_target_count": len(closure.get("verified_indirect_targets", [])),
            "verified_le_vtable_call_site_table_target_rows": len(closure.get("verified_le_vtable_calls", [])),
            "existing_indexed_code_jump_table_count": len(jump_tables),
            "existing_indexed_code_call_table_count": len(call_tables),
            "baseline_lifted_functions": len(baseline.get("lifted", [])),
            "new_lifted_functions_vs_baseline": max(0, len(lifted) - len(baseline.get("lifted", []))),
            "new_vtable_site_table_target_pairs_vs_baseline": len(new_pairs),
            "new_vtable_sites_vs_baseline": len(new_call_sites)},
        "closure_resolution_note": "Object-3 vtable/callback candidates are admitted per original indirect CALL only when the decoded operand is [GPR+aligned slot], each table entry has a canonical LE SRC_OFFSET32 fixup to executable Object-1 code, the runtime base register equals that candidate vtable address, and the loaded target equals that slot's fixed target. Unknown sites remain fail-closed. Object-1 fixup runs are inventoried and only bounded indexed switch/call tables already admitted by the lifter are counted as executable contracts; arbitrary runs are not treated as switches."
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "counts": result["counts"],
                      "closure": result["closure_counts_from_lift_report"]}, indent=2))


def register_type():
    # Capstone x86 constants: REG=1, IMM=2, MEM=3.
    return 1


if __name__ == "__main__":
    main()


