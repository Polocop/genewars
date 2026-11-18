from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
W3_179 = ROOT / "evidence/w3_179_unsmack_dispatch.json"
OUTPUT = ROOT / "evidence/w3_180_smackinternal010_audit.json"
ENTRY = 0x000ECCF0
NEXT_LABEL = 0x000ED030
FIRST_BRANCH = 0x000ECD02
FIRST_PROGRESS = 0x000ECD40
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
DISASM_SHA256 = "dcad6dc4e0f836dba0fa0a63664b1e350c05592dc02b2ceeaa4c6788f68d5271"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def audit() -> dict[str, Any]:
    if sha(TARGET) != TARGET_SHA256 or sha(DISASM) != DISASM_SHA256:
        raise ValueError("exact target or disassembly fingerprint mismatch")
    native = json.loads(W3_179.read_text(encoding="utf-8"))
    if native.get("task") != "W3-179" or native.get("classification") != "HANDLER_ENTRY_ONLY":
        raise ValueError("W3-179 original handler-entry evidence is missing or unexpected")
    entry = native["handler_entry"]
    if entry.get("link_va") != ENTRY or entry.get("process_psp") != native.get("psp"):
        raise ValueError("W3-179 handler entry identity mismatch")

    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM

    image = load_le(TARGET)
    start = ENTRY - image.mem_base
    end = NEXT_LABEL - image.mem_base
    raw = bytes(image.mem[start:end])
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(raw, ENTRY))
    if not insns or insns[0].address != ENTRY:
        raise ValueError("target decoder did not begin at _SmackInternal010")

    by_addr = {ins.address: ins for ins in insns}
    first = by_addr.get(ENTRY)
    branch = by_addr.get(FIRST_BRANCH)
    progress = by_addr.get(FIRST_PROGRESS)
    if first is None or first.bytes != bytes.fromhex("0115f4ca1000"):
        raise ValueError("_SmackInternal010 entry instruction bytes mismatch")
    if branch is None or branch.mnemonic != "ja" or not branch.operands or branch.operands[0].imm != FIRST_PROGRESS:
        raise ValueError("first conditional transfer to the progress checkpoint did not verify")
    if progress is None or progress.bytes != bytes.fromhex("a0c0c91000"):
        raise ValueError("first shared progress instruction bytes mismatch")

    exits = []
    returns = []
    for ins in insns:
        is_flow = ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL)
        if is_flow and ins.operands and ins.operands[0].type == CS_OP_IMM:
            target = int(ins.operands[0].imm)
            if not ENTRY <= target < NEXT_LABEL:
                exits.append({"instruction": hex(ins.address), "mnemonic": ins.mnemonic,
                              "target": hex(target), "bytes": ins.bytes.hex()})
        if ins.mnemonic.startswith("ret"):
            returns.append({"link_va": hex(ins.address), "bytes": ins.bytes.hex()})

    measured = {
        "dispatcher_sequence": native["first_dispatch"]["sequence"],
        "dispatcher_link_va": "0x000EDE94",
        "index_derivation": "captured EAX & 3, verified by exact bytes at the dispatcher entry",
        "derived_table_index": native["first_dispatch"]["w3_177_table_index"],
        "selected_table_value_runtime": hex(native["first_dispatch"]["w3_177_selected_target_raw"]),
        "handler_sequence": entry["sequence"],
        "handler_link_va": hex(entry["link_va"]),
        "handler_runtime_eip": hex(entry["eip"]),
        "handler_registers": {k: hex(entry[k]) for k in
                               ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")},
        "handler_captured_registers_are_original_observed": True,
    }
    return {
        "schema": "w3-180-smackinternal010-audit/v1",
        "task": "W3-180",
        "provenance": {"target_sha256": sha(TARGET), "disassembly_sha256": sha(DISASM),
                       "w3_179_evidence": "evidence/w3_179_unsmack_dispatch.json",
                       "w3_179_trace_sha256": native["trace"]["sha256"]},
        "label_range": {"entry_link_va": hex(ENTRY), "next_handler_label": hex(NEXT_LABEL),
                        "decoded_bytes": len(raw), "interpretation": "label-to-next-label region only; not a proven standalone function extent"},
        "entry_instruction": {"link_va": hex(first.address), "bytes": first.bytes.hex(),
                              "mnemonic": first.mnemonic, "operands": first.op_str,
                              "captured_entry_edx": hex(entry["edx"]),
                              "global_operand_link_va": "0x0010CAF4",
                              "global_pre_and_post_values": "NOT_CAPTURED"},
        "first_branch": {"link_va": hex(branch.address), "bytes": branch.bytes.hex(),
                         "mnemonic": branch.mnemonic, "target_link_va": hex(int(branch.operands[0].imm)),
                         "first_progress_checkpoint": hex(FIRST_PROGRESS)},
        "first_progress_instruction": {"link_va": hex(progress.address), "bytes": progress.bytes.hex(),
                                       "mnemonic": progress.mnemonic, "operands": progress.op_str,
                                       "meaning": "first shared continuation instruction after the initial counter/wrap handling; semantic data ownership remains unproven"},
        "direct_flow_exits_from_label_range": exits,
        "returns_inside_label_range": returns,
        "dynamic_entry": measured,
        "next_capture_recommendation": {"checkpoint_link_va": hex(FIRST_PROGRESS),
                                         "why": "direct conditional target at the first handler entry boundary and shared continuation after the fallthrough wrap path",
                                         "capture": "fresh code/data mapping, EFLAGS/registers, verified globals 0x10CAF0/0x10CAF4/0x10CAF8 only after valid DS bounds; stop at first entry",
                                         "not_proven": ["the current run's branch outcome at 0xECD02", "global values", "handler completion", "decoded destination", "visible frame"]},
        "interpretation_limits": ["_SmackInternal010 is an exact-target dispatch label; this audit does not assert it is a C function boundary.",
                                  "Static destinations and bytes are not dynamic execution observations.",
                                  "No original handler exit, return, or post-entry global value was captured in W3-179."],
    }


def main() -> int:
    result = audit()
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(OUTPUT), "entry": result["label_range"]["entry_link_va"],
                      "progress": result["first_progress_branch_target" if False else "first_branch"]["target_link_va"],
                      "exit_count": len(result["direct_flow_exits_from_label_range"]),
                      "ret_count": len(result["returns_inside_label_range"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
