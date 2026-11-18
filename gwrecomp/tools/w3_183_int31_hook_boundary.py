"""Static/synthetic audit of the original INT 31 hook boundary at link VA 0xBC765."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_182_ORIGINAL_AX0300_20261009_01.jsonl"
RESULT = ROOT / "evidence/w3_183_int31_hook_boundary.json"
REPORT = ROOT / "reports/coordination/w3_183_int31_hook_boundary.md"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"


def audit() -> dict:
    if not TARGET.is_file() or not CORE.is_file() or not TRACE.is_file():
        raise FileNotFoundError("required W3-182 target, source, or trace is missing")
    target_sha = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if target_sha != TARGET_SHA256:
        raise RuntimeError("exact original target hash mismatch")
    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le
    import capstone

    image = load_le(TARGET)
    start, end = 0xBC748, 0xBC769
    raw = bytes(image.mem[start - image.mem_base:end - image.mem_base])
    decoded = [{"address": ins.address, "bytes": ins.bytes.hex(),
                "mnemonic": ins.mnemonic, "operands": ins.op_str}
               for ins in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32).disasm(raw, start)]
    required = {0xBC748: ("call", "0x96c10"), 0xBC74D: ("xor", "ecx, ecx"),
                0xBC761: ("mov", "ax, 0x300"), 0xBC765: ("int", "0x31"),
                0xBC767: ("pop", "es")}
    by_address = {ins["address"]: ins for ins in decoded}
    for address, expected in required.items():
        ins = by_address.get(address)
        if not ins or (ins["mnemonic"], ins["operands"]) != expected:
            raise RuntimeError(f"unexpected exact-target instruction at {address:#x}: {ins}")

    source = CORE.read_text(encoding="utf-8")
    trace_rows = [json.loads(line) for line in TRACE.read_text(encoding="utf-8").splitlines()]
    target_events = [row for row in trace_rows
                     if row.get("checkpoint") == "W3_182_DPMI0300_ENTRY"]
    main = next((row for row in trace_rows if row.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    has_dynamic_core_fast_link = ("cache.block.running->LinkTo" in source and
                                  "goto run_block" in source and
                                  "skip restart_core's per-PC candidate checks" in source)
    special_window = "linked_candidate_link_va >= 0x00094cda" in source and \
            "linked_candidate_link_va <= 0x00094dc1" in source
    exact_candidate = "candidate_link_va == 0x000bc765" in source and \
            "w3_182_dpmi0300_entry_candidate" in source
    return {"classification": "CHECKPOINT_CAN_MISS_CACHED_BLOCK_INTERIOR",
            "certainty": "STATIC_MECHANISM_CONFIRMED; ORIGINAL EXECUTION AT BC765 UNKNOWN",
            "target_sha256": target_sha, "pinned_revision": REVISION,
            "link_va_range": {"start": hex(start), "end_exclusive": hex(end),
                              "bytes": raw.hex()},
            "instructions": decoded, "int31_entry": "0xBC765",
            "call_return_entry": "0xBC74D", "straight_line_to_int31": True,
            "hook": {"exact_candidate_present": exact_candidate,
                     "candidate_link_va": "0xBC765",
                     "candidate_predicates": ["target_context", "target_main_rebase", "not previously seen"],
                     "candidate_evaluation_point": "restart_core dispatch loop"},
            "dynarec": {"cached_link_runs_block_directly": has_dynamic_core_fast_link,
                        "per_pc_checks_skipped_on_fast_link": has_dynamic_core_fast_link,
                        "existing_forced_window": {"start": "0x94CDA", "end": "0x94DC1",
                                                    "present": special_window},
                        "BC765_forced_window_present": "BC74D..BC765" in source},
            "replay": {"main_observed": bool(main), "code_rebase":
                       hex(int(main["eip"]) - int(main["link_va"])) if main else None,
                       "event_count": len(trace_rows), "target_event_count": len(target_events),
                       "last_sequence": trace_rows[-1].get("sequence") if trace_rows else None,
                       "target_instruction_execution_proven": bool(target_events)},
            "interpretation": [
                "The static opcode and caller path are verified in the exact target.",
                "The dynrec source confirms a cached BR_Link can enter run_block without restart_core's per-PC candidate checks.",
                "The existing bounded forced window covers 0x94CDA..0x94DC1, not the BC74D..BC765 caller path.",
                "Therefore the missing W3-182 event is consistent with a cached-block interior miss; it does not prove whether INT 31 executed in that replay."],
            "next_capture": {"start_link_va": "0xBC74D", "end_link_va": "0xBC765",
                             "method": "Add a narrow W3-182 single-instruction probe window and a matching BR_Link dispatcher re-entry range, mirroring the existing bounded W3-163 mechanism.",
                             "must_revalidate": ["fresh MAIN mapping", "PSP", "target_context", "AX low word 0x0300", "opcode bytes CD 31", "frame descriptor bounds"]}}


def main() -> int:
    result = audit()
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"classification": result["classification"],
                      "cached_link_fast_path": result["dynarec"]["cached_link_runs_block_directly"],
                      "target_event_count": result["replay"]["target_event_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
