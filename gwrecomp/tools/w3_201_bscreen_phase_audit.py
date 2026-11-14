#!/usr/bin/env python3
"""Reconcile W3-199 B_SCREEN lifetime and derive a bounded pre-free sample."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
RUN_EVIDENCE = ROOT / "evidence/w3_199_ecd40_continuation.json"
RUN_TRACE = ROOT / "build/dosboxx_oracle/C/W3_199_ECD40_CONTINUATION_20261009_01.jsonl"
OLD_EVIDENCE = ROOT / "evidence/w3_188_b_screen_payload.json"
OUTPUT = ROOT / "evidence/w3_201_bscreen_phase_audit.json"
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
ALLOC_SIZE = 0x4B000
SAMPLE_BYTES = 64


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bounded_sample_range(base: int, allocation_size: int, sample_size: int = SAMPLE_BYTES) -> tuple[int, int]:
    if base <= 0 or allocation_size != ALLOC_SIZE or sample_size <= 0 or sample_size > allocation_size:
        raise ValueError("unverified allocation or invalid sample size")
    end = base + sample_size
    allocation_end = base + allocation_size
    if end > allocation_end or allocation_end > 0x1_0000_0000:
        raise ValueError("sample range exceeds allocation bounds")
    return base, end


def decode_window(image, start: int, end: int) -> list[dict]:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    lo, hi = start - image.mem_base, end - image.mem_base
    if lo < 0 or hi > len(image.mem) or end <= start:
        raise ValueError("static decode window outside loaded LE image")
    raw = bytes(image.mem[lo:hi])
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoded = [{"link_va": ins.address, "bytes": ins.bytes.hex(),
                "mnemonic": ins.mnemonic, "operands": ins.op_str, "size": ins.size}
               for ins in decoder.disasm(raw, start)]
    if not decoded or decoded[0]["link_va"] != start:
        raise ValueError(f"decode did not start at {start:#x}")
    return decoded


def audit() -> dict:
    actual_hash = sha(TARGET)
    if actual_hash != TARGET_SHA256:
        raise ValueError(f"original target hash mismatch: {actual_hash}")
    run = json.loads(RUN_EVIDENCE.read_text(encoding="utf-8"))
    prior = json.loads(OLD_EVIDENCE.read_text(encoding="utf-8"))
    if run.get("task") != "W3-199" or prior.get("task") != "W3-188":
        raise ValueError("source evidence task identity mismatch")
    if run["source"]["target_sha256"] != actual_hash or prior["source"]["target_sha256"] != actual_hash:
        raise ValueError("target provenance differs across evidence")
    if sha(RUN_TRACE) != run["trace"]["sha256"]:
        raise ValueError("W3-199 trace hash mismatch")
    rows = [json.loads(line) for line in RUN_TRACE.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_sequence = {int(row["sequence"]): row for row in rows if "sequence" in row}
    allocation, store, free = (by_sequence[s] for s in (381, 382, 383))
    if [allocation.get("checkpoint"), store.get("checkpoint"), free.get("checkpoint")] != [
            "W3_188_B_SCREEN_ALLOC_RETURN", "W3_129_B_SCREEN_POST_STORE", "W3_129_MEMORY_FREE_ENTRY"]:
        raise ValueError("W3-199 B_SCREEN event sequence identity mismatch")
    pointer = int(allocation["eax"])
    if int(allocation["w3_188_alloc_size"]) != ALLOC_SIZE:
        raise ValueError("measured allocation size mismatch")
    if int(store["w3_188_alloc_pointer"]) != pointer or int(store["w3_129_b_screen_value"]) != pointer:
        raise ValueError("B_SCREEN store does not match allocation return")
    if int(free["eax"]) != pointer or int(free["w3_129_b_screen_value"]) != pointer:
        raise ValueError("free entry does not match same-run B_SCREEN allocation")
    if not (allocation["sequence"] < store["sequence"] < free["sequence"]):
        raise ValueError("B_SCREEN lifetime event order mismatch")
    rebase = int(run["code_rebase"], 16)
    if any(int(row["eip"]) - int(row["link_va"]) != rebase for row in (allocation, store, free)):
        raise ValueError("B_SCREEN checkpoints do not share the recorded code rebase")
    if not (allocation["process_psp"] == store["process_psp"] == free["process_psp"] == run["psp"]):
        raise ValueError("B_SCREEN checkpoints do not share the recorded process PSP")

    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le
    image = load_le(TARGET)
    free_window = decode_window(image, 0x000929D0, 0x00092A10)
    alloc_window = decode_window(image, 0x00092B6B, 0x00092B90)
    free_call = next((ins for ins in free_window if ins["link_va"] == 0x000929F5), None)
    if not free_call or free_call["mnemonic"] != "call" or "0x92030" not in free_call["operands"].lower():
        raise ValueError("static B_SCREEN free callsite at 0x929F5 did not decode")
    if int(free["return_address"]) - rebase != 0x000929FA:
        raise ValueError("dynamic free return does not identify the decoded 0x929F5 call")
    alloc_call = next((ins for ins in alloc_window if ins["mnemonic"] == "call" and
                       "0x91e00" in ins["operands"].lower()), None)
    store_ins = next((ins for ins in alloc_window if ins["link_va"] == 0x00092B87), None)
    pointer_store = next((ins for ins in alloc_window if ins["link_va"] == 0x00092B82), None)
    if (not alloc_call or not store_ins or store_ins["mnemonic"] != "mov" or
            not pointer_store or pointer_store["mnemonic"] != "mov" or
            "0x114ca0" not in pointer_store["operands"].lower()):
        raise ValueError("allocation/store code window did not decode as expected")
    sample_start, sample_end = bounded_sample_range(pointer, ALLOC_SIZE)
    return {
        "schema": "w3-201-bscreen-phase-audit/v1",
        "task": "W3-201",
        "classification": "SAME_RUN_ALLOCATION_STORE_FREE_CONFIRMED_PRE_FREE_SAMPLE_ACTIONABLE",
        "provenance": {"target_path": "evidence/genewars-1_1.exe", "target_sha256": actual_hash,
                       "w3_199_evidence_sha256": sha(RUN_EVIDENCE),
                       "w3_199_trace_sha256": run["trace"]["sha256"],
                       "w3_188_evidence_sha256": sha(OLD_EVIDENCE)},
        "w3_199_same_run": {"run_id": run["run_id"], "psp": run["psp"],
                            "code_rebase": run["code_rebase"],
                            "allocation": {"sequence": allocation["sequence"],
                                           "link_va": hex(allocation["link_va"]),
                                           "runtime_eip": hex(allocation["eip"]),
                                           "pointer": hex(pointer), "size_bytes": ALLOC_SIZE},
                            "store": {"sequence": store["sequence"], "link_va": hex(store["link_va"]),
                                      "b_screen_pointer": hex(int(store["w3_129_b_screen_value"]))},
                            "free": {"sequence": free["sequence"], "link_va": hex(free["link_va"]),
                                     "eax_pointer": hex(int(free["eax"])),
                                     "return_address_runtime": hex(int(free["return_address"])),
                                     "return_address_link_va": hex(int(free["return_address"]) - rebase)}},
        "w3_188_distinct_run": {"run_id": prior["run_id"], "pointer": prior["pointer"],
                                "sample_bytes": prior["sample_bytes"], "nonzero_bytes": prior["nonzero_bytes"],
                                "sample_hex": prior["sample_hex"],
                                "interpretation": "64-byte zero prefix at its measured store checkpoint; separate execution, not merged with W3-199."},
        "static_windows": {"le_mem_base": image.mem_base,
                           "play_smacker_free_branch": free_window,
                           "b_screen_alloc_and_store": alloc_window,
                           "interpretation": "Static instructions identify allocation/store and the free callsite. They do not establish which guest writes occurred between W3-199 checkpoints."},
        "bounded_sample_candidate": {"checkpoint": "W3_129_MEMORY_FREE_ENTRY at link VA 0x92030",
                                     "runtime_mapping": "Use the current replay's measured code/data descriptors and PSP.",
                                     "only_if": ["EAX equals the same-run B_SCREEN pointer captured at 0x92B87",
                                                 "the recorded allocation size is 0x4B000",
                                                 "current DS descriptor and physical memory bounds validate the entire allocation"],
                                     "sample_start": hex(sample_start), "sample_end_exclusive": hex(sample_end),
                                     "bytes_max": SAMPLE_BYTES,
                                     "interpretation_limit": "Raw allocation bytes only; nonzero data is not pixel-format, framebuffer-presentation, menu, or gameplay proof."},
        "next_action": "Add one 64-byte raw sample at the matching free-entry candidate, reusing W3-188's descriptor/physical/allocation bounds and same-pointer checks; run one guarded replay only after synthetic tests and fresh sandbox verification.",
        "limitations": ["No new replay was performed.", "W3-199 itself did not sample payload at free entry.",
                        "W3-188's zero prefix is from a separate run and cannot stand in for W3-199 contents."],
    }


def main() -> int:
    result = audit()
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(OUTPUT), "classification": result["classification"],
                      "sample_candidate": result["bounded_sample_candidate"],
                      "static_free_callsite": result["static_windows"]["play_smacker_free_branch"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
