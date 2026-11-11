#!/usr/bin/env python3
"""Hash-bound static decode of the short original-code window before 0xECD40."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "evidence/genewars-1_1.exe"
RUN_EVIDENCE = ROOT / "evidence/w3_196_ecd40_armed_progress.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_196_ECD40_ARMED_20261009_01.jsonl"
OUTPUT = ROOT / "evidence/w3_197_ecdfollow_static.json"
EXPECTED_TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
START = 0x000ECD2B
STEP_AFTER = 0x000ECD31
TARGET_LINK = 0x000ECD40
WINDOW_END = TARGET_LINK + 5


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_bytes(raw: bytes, start: int) -> list[dict]:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    return [{"link_va": ins.address, "bytes": ins.bytes.hex(),
             "mnemonic": ins.mnemonic, "operands": ins.op_str,
             "size": ins.size}
            for ins in decoder.disasm(raw, start)]


def analyze() -> dict:
    actual_hash = sha(TARGET)
    if actual_hash != EXPECTED_TARGET_SHA256:
        raise ValueError(f"exact original target hash mismatch: {actual_hash}")
    run = json.loads(RUN_EVIDENCE.read_text(encoding="utf-8"))
    if run.get("task") != "W3-196" or run.get("run_id") != "w3-196-ecd40-armed-20261009-01":
        raise ValueError("W3-196 evidence identity mismatch")
    if run.get("source", {}).get("target_sha256") != actual_hash:
        raise ValueError("replay source target does not match the static input")
    step = next((row for row in map(json.loads, TRACE.read_text(encoding="utf-8").splitlines())
                 if row.get("event") == "W3_193_ECD40_STEP_RESULT"), None)
    if step is None:
        raise ValueError("W3-196 bounded step event is missing")
    dispatch = run["first_dispatch"]
    handler = run["handler_entry"]
    rebase = int(run["code_rebase"], 16)
    if not (dispatch["sequence"] < handler["sequence"] < step["sequence"]):
        raise ValueError("dynamic dispatch/handler/step event order mismatch")
    if int(step["before_link_va"]) != START or int(step["after_link_va"]) != STEP_AFTER:
        raise ValueError("same-run pre/post EIP differs from the recorded checkpoint")
    if int(step["target_runtime"]) != rebase + TARGET_LINK:
        raise ValueError("same-run target runtime does not match measured code rebase")

    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le
    image = load_le(TARGET)
    lo, hi = START - image.mem_base, WINDOW_END - image.mem_base
    if lo < 0 or hi > len(image.mem) or hi <= lo:
        raise ValueError("bounded link VA window is outside the loaded LE image")
    raw = bytes(image.mem[lo:hi])
    instructions = decode_bytes(raw, START)
    addresses = [row["link_va"] for row in instructions]
    if not instructions or addresses[0] != START or TARGET_LINK not in addresses:
        raise ValueError("decoder did not cover the measured entry and target boundary")
    target_instruction = next(row for row in instructions if row["link_va"] == TARGET_LINK)
    if target_instruction["bytes"] != "a0c0c91000":
        raise ValueError("exact target instruction bytes at 0xECD40 did not match")
    target_index = addresses.index(TARGET_LINK)
    preceding = instructions[:target_index]
    cursor = START
    for ins in instructions:
        if ins["link_va"] != cursor:
            raise ValueError("disassembly contains a gap before the target")
        cursor += ins["size"]
    flow = {"call", "callf", "jmp", "ljmp", "ja", "jae", "jb", "jbe", "je", "jne",
            "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp",
            "jcxz", "jecxz", "loop", "loope", "loopne", "ret", "retf", "iret"}
    transfers_before_target = [ins for ins in preceding if ins["mnemonic"] in flow]
    if transfers_before_target:
        raise ValueError(f"control transfer occurs before the target: {transfers_before_target}")
    suffix = [row for row in instructions if STEP_AFTER <= row["link_va"] <= TARGET_LINK]
    return {
        "schema": "w3-197-ecdfollow-static/v1",
        "task": "W3-197",
        "classification": "STATIC_FALLTHROUGH_TO_ECD40_DYNAMICALLY_UNCONFIRMED",
        "provenance": {"target": "evidence/genewars-1_1.exe", "target_sha256": actual_hash,
                       "source_run_evidence": "evidence/w3_196_ecd40_armed_progress.json",
                       "source_trace": "build/dosboxx_oracle/C/W3_196_ECD40_ARMED_20261009_01.jsonl",
                       "trace_sha256": run["trace"]["sha256"],
                       "staging_revision": run["source"]["staging_revision"]},
        "dynamic_observation": {"dispatch_sequence": dispatch["sequence"],
                                "handler_sequence": handler["sequence"],
                                "step_sequence": step["sequence"],
                                "code_rebase": rebase,
                                "before_link_va": int(step["before_link_va"]),
                                "after_link_va": int(step["after_link_va"]),
                                "target_runtime": int(step["target_runtime"]),
                                "target_link_va": TARGET_LINK,
                                "target_reached_in_run": False},
        "static_decode": {"le_mem_base": image.mem_base,
                          "window_start_link_va": START,
                          "window_end_exclusive": WINDOW_END,
                          "window_bytes": raw.hex(),
                          "instructions": instructions,
                          "post_step_successor": STEP_AFTER,
                          "instructions_from_successor_through_target": suffix,
                          "control_transfer_before_target": transfers_before_target,
                          "interpretation": "The decoded bytes are contiguous fall-through through 0xECD40; this is static control flow, not proof that the replay dynamically executed the intervening instructions."},
        "next_action": "Instrument a fixed maximum of five additional normal-core single-instruction advances from 0xECD31; emit bounded pre/post EIP per advance and stop immediately when pre-EIP equals 0xECD40, the path diverges, or the cap is reached. Do not repeat the prior one-step replay unchanged.",
        "limitations": ["No new original execution occurred in this task.",
                        "The dynamic replay did not reach 0xECD40.",
                        "No framebuffer or pixel payload is established."],
    }


def main() -> int:
    result = analyze()
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(OUTPUT), "classification": result["classification"],
                      "window_bytes": result["static_decode"]["window_bytes"],
                      "next": result["next_action"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
