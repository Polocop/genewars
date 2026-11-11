#!/usr/bin/env python3
"""Offline reconciliation of the W3-289 ECD40 timeout boundary."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "build/dosboxx_oracle/C/W3_289_SMACKER_LATER_CALLEE_20261010_01.jsonl"
CAPTURE = ROOT / "evidence/w3_289_smacker_later_callee_capture.json"
W3_280 = ROOT / "evidence/w3_280_play_smk_step.json"
W3_288 = ROOT / "evidence/w3_288_smacker_trigger_correction.json"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
OUTPUT = ROOT / "evidence/w3_290_ecd40_stall_audit.json"
REPORT = ROOT / "reports/coordination/w3_290_ecd40_stall_audit.md"

REQUIRED_LATCHES = (
    "w3_275_second_smacker_callsite",
    "w3_275_second_smacker_media_entry",
    "w3_278_later_play_smk_entry",
    "w3_278_branch_target",
    "w3_289_smacker_callee_entry",
)


def load_trace(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > 1024 * 1024:
        raise ValueError("W3-289 trace exceeds its one MiB cap")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("trace contains a non-object JSON record")
    return rows


def analyze(raw: bytes, capture: dict[str, Any], source: str) -> dict[str, Any]:
    rows = load_trace(raw)
    trace_hash = hashlib.sha256(raw).hexdigest()
    if capture.get("trace", {}).get("sha256") != trace_hash:
        raise ValueError("raw trace SHA-256 does not match W3-289 capture evidence")
    if capture.get("trace", {}).get("bytes") != len(raw) or capture.get("trace", {}).get("rows") != len(rows):
        raise ValueError("raw trace size/row count does not match W3-289 capture evidence")

    mappings = [row for row in rows if row.get("event") == "main_mapping" and row.get("mapping_matches") is True]
    if len(mappings) != 1:
        raise ValueError("expected exactly one matching MAIN mapping")
    code_rebase = int(mappings[0]["code_rebase"])

    target_checkpoints = [row for row in rows if row.get("event") == "target_runtime_checkpoint"]
    w3_193 = [row for row in rows if row.get("event") == "W3_193_ECD40_STEP_RESULT"]
    w3_198 = [row for row in rows if row.get("event") == "W3_198_ECD40_CONTINUATION_STEP"]
    stop_events = [row for row in rows if row.get("event") == "W3_198_ECD40_CONTINUATION_STOP"]
    present = [row for row in rows if row.get("event") == "backend_present_return"]
    observed_latches = {name: [row for row in rows if row.get("event") == name] for name in REQUIRED_LATCHES}

    if len(w3_193) != 1 or [int(row.get("ordinal", -1)) for row in w3_198] != [1, 2, 3, 4, 5]:
        raise ValueError("W3-193/W3-198 step sequence is incomplete or duplicated")
    last_step = w3_198[-1]
    target_runtime = code_rebase + 0x000ECD40
    expected_before = 0x000ECD31
    for ordinal, step in enumerate(w3_198, 1):
        if int(step.get("ordinal", -1)) != ordinal or int(step.get("before_link_va", -1)) != expected_before:
            raise ValueError("W3-198 continuation links are not a contiguous ordered sequence")
        expected_before = int(step.get("after_link_va", -1))
    if int(last_step.get("after_runtime", -1)) != target_runtime:
        raise ValueError("last W3-198 step did not end at this run's mapped ECD40 target")
    if any(observed_latches.values()):
        raise ValueError("unexpected later Smacker latch/callee event present; task premise changed")
    if capture.get("guard", {}).get("cause") != "TIMEOUT":
        raise ValueError("W3-289 guard evidence is not a timeout")

    # Static source semantics: target-hit disarms without emitting a stop record.
    armed_start = source.find("if (w3_198_ecd40_continuation_armed) {")
    span_end = source.find("if (target_context && target_main_rebase && block &&", armed_start)
    if armed_start < 0 or span_end < 0:
        raise ValueError("cannot locate the bounded W3-198 continuation source block")
    armed_block = source[armed_start:span_end]
    target_hit = armed_block.find("else if (ip_point == w3_198_ecd40_target_runtime)")
    target_hit_end = armed_block.find("} else if", target_hit + 1)
    target_hit_block = armed_block[target_hit:target_hit_end if target_hit_end >= 0 else len(armed_block)]
    target_hit_disarms_silently = (
        target_hit >= 0
        and "w3_198_ecd40_continuation_armed = false;" in target_hit_block
        and "w3_198_log_stop" not in target_hit_block
    )
    step_cap_present = "w3_198_ecd40_continuation_steps < 5" in armed_block
    if not target_hit_disarms_silently or not step_cap_present:
        raise ValueError("W3-198 target-hit/step-cap source semantics changed")

    source_hash = hashlib.sha256(CORE.read_bytes()).hexdigest() if CORE.is_file() else None
    capture_source_hash = capture.get("provenance", {}).get("instrumentation_core_sha256")
    if source_hash != capture_source_hash:
        raise ValueError("current instrumentation source differs from the W3-289 built-source fingerprint")

    branch_link = int(last_step["after_runtime"]) - code_rebase
    w3_280 = json.loads(W3_280.read_text(encoding="utf-8"))
    w3_288 = json.loads(W3_288.read_text(encoding="utf-8"))
    if w3_280.get("analysis", {}).get("branch_destination") != "0x000AE2E3" or w3_280.get("analysis", {}).get("branch_taken") is not False:
        raise ValueError("W3-280 branch-step evidence no longer matches the fall-through premise")
    if w3_288.get("task") != "W3-288":
        raise ValueError("W3-288 source-backed trigger correction evidence is missing")

    return {
        "schema": "w3-290-ecd40-timeout-audit/v1",
        "task": "W3-290",
        "evidence_level": "ORIGINAL_OBSERVED",
        "claim_scope": "offline reconciliation of one existing guarded original replay; no new emulator run",
        "inputs": {
            "w3_289_capture": "evidence/w3_289_smacker_later_callee_capture.json",
            "w3_289_trace": "build/dosboxx_oracle/C/W3_289_SMACKER_LATER_CALLEE_20261010_01.jsonl",
            "w3_280_branch_step": "evidence/w3_280_play_smk_step.json",
            "w3_288_trigger_correction": "evidence/w3_288_smacker_trigger_correction.json",
            "w3_280_observed_branch_destination": w3_280["analysis"]["branch_destination"],
            "w3_280_branch_taken": w3_280["analysis"]["branch_taken"],
            "w3_288_task": w3_288["task"],
            "trace_sha256_verified": trace_hash,
            "built_source_sha256_verified": source_hash,
            "prior_build_source_sha256": capture_source_hash,
        },
        "original_observations": {
            "guard_cause": capture["guard"].get("cause"),
            "guard_exit_reason": capture["guard"].get("exit_reason"),
            "guard_duration_s": capture["guard"].get("duration_s"),
            "matching_main_mapping_count": len(mappings),
            "code_rebase": f"0x{code_rebase:08X}",
            "last_timed_target_checkpoint": ({
                "sequence": target_checkpoints[-1].get("sequence"),
                "checkpoint": target_checkpoints[-1].get("checkpoint"),
                "link_va": f"0x{int(target_checkpoints[-1]['link_va']):08X}",
                "elapsed_ms": target_checkpoints[-1].get("elapsed_ms"),
            } if target_checkpoints else None),
            "w3_193_step_result": {k: w3_193[0].get(k) for k in (
                "sequence", "before_link_va", "after_link_va", "target_runtime", "normal_core_return"
            )},
            "w3_198_continuation_steps": [{k: row.get(k) for k in (
                "sequence", "ordinal", "before_link_va", "after_link_va", "before_runtime", "after_runtime", "normal_core_return"
            )} for row in w3_198],
            "last_step_derived_target": {
                "runtime": f"0x{target_runtime:08X}",
                "link_va": f"0x{branch_link:08X}",
                "derivation": "after_runtime minus this run's unique MAIN code_rebase",
            },
            "w3_198_stop_event_count": len(stop_events),
            "later_latch_counts": {name: len(found) for name, found in observed_latches.items()},
            "backend_present_return_count": len(present),
            "backend_present_frame_hash": (present[-1].get("frame_hash") if present else None),
            "backend_present_pixel_payload": (present[-1].get("post_present_pixels") if present else None),
            "backend_aperture_nonzero_bytes": (present[-1].get("vga", {}).get("aperture_nonzero_bytes") if present else None),
        },
        "source_observations": {
            "w3_198_step_cap_five": step_cap_present,
            "target_hit_disarms_continuation": target_hit_disarms_silently,
            "target_hit_logs_stop_event": False,
            "proof": "In the current source, the ip_point == target_runtime branch disarms the latch and does not call w3_198_log_stop; the separate stop logger is reached only on mapping/process change or the other-path branch.",
        },
        "assessment": {
            "last_emitted_probe": "five-step sequence ended at runtime target whose derived link VA is 0x000ECD40",
            "whether_target_hit_reentry_was_processed": "UNKNOWN: no event is emitted by the source on that branch, and the trace ends before a later checkpoint confirms re-entry",
            "why_later_smacker_latch_was_not_reached": "UNKNOWN: the trace has no later latch/callee; a 120-second guard timeout alone does not distinguish slow execution, an emulator wait, or an instrumentation interaction",
            "cause_attributed_to_single_step_instrumentation": False,
            "framebuffer_verified": False,
            "next_capture_design": "If a new evidence-backed task authorizes another replay, add one bounded event on the W3-198 ECD40 target-hit branch before disarming, recording the fresh MAIN mapping, PSP, CS:EIP/link VA, elapsed time, and next dispatch checkpoint. Preserve the 120-second guard. Do not repeat W3-289 with unchanged source/settings.",
        },
        "event_counts": dict(sorted(Counter(row.get("event", "<missing>") for row in rows).items())),
        "tests": {"synthetic_suite": "tests.test_w3_290_ecd40_stall_audit", "oracle_or_build_executed": False},
    }


def write_outputs(result: dict[str, Any]) -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    orig = result["original_observations"]
    last = orig["w3_198_continuation_steps"][-1]
    assessment = result["assessment"]
    lines = [
        "# W3-290 — Offline ECD40 timeout audit", "",
        "Conclusion: **cause not established**. This audit did not run DOSBox or rebuild Staging.", "",
        f"- W3-289 was terminated by the guard after {orig['guard_duration_s']} s (`{orig['guard_cause']}` / `{orig['guard_exit_reason']}`).",
        f"- Verified MAIN code rebase: `{orig['code_rebase']}`. Last timed checkpoint: sequence {orig['last_timed_target_checkpoint']['sequence']}, `{orig['last_timed_target_checkpoint']['checkpoint']}` at `{orig['last_timed_target_checkpoint']['link_va']}` and {orig['last_timed_target_checkpoint']['elapsed_ms']} ms.",
        f"- W3-193 stepped from `0x{int(result['original_observations']['w3_193_step_result']['before_link_va']):08X}` to `0x{int(result['original_observations']['w3_193_step_result']['after_link_va']):08X}`. W3-198 then emitted ordinals 1–5; ordinal 5 ended at `0x{int(last['after_link_va']):08X}`.",
        f"- The source's W3-198 target-hit branch disarms without emitting `W3_198_ECD40_CONTINUATION_STOP`. The trace does not confirm whether that branch was processed after the final step.",
        f"- Later W3-275/W3-278 latch and callee counts: `{orig['later_latch_counts']}`. Cause of the missing latch remains **UNKNOWN**; single-step instrumentation is not proven causal.",
        f"- Backend present return count: {orig['backend_present_return_count']}; pixel payload and frame hash: `{orig['backend_present_pixel_payload']}` / `{orig['backend_present_frame_hash']}`; aperture nonzero bytes: `{orig['backend_aperture_nonzero_bytes']}`. First framebuffer remains unverified.",
        "", "Next capture design: add a one-shot event on the ECD40 target-hit branch, then record the next dispatch checkpoint under the same guard limits. Do not repeat W3-289 unchanged.", "",
        f"Trace SHA-256: `{result['inputs']['trace_sha256_verified']}`. Built-source SHA-256 match: `{result['inputs']['built_source_sha256_verified']}`.", "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    raw = TRACE.read_bytes()
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    source = CORE.read_text(encoding="utf-8")
    result = analyze(raw, capture, source)
    write_outputs(result)
    print(json.dumps({"evidence": str(OUTPUT), "report": str(REPORT), "conclusion": result["assessment"]["why_later_smacker_latch_was_not_reached"], "last_link_va": result["original_observations"]["last_step_derived_target"]["link_va"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
