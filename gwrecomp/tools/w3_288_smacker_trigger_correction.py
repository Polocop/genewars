#!/usr/bin/env python3
"""Correct W3-287's later-Smacker trigger using current source and retained traces."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
W287 = ROOT / "evidence/w3_287_smacker_timeout_audit.json"
W280 = ROOT / "evidence/w3_280_play_smk_step.json"
W285 = ROOT / "evidence/w3_285_smacker_callee_capture.json"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
RENDER = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/gui/render/opengl_renderer.cpp"
OUT = ROOT / "evidence/w3_288_smacker_trigger_correction.json"
REPORT = ROOT / "reports/coordination/w3_288_smacker_trigger_correction.md"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_event(rows: list[dict[str, Any]], event: str) -> list[dict[str, Any]]:
    return [r for r in rows if r.get("event") == event]


def correct_plan(w287: dict[str, Any], w280_rows: list[dict[str, Any]], w285_rows: list[dict[str, Any]],
                 core_source: str, renderer_source: str, core_hash: str, recorded_w285_core_hash: str) -> dict[str, Any]:
    latch_terms = [
        "w3_117_seen_mask |= w3_117_target_bit",
        "!(w3_117_seen_mask & w3_117_target_bit)",
        "static uint32_t w3_117_seen_mask = 0",
    ]
    mask_occurrences = core_source.count("w3_117_seen_mask")
    mask_assignments = [line.strip() for line in core_source.splitlines()
                        if re.search(r"\bw3_117_seen_mask\s*=(?!=)", line)]
    one_shot_current = (all(x in core_source for x in latch_terms)
                        and len(mask_assignments) == 1
                        and mask_assignments[0].startswith("static uint32_t"))
    w275_logic = all(x in core_source for x in (
        "w3_269_game_targets_armed && target_context && target_main_rebase",
        "!w3_275_second_smacker_entry_seen && candidate_link_va == 0x000929d0",
        "w3_275_second_smacker_entry_seen && !w3_275_second_smacker_callsite_seen",
        "candidate_link_va == 0x00092add",
        'w3_275_capture_second_smacker("w3_275_second_smacker_callsite")',
    ))
    event280 = find_event(w280_rows, "w3_275_second_smacker_callsite")
    event285 = find_event(w285_rows, "w3_275_second_smacker_callsite")
    cp280 = [r for r in w280_rows if r.get("event") == "target_runtime_checkpoint" and r.get("checkpoint") == "W3_117_PLAYSMACKER_CALLSITE"]
    selected_seq = {"second_smacker_entry": 389, "w3_275_callsite_marker": 393, "adjacent_w3_117_checkpoint": 394,
                    "media_entry": 395, "branch_entry": 396, "branch_destination": 399}
    actual_seq = {
        "second_smacker_entry": next((r.get("sequence") for r in find_event(w280_rows, "w3_275_second_smacker_entry")), None),
        "w3_275_callsite_marker": event280[0].get("sequence") if event280 else None,
        "adjacent_w3_117_checkpoint": next((r.get("sequence") for r in cp280 if r.get("sequence", 0) > (event280[0].get("sequence", 0) if event280 else 0)), None),
        "media_entry": next((r.get("sequence") for r in find_event(w280_rows, "w3_275_second_smacker_media_entry")), None),
        "branch_entry": next((r.get("sequence") for r in find_event(w280_rows, "w3_278_later_play_smk_entry")), None),
        "branch_destination": next((r.get("sequence") for r in find_event(w280_rows, "w3_278_branch_target")), None),
    }
    render_present_prereq = "VGA_W3_262_PresentCaptureActive()" in renderer_source and "GWRECOMP_W3_269_CAPTURE" in renderer_source
    corrected = {
        "trigger": "Use the one-shot event w3_275_second_smacker_callsite at link 0x92ADD. It is armed only after the post-present marker has armed game targets and a later 0x929D0 entry sets w3_275_second_smacker_entry_seen. Do not count W3_117 checkpoint rows to infer ordinal 2 in the current W3-285 source.",
        "source_semantics": {
            "current_core_sha256": core_hash,
            "matches_w3_285_recorded_core_source": core_hash == recorded_w285_core_hash,
            "w3_117_seen_mask_reference_count": mask_occurrences,
            "w3_117_one_shot_seen_mask_and_no_reset_found": one_shot_current,
            "do_not_project_current_w3_117_semantics_back_to_w3_280": True,
            "w3_275_latch_prerequisites_found": w275_logic,
            "post_present_marker_requires_262_present_capture_and_w3_269": render_present_prereq,
            "viewport_sample_w3_267_is_required_for_marker": False,
        },
        "W3_280_same_run_sequence_check": {"expected": selected_seq, "observed": actual_seq,
                                            "matches": selected_seq == actual_seq,
                                            "adjacent_rows_are_same_callsite_region_not_two_ordinal_occurrences": bool(event280 and actual_seq["adjacent_w3_117_checkpoint"] == actual_seq["w3_275_callsite_marker"] + 1)},
        "W3_285_marker_observed": bool(event285),
        "cause_of_missing_W3_285_later_invocation": "UNKNOWN; no later W3-275 marker, branch event, or execution-stop observation identifies a cause before the guard timeout.",
        "corrected_capture_design": {
            "arm_from": "w3_275_second_smacker_callsite (unique same-run later caller latch), not W3_117 checkpoint ordinal",
            "retain_for_arm": ["GWRECOMP_W3_262_CAPTURE=1", "GWRECOMP_W3_269_CAPTURE=1"],
            "optional_capture_to_omit": "GWRECOMP_W3_267_CAPTURE_VIEWPORT; it gates bounded viewport readback, not the W3-269 marker itself.",
            "then_capture": [
                "later wrapper entry 0xAE2D0",
                "global load/test/actual branch destination 0xAE2DF, 0xAE2E1, then 0xAE2E3 or 0xAE2E8",
                "if destination 0xAE2E3, step TEST BL/JE and record actual target 0xAE2E8 or 0xAE2F2",
                "if path reaches 0xAE2F2, record global compare at 0xAE2FC and actual target/convergence at 0xAE301",
                "record the actual callee entry: 0xAE308 only on the observed 0xAE301 call path; 0xAE4D8 if the alternate static call path is taken",
            ],
            "max_selected_events": 10,
            "step_instruction_cap": 16,
            "trace_byte_cap": 1048576,
            "trace_row_cap": 2048,
            "wall_timeout_s": 120,
            "fresh_main_mapping_required": True,
            "timeout_interpretation": "INCONCLUSIVE; do not infer branch or cause from missing events.",
        },
        "correction_to_w3_287": "The W3-287 suggestion to count W3_117_PLAYSMACKER_CALLSITE checkpoint rows as ordinal 2 is withdrawn for the current W3-285 source. The current seen-mask/one-shot predicate blocks a repeated target bit; W3-280's two target rows come from a different core source hash. Use the measured W3-275 latch instead.",
        "handoff_content": "Correction to W3-287: do not select occurrence 2 from W3_117 checkpoint rows in the W3-285 source. Use the W3-275 later-callsite latch sequence instead. W3-285 remains a duplicate first invocation; W3-280's later branch is the only measured later gate. Timeout cause remains UNKNOWN. No Runtime change or parity claim.",
        "no_new_oracle_or_build": True,
        "source_evidence": {
            "w3_285_source_hash_recorded": recorded_w285_core_hash,
            "current_renderer_sha256": sha(renderer_source.encode("utf-8")),
            "W3_280_core_hash_recorded": w287["run_comparison"]["W3-280"]["core_dyn_x86_sha256"],
        },
    }
    return corrected


def run_audit(root: Path = ROOT) -> dict[str, Any]:
    w287 = json.loads((root / W287.relative_to(ROOT)).read_text(encoding="utf-8"))
    w280meta = json.loads((root / W280.relative_to(ROOT)).read_text(encoding="utf-8"))
    w285meta = json.loads((root / W285.relative_to(ROOT)).read_text(encoding="utf-8"))
    def rows(meta: dict[str, Any]) -> list[dict[str, Any]]:
        p = root / meta["trace"]["path"].replace("\\", "/")
        raw = p.read_bytes()
        if sha(raw) != meta["trace"]["sha256"] or len(raw) != meta["trace"]["bytes"]:
            raise ValueError(f"trace integrity mismatch: {p}")
        return [json.loads(line) for line in raw.splitlines() if line.strip()]
    core_bytes = (root / CORE.relative_to(ROOT)).read_bytes()
    core = core_bytes.decode("utf-8")
    render = (root / RENDER.relative_to(ROOT)).read_text(encoding="utf-8")
    recorded_hash = w285meta["provenance"]["source_sha256"]["src/cpu/core_dyn_x86.cpp"]
    result = correct_plan(w287, rows(w280meta), rows(w285meta), core, render, sha(core_bytes), recorded_hash)
    result["task"] = "W3-288"
    result["schema"] = "w3-288-smacker-trigger-correction/v1"
    result["evidence_level"] = "ORIGINAL_OBSERVED_WITH_STATIC_SOURCE_CORRECTION"
    return result


def render_report(result: dict[str, Any]) -> str:
    seq = result["W3_280_same_run_sequence_check"]
    src = result["source_semantics"]
    plan = result["corrected_capture_design"]
    return "\n".join([
        "# W3-288 — Corrected later-Smacker trigger",
        "",
        "Status: **offline source/evidence correction**. No Oracle, DOSBox, or build was run.",
        "",
        "## Why W3-287's suggested ordinal was unsafe",
        "",
        f"The current core source hash `{result['source_evidence']['w3_285_source_hash_recorded']}` matches the W3-285 recorded core source. Its W3-117 checkpoint uses a seen-bit mask and one-shot predicate (`{src['w3_117_seen_mask_reference_count']}` source references; reset not found: `{src['w3_117_one_shot_seen_mask_and_no_reset_found']}`). Therefore an emitted W3-117 target checkpoint is not a reliable counter for dynamic callsite occurrence 2 in this build. W3-280 has a different core source hash, so its behavior is not projected backward onto W3-285.",
        "",
        "## Code-backed later-callsite latch",
        "",
        f"W3-275's custom latch prerequisites are present in source: `{src['w3_275_latch_prerequisites_found']}`. W3-280 records second Smacker entry at seq {seq['observed']['second_smacker_entry']}, the custom later-callsite marker at seq {seq['observed']['w3_275_callsite_marker']}, the adjacent W3-117 row at seq {seq['observed']['adjacent_w3_117_checkpoint']}, media entry at seq {seq['observed']['media_entry']}, then branch entry/destination at {seq['observed']['branch_entry']}/{seq['observed']['branch_destination']}. Sequence audit matches: `{seq['matches']}`. W3-285 has no W3-275 later-callsite marker.",
        "",
        "The post-present arm requires W3-262 present capture plus W3-269. W3-267 controls optional viewport readback and is not required by the source path that sets the W3-269 marker.",
        "",
        "## Corrected bounded capture design",
        "",
        f"Arm on `{plan['arm_from']}`. Capture the real later wrapper/branch path and follow its actual destination; do not assume every branch reaches `0xAE308`. If the path reaches the common `0xAE301` call, record `0xAE308`; if the alternate static route is taken, record `0xAE4D8`.",
        "",
        f"Caps: {plan['max_selected_events']} selected events, {plan['step_instruction_cap']} stepped instructions, {plan['trace_byte_cap']} trace bytes, {plan['trace_row_cap']} rows, and the existing {plan['wall_timeout_s']}s timeout. Require a fresh MAIN mapping; timeout remains inconclusive.",
        "",
        "## Corrected W3-287 record",
        "",
        result["correction_to_w3_287"],
        "",
        "WORK2 should treat W3-285 only as duplicate first-invocation confirmation. No Runtime change, original/native parity, executed AE306 return, framebuffer, menu, or gameplay is established.",
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    result = run_audit()
    # Mutate only W3-287's owned artifacts after recording the correction.
    result["supersedes_w3_287_design"] = True
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.report.write_text(render_report(result), encoding="utf-8")
    old_path = ROOT / "evidence/w3_287_smacker_timeout_audit.json"
    old = json.loads(old_path.read_text(encoding="utf-8"))
    old["minimal_next_capture_design"] = result["corrected_capture_design"]
    old["trigger_design_correction"] = {
        "corrected_by": "W3-288",
        "evidence": "evidence/w3_288_smacker_trigger_correction.json",
        "replacement": result["correction_to_w3_287"],
        "cause_remains": "UNKNOWN",
    }
    old_path.write_text(json.dumps(old, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    old_report = ROOT / "reports/coordination/w3_287_smacker_timeout_audit.md"
    old_md = old_report.read_text(encoding="utf-8")
    start_marker = "## Smallest next capture design\n"
    end_marker = "## WORK2 correction\n"
    if start_marker in old_md and end_marker in old_md:
        before, rest = old_md.split(start_marker, 1)
        _, after = rest.split(end_marker, 1)
        replacement = (
            "## Smallest next capture design\n\n"
            "Arm on the source-backed one-shot `w3_275_second_smacker_callsite` marker at `0x92ADD`. "
            "It follows the post-present arm and later `0x929D0` entry. In W3-280 this marker is seq 393; "
            "the adjacent W3-117 target row at seq 394 is the same callsite region, not a separate dynamic ordinal. "
            "Do not use W3-117 target rows as an occurrence counter in the W3-285 source build: its seen-bit mask "
            "suppresses a previously captured target bit. Do not project that implementation backward to W3-280's "
            "different source hash.\n\n"
            "After the later-callsite marker, capture the fresh wrapper entry and actual branch sequence/destination. "
            "Follow the observed path: if it reaches `0xAE301`, record callee `0xAE308`; if it takes the alternate "
            "static call path, record `0xAE4D8`. Keep fresh MAIN rebase validation, <=10 selected events, <=16 "
            "stepped instructions, <=1 MiB / 2048 rows, and the existing 120-second guard. Omit optional viewport "
            "readback while retaining W3-262/W3-269 marker prerequisites. Timeout remains inconclusive.\n\n"
        )
        old_md = before + replacement + end_marker + after
    marker = "\n## Trigger design correction (W3-288)\n"
    if marker in old_md:
        old_md = old_md.split(marker, 1)[0]
    old_report.write_text(old_md + marker + "\n" + result["correction_to_w3_287"] + " See `evidence/w3_288_smacker_trigger_correction.json` for source and trace checks.\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "trigger": "W3-275 later-callsite latch", "sequence_matches": result["W3_280_same_run_sequence_check"]["matches"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
