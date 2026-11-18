"""Read-only W3-213/W1-063 AdjustAmount checkpoint audit."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REVISION = "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f"
CHECKPOINTS = {
    "W3_213_ADJUST_CALLSITE": 0xC3D98,
    "W3_213_ADJUST_ENTRY": 0xC3F76,
    "W3_213_ADJUST_RETURN": 0xC3D9D,
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def file_record(relative: str) -> dict[str, Any]:
    path = ROOT / relative
    return {"path": relative, "exists": path.is_file(),
            "bytes": path.stat().st_size if path.is_file() else None,
            "sha256": sha256(path) if path.is_file() else None}


def summarize(w3_213: dict[str, Any], trace_213: list[dict[str, Any]],
              w3_068: dict[str, Any], trace_068: list[dict[str, Any]],
              w1_063: dict[str, Any], heap_alignment: dict[str, Any],
              core_text: str) -> dict[str, Any]:
    create_anchors = [row for row in trace_213
                      if row.get("event") == "target_code_anchor" and
                      row.get("anchor") == "CREATE_NEW_NHEAP_ENTRY"]
    checkpoints_213 = [row for row in trace_213
                       if row.get("event") == "target_runtime_checkpoint" and
                       row.get("checkpoint") in CHECKPOINTS and
                       row.get("link_va") == CHECKPOINTS[row.get("checkpoint")]]
    adjust_anchors_068 = [row for row in trace_068
                          if row.get("event") == "target_code_anchor" and
                          row.get("anchor") == "ADJUSTAMOUNT_ENTRY" and
                          row.get("link_va") == 0xC3F76]
    native = w1_063.get("w1_063_strict_ax0501", {})
    native_frontier = native.get("frontier", {})
    original = heap_alignment.get("original", {})
    original_adjust = original.get("adjustamount", {})
    original_entry = adjust_anchors_068[0] if len(adjust_anchors_068) == 1 else None
    native_allocator_events = native.get("allocator_chain_events", [])
    native_adjust_lines = [line for line in native_allocator_events
                           if "ALLOC_ENTRY" in line and "va=000c3f76" in line]
    global_samples = (create_anchors[0].get("selected_global_samples", [])
                      if create_anchors else [])
    global_10c828 = next((sample.get("value_u32") for sample in global_samples
                          if sample.get("link_offset") == 0x10C828), None)
    focus_declared = all(f"0x{address:08x}" in core_text.lower()
                         for address in CHECKPOINTS.values())
    capture_only_is_filter = (
        "const bool trace_candidate = target_context &&" in core_text and
        "(selected_capture_site || possible_main_entry)" in core_text and
        "const bool w3_213_capture_only" in core_text and
        "target_main_rebase && w3_213_focus_site" in core_text
    )
    return {
        "classification": "W3_213_TARGET_CHECKPOINTS_NOT_OBSERVED",
        "w3_213": {
            "run_id": w3_213.get("run_id"),
            "classification": w3_213.get("capture", {}).get("classification"),
            "target_count": w3_213.get("capture", {}).get("target_count"),
            "missing": w3_213.get("capture", {}).get("missing"),
            "code_rebase": w3_213.get("capture", {}).get("main_mapping", {}).get("runtime_rebase"),
            "data_rebase": w3_213.get("capture", {}).get("main_mapping", {}).get("data_rebase"),
            "create_new_nheap_anchor": create_anchors[0] if len(create_anchors) == 1 else None,
            "create_anchor_data_global_10c828": global_10c828,
            "checkpoints_found": checkpoints_213,
            "guard": {k: w3_213.get("guard", {}).get(k) for k in
                      ("exit_reason", "cause", "duration_s", "limits", "sandbox_verified")},
            "trace_event_count": w3_213.get("trace", {}).get("event_count"),
        },
        "w3_068_original": {
            "expand_ordinal": original.get("expand_ordinal"),
            "create_ordinal": original.get("create_ordinal"),
            "rationalalloc_ordinal": original.get("rationalalloc_ordinal"),
            "adjustamount_input": original_adjust.get("input"),
            "adjustamount_output": original_adjust.get("output"),
            "first_write_instruction": original_adjust.get("first_write_instruction"),
            "threshold_global": original.get("threshold_global", "not captured"),
            "adjustamount_entry_anchor": original_entry,
            "anchor_runtime_mapping_valid": bool(original_entry and
                original_entry.get("measured_address_matches") is True and
                original_entry.get("candidate_rebase") == 0x1EB000),
            "global_10c828_at_adjust_entry": None,
        },
        "w1_063_native": {
            "target_sha256": w1_063.get("target_sha256"),
            "command_tail": w1_063.get("command_tail"),
            "first_ax0501_frontier": native_frontier,
            "request_size_bytes": native.get("request_size_bytes"),
            "response_records": native.get("response_records"),
            "adjustamount_entry_lines": native_adjust_lines,
            "native_adjustamount_global_10c828": "0x10" if any(
                "global_10c828=00000010" in line for line in native_adjust_lines) else None,
        },
        "hypothesis_audit": {
            "all_three_sites_named_in_core": focus_declared,
            "capture_only_is_a_restart_candidate_filter": capture_only_is_filter,
            "w3_213_did_not_emit_any_requested_target_checkpoint": len(checkpoints_213) == 0,
            "exact_reason_target_was_not_seen": "UNKNOWN: the trace proves the configured candidate checkpoints were not emitted, but does not distinguish an unexecuted path from an address that was not a dynrec restart boundary.",
            "new_hypothesis_supported": capture_only_is_filter and len(checkpoints_213) == 0 and
                original_entry is not None,
            "new_hypothesis": "Add an explicit bounded dynrec block split/restart at the verified AdjustAmount callsite, entry, and return link VAs; in one replay re-verify code/data rebases, then sample only the requested stack slot and [0x10C828]/[0x10B78E..0x10B790].",
            "do_not_combine": [
                "W3-068 original AdjustAmount input 0x40/output 0x1000 with native W1-063 input slot 1/output 0x1000 as if they were one invocation.",
                "W3-213 CreateNewNHeap global sample 0x10 with W3-068 AdjustAmount entry from another run.",
                "W1 heap-init 0x8000 observations with W3-068/W1-063 first 0x1000 requests."
            ],
        },
    }


def audit() -> dict[str, Any]:
    w3_213_path = ROOT / "evidence/w3_213_adjustamount_original.json"
    w3_213 = read_json(w3_213_path)
    trace_213_path = ROOT / w3_213["trace"]["path"]
    w3_068_path = ROOT / "evidence/w3_068_caller_chain_capture_20261008.json"
    w3_068 = read_json(w3_068_path)
    trace_068_path = ROOT / "evidence/w3_068_heap_alignment_capture_20261008_01.jsonl"
    w1_path = ROOT / "evidence/native_ax0501_strict_w1_063.json"
    heap_path = ROOT / "evidence/w1_heap_init_alignment_20261008.json"
    core_path = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
    runner_path = ROOT / "tools/w3_213_adjustment_capture.py"
    w1 = read_json(w1_path)
    heap = read_json(heap_path)
    core_text = core_path.read_text(encoding="utf-8", errors="replace")
    host_build = w3_213.get("host_build", {})
    binary_path = ROOT / host_build.get("binary_path", "")
    current_binary_path = ROOT / "build/staging-w3-059-exec/Debug/dosbox.exe"
    revision = host_build.get("source_revision")
    files = {str(path.relative_to(ROOT)): file_record(str(path.relative_to(ROOT)))
             for path in (w3_213_path, trace_213_path, w3_068_path, trace_068_path,
                          w1_path, heap_path, core_path, runner_path,
                          binary_path, current_binary_path) if path.is_file()}
    result = summarize(w3_213, read_jsonl(trace_213_path), w3_068,
                       read_jsonl(trace_068_path), w1, heap, core_text)
    return {
        "schema": "gwrecomp.w3-222-adjustment-checkpoint-audit/v1",
        "task": "W3-222",
        "evidence_level": "SYNTHETIC_PASS",
        "source_evidence_level": "ORIGINAL_OBSERVED",
        "runtime_capture_outcome": "INCONCLUSIVE",
        "pinned_staging_revision": EXPECTED_REVISION,
        "w3_213_source_revision_matches_pin": revision == EXPECTED_REVISION,
        "w3_213_source_core_sha256": host_build.get("source_core_sha256"),
        "current_core_sha256": files.get(str(core_path.relative_to(ROOT)), {}).get("sha256"),
        "w3_213_build_sha256": host_build.get("binary_sha256"),
        "current_instrumented_binary_sha256": files.get(str(current_binary_path.relative_to(ROOT)), {}).get("sha256"),
        "files": files,
        **result,
        "limitations": [
            "The W3-068 AdjustAmount entry anchor and W3-213 CreateNewNHeap data anchor are from different original runs.",
            "No new replay was run for this static/evidence audit.",
            "A W3-068 entry anchor at C3F76 proves that address was observed in that run; it does not prove W3-213's missing target path was executed.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, ensure_ascii=False))
