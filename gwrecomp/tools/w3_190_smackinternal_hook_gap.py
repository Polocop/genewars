"""Read-only audit of the missing W3-181 handler progress checkpoint."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "build/dosboxx_oracle/C/W3_181_SMACKINTERNAL010_PROGRESS_20261009_01.jsonl"
CAPTURE = ROOT / "evidence/w3_181_smackinternal010_progress.json"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
W180 = ROOT / "evidence/w3_180_smackinternal010_audit.json"
OUTPUT = ROOT / "evidence/w3_190_smackinternal_hook_gap.json"


def analyze(capture, events, source_text, capture_source_sha, current_source_sha, static_audit):
    by_name = {e.get("checkpoint"): e for e in events if e.get("checkpoint")}
    first = by_name.get("W3_177_UNSMACK_DISPATCH_FIRST")
    entry = by_name.get("W3_177_UNSMACK_HANDLER_ENTRY")
    reentry = by_name.get("W3_177_UNSMACK_DISPATCH_REENTRY")
    progress = by_name.get("W3_181_SMACKINTERNAL010_PROGRESS")
    if not (first and entry and reentry):
        raise ValueError("required dispatch/handler events absent")
    if not (first["sequence"] < entry["sequence"] < reentry["sequence"]):
        raise ValueError("dispatch event order invalid")
    if progress is not None:
        raise ValueError("W3-181 trace does contain the supposedly missing checkpoint")
    sequence = [e for e in events if entry["sequence"] <= e.get("sequence", -1) <= reentry["sequence"]]
    if len(sequence) < 2:
        raise ValueError("insufficient intervening event context")
    compact = "".join(source_text.split())
    candidate = "constboolw3_181_progress_candidate=target_context&&target_main_rebase&&w3_177_target_entry_seen&&!w3_181_progress_seen&&candidate_link_va==0x000ecd40;"
    if candidate not in compact:
        raise ValueError("current source no longer contains the expected progress-candidate gate")
    candidate = "const bool w3_181_progress_candidate = target_context && target_main_rebase &&"
    restart = source_text.find("restart_core:")
    progress_at = source_text.find(candidate)
    fallback = source_text.find("if (w3_143_postopen_probe_window", progress_at)
    dynrun = source_text.find("sync_normal_fpu_and_run_dyn_code(block->cache.start)", progress_at)
    if min(restart, progress_at, fallback, dynrun) < 0 or not (restart < progress_at < fallback < dynrun):
        raise ValueError("unexpected current hook evaluation/core dispatch layout")
    fallback_region = source_text[fallback:source_text.find("if (!chandler)", fallback)]
    cache_targets_start = source_text.find("static constexpr uint32_t w3_167_target_link_vas[]")
    cache_targets_end = source_text.find("};", cache_targets_start)
    cache_targets = source_text[cache_targets_start:cache_targets_end]
    if "0x000ecd40" in fallback_region or "0x000ecd40" in cache_targets:
        raise ValueError("current probe fallback/cache-span list unexpectedly includes 0xECD40")
    expected = capture["source"]["instrumented_core_sha256"]
    current_matches = expected == current_source_sha
    return {
        "schema": "w3-190-smackinternal-hook-gap/v1",
        "task": "W3-190",
        "classification": "SOURCE_MISMATCH_CAUSE_UNRESOLVED",
        "capture": {
            "run_id": capture["run_id"],
            "target_sha256": capture["source"]["target_sha256"],
            "trace_sha256": capture["trace"]["sha256"],
            "trace_events": len(events),
            "captured_instrumented_core_sha256": expected,
            "current_instrumented_core_sha256": current_source_sha,
            "source_hash_matches_captured_build": current_matches,
        },
        "observed_event_order": [
            {"sequence": first["sequence"], "checkpoint": first["checkpoint"], "link_va": hex(first["link_va"])},
            {"sequence": entry["sequence"], "checkpoint": entry["checkpoint"], "link_va": hex(entry["link_va"])},
            {"sequence": reentry["sequence"], "checkpoint": reentry["checkpoint"], "link_va": hex(reentry["link_va"])},
        ],
        "trace_gap": {
            "progress_checkpoint_present": False,
            "progress_link_va": "0x000ECD40",
            "intervening_events": len(sequence) - 2,
            "dispatcher_reentry_proves_handler_completion": False,
            "guest_control_flow_skip_proven": False,
        },
        "current_source_audit": {
            "source_sha256": current_source_sha,
            "progress_candidate_gate_present": True,
            "candidate_requires_target_handler_entry_seen": True,
            "candidate_evaluated_from_restart_core_path": restart < progress_at,
            "target_in_current_one_cycle_probe_window": False,
            "target_in_current_cache_span_target_list": False,
            "dynrec_block_execution_follows_candidate_checks": progress_at < dynrun,
            "applies_to_w3_181_build": current_matches,
            "static_w3_180_branch_convergence": static_audit["first_branch"]["target_link_va"] == "0xecd40",
        },
        "classification_reason": "The preserved W3-181 trace has dispatcher and handler entries followed by dispatcher re-entry, but no 0xECD40 event. The current instrumentation source has a plausible dynrec boundary coverage gap, but its SHA-256 differs from the source hash recorded for W3-181, so this source cannot establish why that run missed the checkpoint.",
        "next_action": "Locate an immutable source snapshot matching the captured instrumented-core SHA-256, or build a new instrumented binary with the exact 0xECD40 cached-block discriminator and synthetic coverage before any separately authorized guarded replay. Do not repeat W3-181 unchanged.",
    }


def build():
    raw = TRACE.read_bytes()
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    if hashlib.sha256(raw).hexdigest() != capture["trace"]["sha256"] or len(raw) != capture["trace"]["bytes"]:
        raise ValueError("W3-181 raw trace provenance mismatch")
    events = [json.loads(line) for line in raw.splitlines()]
    source_bytes = SOURCE.read_bytes()
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    audit = json.loads(W180.read_text(encoding="utf-8"))
    result = analyze(capture, events, source_bytes.decode("utf-8"), capture["source"]["instrumented_core_sha256"], source_sha, audit)
    result["capture"]["source_path"] = "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
    result["capture"]["trace_bytes"] = len(raw)
    return result


def main():
    result = build()
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"classification": result["classification"], "source_hash_matches": result["capture"]["source_hash_matches_captured_build"], "next_action": result["next_action"], "output": str(OUTPUT)}, indent=2))


if __name__ == "__main__":
    main()
