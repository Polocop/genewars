"""Source and trace audit for missing W3-125 target callbacks; never runs DOSBox."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
PRIOR = ROOT / "evidence/w3_125_lbmemoryalloc_boundary.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_125_LBMEMORYALLOC_BOUNDARY_20261009_01.jsonl"
SELECTED_SITES = (0x92B71, 0x92B7D, 0x91E00, 0x92B82)


def audit_source(source: str) -> dict[str, Any]:
    selection_start = source.index("const bool selected_capture_site")
    selection_end = source.index("// Before MAIN's runtime mapping is known", selection_start)
    selected = source[selection_start:selection_end]
    window_start = source.index("const bool video_probe_window")
    window_end = source.index("in_target_function =", window_start)
    video = source[window_start:window_end]
    fallback_start = source.index("// A selected address can still live inside a cached dynrec block")
    fallback_end = source.index("if (!chandler)", fallback_start)
    fallback = source[fallback_start:fallback_end]
    block_start = source.index("CacheBlock * block=chandler->FindCacheBlock")
    block_end = source.index("run_block:", block_start)
    block = source[block_start:block_end]
    return {
        "selected_sites_present": {f"0x{site:08X}": f"0x{site:08x}" in selected for site in SELECTED_SITES},
        "checkpoint_is_gated_by_current_restart_site": "const bool trace_candidate" in source and
            "if (trace_candidate)" in source and "target_runtime_checkpoint" in source,
        "video_window_includes_callsite": "candidate_link_va >= 0x00092930 && candidate_link_va <= 0x00092add" in video,
        "one_cycle_normal_core_video_fallback": "if (setup_this_probe_window || video_probe_window)" in fallback and
            "CPU_Cycles = 1" in fallback and "sync_dh_fpu_and_run_normal_core" in fallback,
        "fallback_restarts_only_on_zero_return": "if (!nc_retcode)" in fallback and "goto restart_core" in fallback,
        "new_block_limited_when_trace_candidate": "in_target_function ? 1 : 32" in block,
        "cached_block_reused_without_selected_site_split": "if (!block)" in block and
            "FindCacheBlock(ip_point&4095)" in block,
        "source_sha256": hashlib.sha256(CORE.read_bytes()).hexdigest(),
    }


def audit_trace() -> dict[str, Any]:
    evidence = json.loads(PRIOR.read_text(encoding="utf-8"))
    raw = TRACE.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != evidence["trace"]["sha256"]:
        raise ValueError("W3-125 raw trace hash mismatch")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    checkpoints = [row for row in rows if row.get("event") == "target_runtime_checkpoint"]
    relevant = [row for row in checkpoints if row.get("link_va") in
                (0x92B71, 0x92B7D, 0x91E00, 0x92B82, 0x92B87)]
    links = [row.get("link_va") for row in relevant]
    return {
        "trace_sha256": digest,
        "target_checkpoint_count": len(checkpoints),
        "relevant_observed_link_vas": [f"0x{link:08X}" for link in links],
        "expected_capture_links_missing": [f"0x{link:08X}" for link in
            (0x92B7D, 0x91E00, 0x92B82) if link not in links],
        "anchor_and_later_join_observed": 0x92B71 in links and 0x92B87 in links,
        "interpretation": "Instrumentation gap is directly observed; source has a per-restart selected-site checkpoint and a one-cycle normal-core video path that spans 0x92B7D, but this trace does not prove that the callsite/callee became a restart checkpoint. The exact runtime reason for that omission remains unresolved.",
    }


def build_evidence() -> dict[str, Any]:
    prior_raw = PRIOR.read_bytes()
    source_result = audit_source(CORE.read_text(encoding="utf-8"))
    trace_result = audit_trace()
    return {
        "schema": "w3-126-callback-coverage/v1",
        "task": "W3-126",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "prior_w3_125_evidence_sha256": hashlib.sha256(prior_raw).hexdigest(),
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "source_audit": source_result,
        "original_trace_audit": trace_result,
        "conclusion": "The registered W3-125 test failure was an omitted FALLTHROUGH constant and is fixed; its six-test suite now passes. Source confirms checkpoints are selected from the current restart PC. Although the video probe spans 0x92B7D and includes a one-cycle normal-core fallback, the W3-125 trace still lacks the callsite/callee/return checkpoints. The cause of that missed callback remains unresolved; no new original replay is justified until instrumentation coverage is measured or changed.",
        "next_action": "Add a synthetic or bounded diagnostic for per-instruction callback/restart coverage at 0x92B7D and 0x91E00, then adjust the capture mechanism before any new original replay.",
        "original_replay_performed_by_this_task": False,
    }


if __name__ == "__main__":
    out = ROOT / "evidence/w3_126_callback_coverage.json"
    out.write_text(json.dumps(build_evidence(), indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(out), "source_audit": audit_source(CORE.read_text(encoding="utf-8")),
                      "trace_audit": audit_trace()}, indent=2))
