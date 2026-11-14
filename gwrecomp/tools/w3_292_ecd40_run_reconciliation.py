#!/usr/bin/env python3
"""Offline compare the retained W3-289 and W3-291 ECD40 runs."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNS = {
    "W3-289": {
        "capture": ROOT / "evidence/w3_289_smacker_later_callee_capture.json",
        "trace": ROOT / "build/dosboxx_oracle/C/W3_289_SMACKER_LATER_CALLEE_20261010_01.jsonl",
        "guard": ROOT / "evidence/oracle_runs/oracle_runs_w3-289-smacker-later-callee-20261010-01.json",
        "runner": ROOT / "tools/w3_289_smacker_later_callee_runner.py",
    },
    "W3-291": {
        "capture": ROOT / "evidence/w3_291_ecd40_target_hit_capture.json",
        "trace": ROOT / "build/dosboxx_oracle/C/W3_291_ECD40_TARGET_HIT_20261010_01.jsonl",
        "guard": ROOT / "evidence/oracle_runs/oracle_runs_w3-291-ecd40-target-hit-20261010-01.json",
        "runner": ROOT / "tools/w3_291_ecd40_target_hit_runner.py",
    },
}
OUTPUT = ROOT / "evidence/w3_292_ecd40_run_reconciliation.json"
REPORT = ROOT / "reports/coordination/w3_292_ecd40_run_reconciliation.md"


def parse(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > 1024 * 1024:
        raise ValueError("input trace exceeds the recorded one MiB cap")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if len(rows) > 2048 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("trace row shape/count invalid")
    return rows


def _select(rows: list[dict[str, Any]], event: str, checkpoint: str | None = None) -> list[dict[str, Any]]:
    selected = [r for r in rows if r.get("event") == event]
    return [r for r in selected if checkpoint is None or r.get("checkpoint") == checkpoint]


def _registers(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    names = ("sequence", "link_va", "eip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags", "cs", "ds", "es", "ss", "elapsed_ms")
    return {name: row.get(name) for name in names}


def summarize_run(name: str, capture: dict[str, Any], guard: dict[str, Any], raw: bytes, runner: str) -> dict[str, Any]:
    rows = parse(raw)
    trace_meta = capture.get("trace", {})
    trace_hash = hashlib.sha256(raw).hexdigest()
    if trace_hash != trace_meta.get("sha256") or len(raw) != trace_meta.get("bytes") or len(rows) != trace_meta.get("rows"):
        raise ValueError(f"{name}: raw trace does not match its capture manifest")
    if guard.get("run_id") != capture.get("run_id"):
        raise ValueError(f"{name}: guard/capture run id mismatch")
    if guard.get("provenance", {}).get("runtime_sha") != capture.get("provenance", {}).get("binary_sha256"):
        raise ValueError(f"{name}: guard/runtime binary hash mismatch")
    maps = _select(rows, "main_mapping")
    if len(maps) != 1 or maps[0].get("mapping_matches") is not True:
        raise ValueError(f"{name}: exactly one matching MAIN mapping is required")
    base = int(maps[0]["code_rebase"])
    dispatch = _select(rows, "target_runtime_checkpoint", "W3_177_UNSMACK_DISPATCH_FIRST")
    handler = _select(rows, "target_runtime_checkpoint", "W3_177_UNSMACK_HANDLER_ENTRY")
    if len(dispatch) != 1 or len(handler) != 1:
        raise ValueError(f"{name}: W3-177 dispatch/handler checkpoint missing or duplicated")
    initial = _select(rows, "W3_193_ECD40_STEP_RESULT")
    if len(initial) != 1:
        raise ValueError(f"{name}: expected one W3-193 step result")
    steps = _select(rows, "W3_198_ECD40_CONTINUATION_STEP")
    stops = _select(rows, "W3_198_ECD40_CONTINUATION_STOP")
    if len(stops) > 1:
        raise ValueError(f"{name}: duplicate W3-198 stop events")
    toggles = {
        opt: (f'"{key}": "1"' in runner or f'"{key}":"1"' in runner)
        for opt, key in (
            ("w3_279_branch_step", "GWRECOMP_W3_279_BRANCH_STEP"),
            ("w3_285_capture", "GWRECOMP_W3_285_CAPTURE"),
            ("w3_289_capture", "GWRECOMP_W3_289_CAPTURE"),
            ("w3_291_capture", "GWRECOMP_W3_291_CAPTURE"),
        )
    }
    counts = Counter(row.get("event", "<missing>") for row in rows)
    return {
        "run_id": capture.get("run_id"),
        "target_sha256": capture.get("provenance", {}).get("target_sha256"),
        "fixture_bytes": capture.get("provenance", {}).get("fixture_bytes"),
        "config_sha256": capture.get("provenance", {}).get("config_sha256"),
        "cue_sha256": capture.get("provenance", {}).get("cue_sha256"),
        "cue_read_only": capture.get("provenance", {}).get("cue_read_only"),
        "staging_revision": capture.get("provenance", {}).get("staging_revision"),
        "source_sha256": capture.get("provenance", {}).get("instrumentation_core_sha256", capture.get("provenance", {}).get("instrumentation_source_sha256")),
        "binary_sha256": capture.get("provenance", {}).get("binary_sha256"),
        "trace_sha256": trace_hash,
        "code_rebase": f"0x{base:08X}",
        "guard": {k: guard.get(k) for k in ("cause", "exit_reason", "duration_s", "sandbox_verified", "sandbox_capacity", "host_free_before", "host_free_after", "limits")},
        "w3_177_dispatch": _registers(dispatch[0]),
        "w3_177_handler": _registers(handler[0]),
        "w3_193_initial_step": {k: initial[0].get(k) for k in ("sequence", "process_psp", "before_runtime", "before_link_va", "after_runtime", "after_link_va", "target_runtime", "normal_core_return")},
        "w3_198_step_ordinals": [row.get("ordinal") for row in steps],
        "w3_198_last_step": ({k: steps[-1].get(k) for k in ("sequence", "ordinal", "before_link_va", "after_link_va", "before_runtime", "after_runtime")} if steps else None),
        "w3_198_stop": ({k: stops[0].get(k) for k in ("sequence", "reason", "link_va", "runtime_eip", "steps")} if stops else None),
        "target_hit_seen": bool(_select(rows, "w3_291_ecd40_target_hit")),
        "later_callee_seen": bool(_select(rows, "w3_289_smacker_callee_entry")),
        "backend_present": [{k: row.get(k) for k in ("renderer_active", "present_method_returned", "post_present_pixels", "frame_hash", "vga")} for row in _select(rows, "backend_present_return")],
        "probe_opt_ins_in_runner": toggles,
        "probe_event_counts": {event: counts[event] for event in ("w3_278_branch_target", "w3_285_smacker_direct_entry", "w3_289_smacker_callee_entry", "w3_291_ecd40_target_hit")},
    }


def reconcile(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    identity_keys = ("target_sha256", "fixture_bytes", "config_sha256", "cue_sha256", "cue_read_only", "staging_revision", "code_rebase")
    identical = {key: left.get(key) == right.get(key) for key in identity_keys}
    register_keys = ("link_va", "eip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags", "cs", "ds", "es", "ss")
    equal_at = {}
    for name in ("w3_177_dispatch", "w3_177_handler"):
        a, b = left[name], right[name]
        equal_at[name] = {key: a.get(key) == b.get(key) for key in register_keys}
    x, y = left["w3_193_initial_step"], right["w3_193_initial_step"]
    return {
        "same_fixture_identity_fields": identical,
        "same_staging_revision_and_main_mapping": identical["staging_revision"] and identical["code_rebase"],
        "source_sha256_equal": left["source_sha256"] == right["source_sha256"],
        "binary_sha256_equal": left["binary_sha256"] == right["binary_sha256"],
        "measured_w3_177_register_equality": equal_at,
        "elapsed_ms_comparable": False,
        "elapsed_ms_note": "Different guarded runs/builds and probe opt-ins; equal measured registers do not make timings or full seeds equivalent.",
        "w3_289_initial_step": {"before_link_va": f"0x{int(x['before_link_va']):08X}", "after_link_va": f"0x{int(x['after_link_va']):08X}", "continuation_ordinals": left["w3_198_step_ordinals"]},
        "w3_291_initial_step": {"before_link_va": f"0x{int(y['before_link_va']):08X}", "after_link_va": f"0x{int(y['after_link_va']):08X}", "stop": right["w3_198_stop"], "continuation_ordinals": right["w3_198_step_ordinals"]},
        "first_observed_boundary_difference": "W3-193 before_link_va differs: W3-289 ECD2B -> ECD31 (continuation armed and 5 steps through ECD40); W3-291 ECD31 -> ECD34 (stop initial_step_did_not_reach_measured_successor, steps=0).",
        "runner_opt_in_difference": {k: {"W3-289": left["probe_opt_ins_in_runner"][k], "W3-291": right["probe_opt_ins_in_runner"][k]} for k in left["probe_opt_ins_in_runner"]},
        "optional_probe_events_before_w3_193": {
            "W3-289": left["probe_event_counts"],
            "W3-291": right["probe_event_counts"],
            "interpretation": "The optional branches/callee probes have zero emitted events in the W3-289 trace. This does not prove that the different compiled source/binary or dormant probe checks caused the changed W3-193 start address.",
        },
        "causal_attribution": "UNKNOWN",
        "same_run_or_same_seed_claim": False,
        "framebuffer_verified": False,
        "later_callee_verified": False,
        "next_capture_boundary": "At the W3-193 cache-span step entry, before CPU_Cycles is changed, record one bounded state row: fresh MAIN rebase, PSP, CS:EIP/link VA/ip_point, candidate_link_va, block page start/end, CPU_Cycles, GPR/EFLAGS, and a small instruction-byte sample. Compare this boundary across any future run only with matching build, runner environment, fixture, and explicit seed fingerprint.",
    }


def build_audit() -> dict[str, Any]:
    summaries = {}
    for name, paths in RUNS.items():
        capture = json.loads(paths["capture"].read_text(encoding="utf-8"))
        guard = json.loads(paths["guard"].read_text(encoding="utf-8"))
        raw = paths["trace"].read_bytes()
        runner = paths["runner"].read_text(encoding="utf-8")
        summaries[name] = summarize_run(name, capture, guard, raw, runner)
    return {
        "schema": "w3-292-ecd40-run-reconciliation/v1",
        "task": "W3-292",
        "evidence_level": "ORIGINAL_OBSERVED",
        "analysis_mode": "offline only; no Oracle, DOSBox, or build",
        "runs": summaries,
        "reconciliation": reconcile(summaries["W3-289"], summaries["W3-291"]),
    }


def write_outputs(result: dict[str, Any]) -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    r = result["reconciliation"]
    a, b = result["runs"]["W3-289"], result["runs"]["W3-291"]
    same = r["same_fixture_identity_fields"]
    identity_ok = all(same.values())
    dispatch_equal = all(r["measured_w3_177_register_equality"]["w3_177_dispatch"].values())
    handler_equal = all(r["measured_w3_177_register_equality"]["w3_177_handler"].values())
    lines = [
        "# W3-292 — Offline W3-289/W3-291 ECD40 reconciliation", "",
        "Conclusion: **first observed W3-193 boundary differs; cause remains UNKNOWN**. This task did not replay or build.", "",
        f"- Fixture/config/CUE/revision/mapping identity fields all match: `{identity_ok}` (`{same}`).",
        f"- Instrumentation source hashes equal: `{r['source_sha256_equal']}`; binary hashes equal: `{r['binary_sha256_equal']}`.",
        f"- W3-177 dispatch register fields equal: `{dispatch_equal}`; handler-entry register fields equal: `{handler_equal}`. Timings are not comparable: W3-289 {a['w3_177_handler']['elapsed_ms']} ms, W3-291 {b['w3_177_handler']['elapsed_ms']} ms.",
        f"- W3-289 W3-193: `{r['w3_289_initial_step']}`.",
        f"- W3-291 W3-193: `{r['w3_291_initial_step']}`.",
        f"- Runner opt-ins differ: `{r['runner_opt_in_difference']}`. Optional event counts are `{r['optional_probe_events_before_w3_193']}`.",
        "- These are separate replays and distinct instrumented binaries; equal sampled registers at W3-177 do not establish same seed or same full state. No causality is assigned to dormant probes or the instrumentation build.",
        "- Neither run has pixel-backed framebuffer data or a verified later Smacker callee.",
        "", f"Next bounded boundary: {r['next_capture_boundary']}", "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    result = build_audit()
    write_outputs(result)
    print(json.dumps({"evidence": str(OUTPUT), "report": str(REPORT), "causal_attribution": result["reconciliation"]["causal_attribution"], "identity_match": all(result["reconciliation"]["same_fixture_identity_fields"].values())}))
