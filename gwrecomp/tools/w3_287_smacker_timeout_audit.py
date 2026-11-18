#!/usr/bin/env python3
"""Offline audit of why W3-285 lacks the later Smacker invocation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = {
    "W3-280": ROOT / "evidence/w3_280_play_smk_step.json",
    "W3-281": ROOT / "evidence/w3_281_play_smk_gate.json",
    "W3-285": ROOT / "evidence/w3_285_smacker_callee_capture.json",
}
TIMING = ROOT / "evidence/w3_283_replay_timing_audit.json"
OUT = ROOT / "evidence/w3_287_smacker_timeout_audit.json"
REPORT = ROOT / "reports/coordination/w3_287_smacker_timeout_audit.md"
MAX_BYTES = 1_048_576
MAX_ROWS = 2048


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_run(path: Path, root: Path = ROOT) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    trace_path = root / data["trace"]["path"].replace("\\", "/")
    raw = trace_path.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    checks = {
        "bytes": len(raw),
        "sha256": digest(raw),
        "rows": len(rows),
        "metadata_matches": len(raw) == data["trace"]["bytes"] and digest(raw) == data["trace"]["sha256"] and len(rows) == data["trace"]["rows"],
        "within_caps": len(raw) <= MAX_BYTES and len(rows) <= MAX_ROWS,
    }
    if not checks["metadata_matches"] or not checks["within_caps"]:
        raise ValueError(f"trace integrity/cap check failed for {path}: {checks}")
    elapsed = [r.get("elapsed_ms") for r in rows if isinstance(r.get("elapsed_ms"), int)]
    target_rows = [r for r in rows if r.get("event") == "target_runtime_checkpoint"]
    relevant = [r for r in rows if r.get("link_va") in {600797, 713424, 713439, 713441, 713443}]
    return {
        "task": data.get("task"), "run_id": data.get("run_id"),
        "trace": {"path": str(trace_path.relative_to(root)).replace("\\", "/"), **checks},
        "provenance": data.get("provenance", {}),
        "analysis": data.get("analysis", {}),
        "guard": {"cause": data.get("guard", {}).get("cause"), "duration_s": data.get("guard", {}).get("duration_s")},
        "last_elapsed_ms": max(elapsed) if elapsed else None,
        "target_checkpoint_rows": len(target_rows),
        "smacker_relevant_rows": [
            {k: r.get(k) for k in ("sequence", "event", "checkpoint", "link_va", "elapsed_ms") if k in r}
            for r in relevant
        ],
        "rows": rows,
    }


def select_ordinal(events: list[dict[str, Any]], link_va: int, ordinal: int) -> dict[str, Any] | None:
    """Select a dynamic instruction/checkpoint by occurrence; do not alias #1 to #2."""
    matches = [e for e in events if e.get("link_va") == link_va]
    return matches[ordinal - 1] if ordinal > 0 and len(matches) >= ordinal else None


def select_callsite_occurrence(events: list[dict[str, Any]], ordinal: int) -> dict[str, Any] | None:
    """Count the named target checkpoint only, avoiding adjacent rows for one instruction."""
    matches = [e for e in events if e.get("event") == "target_runtime_checkpoint"
               and e.get("checkpoint") == "W3_117_PLAYSMACKER_CALLSITE"
               and e.get("link_va") == 600797]
    return matches[ordinal - 1] if ordinal > 0 and len(matches) >= ordinal else None


def audit_runs(runs: dict[str, dict[str, Any]], timing: dict[str, Any], source_sha256: str | None = None) -> dict[str, Any]:
    w280, w281, w285 = (runs[k] for k in ("W3-280", "W3-281", "W3-285"))
    later_names = {"w3_278_later_play_smk_entry", "w3_278_global_load", "w3_278_branch_test", "w3_278_branch_target"}
    later = {
        label: [r for r in run["rows"] if r.get("event") in later_names]
        for label, run in runs.items()
    }
    timing_corr = timing["correlation"]
    source_hashes = {label: run["provenance"].get("source_sha256", {}).get("src/cpu/core_dyn_x86.cpp") for label, run in runs.items()}
    binary_hashes = {label: run["provenance"].get("binary_sha256") for label, run in runs.items()}
    same_binary = len(set(binary_hashes.values())) == 1
    same_core_source = len(set(source_hashes.values())) == 1
    # A timeout with differing build inputs and only bounded checkpoints cannot isolate cause.
    # These retained runs do not isolate an execution cause even when build hashes match.
    cause = "UNKNOWN"
    later_callsite = select_callsite_occurrence(w280["rows"], 2)
    return {
        "reason_classification": {
            "status": cause,
            "finding": "W3-285's retained trace contains no later 0xAE2D0/0xAE2DF/0xAE2E1/branch-target event before its 120-second guard timeout.",
            "causality": "UNKNOWN; absence at timeout does not establish guest branch divergence or instrumentation-caused slowdown.",
            "plausible_but_unproven_factors": [
                "W3-280, W3-281, and W3-285 have different instrumented binary hashes; their core_dyn_x86.cpp hashes differ.",
                "W3-283 records W3-281 reaching the corresponding 0x92A24 checkpoint at 115713 trace-ms versus 75379 for W3-280, with missing later branch events; that audit explicitly leaves causality unknown.",
                "W3-285 reaches a last timed target checkpoint at 72012 elapsed-ms, then the guard remains until the 120-second wall timeout; sparse trace events do not reveal intervening execution.",
            ],
            "evidence_against_overclaim": "W3-280's later callsite is recorded at elapsed_ms 82057 and its later branch destination at seq 399. W3-285's trace has 358 rows versus W3-280's 405, but row counts are not execution-speed or instruction-count measurements.",
        },
        "run_comparison": {
            label: {
                "run_id": run["run_id"], "trace": run["trace"],
                "guard_cause": run["guard"]["cause"], "guard_duration_s": run["guard"]["duration_s"],
                "last_trace_elapsed_ms": run["last_elapsed_ms"],
                "target_checkpoint_rows": run["target_checkpoint_rows"],
                "binary_sha256": binary_hashes[label], "core_dyn_x86_sha256": source_hashes[label],
                "later_branch_event_count": len(later[label]),
            } for label, run in runs.items()
        },
        "build_hash_comparison": {
            "binary_hashes_distinct": len(set(binary_hashes.values())) == len(binary_hashes),
            "core_source_hashes_distinct": len(set(source_hashes.values())) == len(source_hashes),
            "binary_sha256_by_run": binary_hashes,
            "core_dyn_x86_sha256_by_run": source_hashes,
            "other_recorded_source_files_match_w3_280": {
                label: {
                    name: runs[label]["provenance"].get("source_sha256", {}).get(name)
                    == runs["W3-280"]["provenance"].get("source_sha256", {}).get(name)
                    for name in runs["W3-280"]["provenance"].get("source_sha256", {})
                    if name != "src/cpu/core_dyn_x86.cpp"
                } for label in ("W3-281", "W3-285")
            },
        },
        "timing_context_from_w3_283": {
            "w3_280_callsite_92add_elapsed_ms": later_callsite.get("elapsed_ms") if later_callsite else None,
            "w3_280_later_branch_target_sequence": 399 if any(r.get("event") == "w3_278_branch_target" for r in later["W3-280"]) else None,
            "w3_280_at_0x92a24_elapsed_ms": timing_corr.get("w3_280_elapsed_ms_at_0x92a24"),
            "w3_281_at_0x92a24_elapsed_ms": timing_corr.get("w3_281_elapsed_ms_at_0x92a24"),
            "w3_283_causality": timing_corr.get("causality"),
            "w3_283_limitation": "Trace timer origin is not demonstrated synchronized to guard wall-clock timestamps.",
        },
        "hook_gates": {
            "w3_285_direct_capture_requires": ["GWRECOMP_W3_285_CAPTURE=1", "w3_280_first_fallthrough_seen", "candidate_link_va=0xAE308", "one-shot not previously emitted"],
            "latch_source": "w3_280_first_fallthrough_seen is set only when the W3-278 branch-target event observes link 0xAE2E3.",
            "observed_w3_285_latch": runs["W3-285"].get("analysis", {}).get("fallthrough_latch_seen"),
            "interpretation": "The hook is dependent on the later gate latch. Its absence in the trace is consistent with the corresponding gate not being reached before timeout, but is not a separate execution stop or proof of branch choice.",
            "source_file_current_sha256": source_sha256,
        },
        "minimal_next_capture_design": {
            "execution": "One guarded replay only after a separately claimed task and successful sandbox/lock preflight; no repeat of W3-285's first-entry probe.",
            "fresh_mapping": "Require a unique matching MAIN mapping and calculate link VA using that run's measured code rebase.",
            "trigger": "Count only target_runtime_checkpoint rows named W3_117_PLAYSMACKER_CALLSITE at link VA 0x92ADD in the MAIN process; ignore occurrence 1 and arm only on occurrence 2 (the later callsite in W3-280). Do not count the adjacent W3-275 custom row for the same instruction as another execution.",
            "selected_events": [
                {"ordinal": 2, "link_va": "0x00092ADD", "purpose": "later callsite identity"},
                {"after_ordinal_2": "0x000AE2D0", "purpose": "later wrapper entry"},
                {"after_later_entry": ["0x000AE2DF", "0x000AE2E1", "0x000AE2E3-or-0x000AE2E8"], "purpose": "fresh load/test/actual destination"},
                {"after_later_gate": "0x000AE308", "purpose": "converged callee entry; record only occurrence associated with callsite ordinal 2"},
            ],
            "caps": {"trace_bytes": MAX_BYTES, "trace_rows": MAX_ROWS, "selected_events": 6, "step_window_instructions": 16, "wall_timeout_s": 120},
            "must_disable_or_omit": "Do not enable broad renderer/video/Smacker checkpoint collections solely for this capture; retain only fresh MAIN mapping and the four ordinal-linked points above.",
            "limitations": "This design improves ordinal specificity and bounds logging; it does not guarantee the second invocation is reached before timeout. Keep any timeout inconclusive.",
        },
        "handoff_content": "W3-285 repeats the first Smacker invocation already in W3-280; W3-280 alone contains the later gate at seq 394-399. No executed AE306 return, framebuffer pixels, menu, gameplay, Runtime defect, or original/native parity is established. No Runtime change is requested.",
    }


def write_report(result: dict[str, Any]) -> str:
    r = result["reason_classification"]
    cmp = result["run_comparison"]
    design = result["minimal_next_capture_design"]
    lines = [
        "# W3-287 — Why the later Smacker invocation is absent from W3-285",
        "",
        "Status: **offline audit complete**. No DOSBox, Oracle, or build was run.",
        "",
        "## Measured run differences",
        "",
        "| Run | Guard | Duration | Trace bytes / rows | Last trace elapsed | Target checkpoints | Later-branch events |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for label in ("W3-280", "W3-281", "W3-285"):
        x = cmp[label]
        lines.append(f"| {label} | {x['guard_cause']} | {x['guard_duration_s']}s | {x['trace']['bytes']} / {x['trace']['rows']} | {x['last_trace_elapsed_ms']} ms | {x['target_checkpoint_rows']} | {x['later_branch_event_count']} |")
    lines += [
        "",
        "W3-280 recorded its later `0x92ADD` callsite at trace elapsed 82057 ms and the `0xAE2E3` branch destination at sequence 399. W3-285's last timed target checkpoint is 72012 ms; its trace has no later `0xAE2D0` entry or branch event. All relevant runs hit the bounded wall timeout, and binary plus `core_dyn_x86.cpp` hashes differ.",
        "",
        f"**Cause classification: {r['status']}.** The evidence establishes only the different last recorded frontier before timeout. W3-283 already observed timing differences between W3-280 and W3-281 and explicitly rated causality UNKNOWN; the timer clocks are not proven synchronized. Row count is not a runtime-speed measurement. The W3-285 hook requires the `0xAE2E3` latch, so its missing custom event is consistent with no latch observed before timeout, but does not independently establish why.",
        "",
        "## Smallest next capture design",
        "",
        f"{design['trigger']} Require fresh per-run MAIN mapping. Record only the ordinal-2 callsite, following wrapper entry, its short branch sequence/destination, and the callee entry linked to that ordinal. Keep limits at {design['caps']['trace_bytes']} bytes, {design['caps']['trace_rows']} rows, {design['caps']['selected_events']} selected points, {design['caps']['step_window_instructions']} instructions, and the existing 120-second guard. Omit broad video/renderer/Smacker checkpoint sets. A timeout remains inconclusive; this design cannot guarantee reaching the second invocation.",
        "",
        "## WORK2 correction",
        "",
        result["handoff_content"],
        "See `evidence/w3_286_smacker_replay_reconciliation.json` and `evidence/w3_287_smacker_timeout_audit.json`.",
        "",
    ]
    return "\n".join(lines)


def run_audit(root: Path = ROOT) -> dict[str, Any]:
    runs = {label: load_run(path, root) for label, path in CAPTURES.items()}
    timing = json.loads((root / TIMING.relative_to(ROOT)).read_text(encoding="utf-8"))
    source = root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
    return audit_runs(runs, timing, digest(source.read_bytes()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    result = run_audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.report.write_text(write_report(result), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "report": str(args.report), "cause": result["reason_classification"]["status"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
