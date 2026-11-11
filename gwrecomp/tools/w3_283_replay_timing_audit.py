"""Offline audit of the bounded W3-280/W3-281 replay traces and guard logs."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DISPLAY_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \| DISPLAY: (.*)$")
VESA_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \| DISPLAY: VESA (.*)$")
SB_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \| ENVELOPE: SB done (.*)$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")


def extract_log_events(stderr_tail: str) -> dict[str, Any]:
    lines = stderr_tail.splitlines()
    display = next((DISPLAY_RE.match(line) for line in lines if DISPLAY_RE.match(line)), None)
    vesas = [VESA_RE.match(line) for line in lines]
    vesas = [m for m in vesas if m]
    sb = [SB_RE.match(line) for line in lines]
    sb = [m for m in sb if m]
    if display is None:
        raise ValueError("guard stderr tail has no initial DISPLAY timestamp")
    origin = parse_timestamp(display.group(1))

    def event(match: re.Match[str]) -> dict[str, Any]:
        timestamp = parse_timestamp(match.group(1))
        return {
            "timestamp_local": match.group(1),
            "seconds_after_initial_display": round((timestamp - origin).total_seconds(), 3),
            "message": match.group(2),
        }

    return {
        "initial_display": event(display),
        "vesa_modes": [event(m) for m in vesas],
        "sound_blaster_envelope_done": [event(m) for m in sb],
        "clock_basis": "timestamps copied from bounded guard stderr_tail; relative intervals use the first DISPLAY line in that same tail",
    }


def read_trace(path: Path, expected_sha256: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = path.read_bytes()
    digest = sha256(raw)
    if digest != expected_sha256:
        raise ValueError(f"trace SHA-256 mismatch for {path}: {digest}")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    try:
        display_path = str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        display_path = str(path)
    return rows, {"path": display_path, "bytes": len(raw), "sha256": digest, "rows": len(rows)}


def select_trace_events(rows: list[dict[str, Any]]) -> dict[str, Any]:
    wanted = {
        "w3_269_game_transition_checkpoint",
        "w3_275_second_smacker_entry",
        "w3_275_second_smacker_callsite",
        "target_runtime_checkpoint",
        "w3_275_second_smacker_media_entry",
        "w3_278_later_play_smk_entry",
        "w3_278_global_load",
        "w3_278_branch_test",
        "w3_278_branch_target",
    }
    result = []
    for row in rows:
        if row.get("event") not in wanted:
            continue
        link = row.get("link_va")
        if link not in {600470, 600528, 598064, 600598, 600612, 600797, 713424, 713439, 713441, 713443}:
            continue
        item = {k: row.get(k) for k in ("sequence", "event", "link_va", "elapsed_ms", "runtime_eip") if k in row}
        result.append(item)
    return {"selected_events": result}


def branch_sequence_consistency(events: list[dict[str, Any]], expected: dict[str, int]) -> bool:
    actual = {row["event"]: row["sequence"] for row in events if row.get("event") in expected}
    return actual == expected


def causality_from_correlation(*_measurements: Any) -> str:
    """Correlation-only inputs never prove a cause in this audit."""
    return "UNKNOWN"


def audit(root: Path = ROOT) -> dict[str, Any]:
    inputs = {
        "W3-280": {
            "capture": root / "evidence/w3_280_play_smk_step.json",
            "guard": root / "evidence/oracle_runs/oracle_runs_w3-280-normal-core-smk-step-20261010-01.json",
        },
        "W3-281": {
            "capture": root / "evidence/w3_281_play_smk_gate.json",
            "guard": root / "evidence/oracle_runs/oracle_runs_w3-281-second-smk-gate-20261010-01.json",
        },
    }
    runs: dict[str, Any] = {}
    for task, paths in inputs.items():
        capture = json.loads(paths["capture"].read_text(encoding="utf-8"))
        guard = json.loads(paths["guard"].read_text(encoding="utf-8"))
        trace_path = root / capture["trace"]["path"]
        rows, trace_meta = read_trace(trace_path, capture["trace"]["sha256"])
        if len(rows) != capture["trace"]["rows"]:
            raise ValueError(f"trace row-count mismatch for {task}")
        log_events = extract_log_events(guard["stderr_tail"])
        selected = select_trace_events(rows)
        branch_expected = {
            "w3_278_later_play_smk_entry": capture.get("analysis", {}).get("selected_sequences", {}).get("w3_278_later_play_smk_entry"),
            "w3_278_global_load": capture.get("analysis", {}).get("selected_sequences", {}).get("w3_278_global_load"),
            "w3_278_branch_test": capture.get("analysis", {}).get("selected_sequences", {}).get("w3_278_branch_test"),
            "w3_278_branch_target": capture.get("analysis", {}).get("selected_sequences", {}).get("branch_destination"),
        } if task == "W3-280" else {}
        branch_expected = {k: v for k, v in branch_expected.items() if v is not None}
        runs[task] = {
            "run_id": capture["run_id"],
            "capture_evidence": str(paths["capture"].relative_to(root)).replace("\\", "/"),
            "guard_evidence": str(paths["guard"].relative_to(root)).replace("\\", "/"),
            "start_time_utc": guard["start_time"],
            "duration_s": guard["duration_s"],
            "guard_cause": guard["cause"],
            "trace": trace_meta,
            **selected,
            "sequence_audit": {
                "step_event_sequences": {k: next((x["sequence"] for x in selected["selected_events"] if x["event"] == k), None) for k in (
                    "w3_278_later_play_smk_entry", "w3_278_global_load", "w3_278_branch_test", "w3_278_branch_target"
                )},
                "guard_sequence_matches_trace": branch_sequence_consistency(selected["selected_events"], branch_expected) if task == "W3-280" else None,
            },
            "display_log_timing": log_events,
        }

    first, second = runs["W3-280"], runs["W3-281"]
    event_a = first["display_log_timing"]["vesa_modes"]
    event_b = second["display_log_timing"]["vesa_modes"]
    trace_last_a = next((x for x in first["selected_events"] if x.get("link_va") == 600612 and x.get("elapsed_ms") is not None), None)
    trace_last_b = next((x for x in second["selected_events"] if x.get("link_va") == 600612 and x.get("elapsed_ms") is not None), None)

    report = (root / "reports/coordination/w3_280_play_smk_step.md").read_text(encoding="utf-8")
    report_values = [int(x) for x in re.findall(r"^\|\s*(\d+)\s*\|", report, re.MULTILINE)]
    expected_branch_sequences = [396, 397, 398, 399]
    table_matches_trace = report_values[-4:] == expected_branch_sequences and first["sequence_audit"]["step_event_sequences"] == {
        "w3_278_later_play_smk_entry": 396,
        "w3_278_global_load": 397,
        "w3_278_branch_test": 398,
        "w3_278_branch_target": 399,
    }
    first_display_a = event_a[0]["seconds_after_initial_display"] if event_a else None
    first_display_b = event_b[0]["seconds_after_initial_display"] if event_b else None
    second_display_a = event_a[1]["seconds_after_initial_display"] if len(event_a) > 1 else None
    second_display_b = event_b[1]["seconds_after_initial_display"] if len(event_b) > 1 else None

    return {
        "schema": "w3-283-replay-timing-audit/v1",
        "task": "W3-283",
        "evidence_level": "ORIGINAL_OBSERVED_COMPARISON",
        "runs": runs,
        "sequence_report_audit": {
            "report": "reports/coordination/w3_280_play_smk_step.md",
            "trace": first["trace"],
            "reported_branch_sequences": report_values[-4:],
            "trace_branch_sequences": expected_branch_sequences,
            "matches": table_matches_trace,
            "clarification": "The trace contains two distinct records at link VA 0xAE2D0: W3-275 media-entry sequence 395, then W3-278 branch-hook entry sequence 396. The report table describes the latter; its 396-399 numbering is correct. The report was clarified to distinguish these records; no source trace or structured capture fact was changed.",
        },
        "correlation": {
            "w3_280_first_vesa_seconds_after_initial_display": first_display_a,
            "w3_281_first_vesa_seconds_after_initial_display": first_display_b,
            "w3_280_second_vesa_seconds_after_initial_display": second_display_a,
            "w3_281_second_vesa_seconds_after_initial_display": second_display_b,
            "w3_280_elapsed_ms_at_0x92a24": trace_last_a.get("elapsed_ms") if trace_last_a else None,
            "w3_281_elapsed_ms_at_0x92a24": trace_last_b.get("elapsed_ms") if trace_last_b else None,
            "w3_280_guard_duration_s": first["duration_s"],
            "w3_281_guard_duration_s": second["duration_s"],
            "interpretation": "Measured wall-clock and trace-timer differences are correlated with the missing later checkpoint in W3-281. This comparison does not establish causality; binary/source hashes differ and the trace elapsed timer is not proven synchronized to the log clock.",
            "causality": causality_from_correlation(first_display_a, first_display_b, second_display_a, second_display_b),
        },
        "limits": [
            "Offline-only audit; no DOSBox, Oracle, replay, or build was run.",
            "Guard display/audio timestamps come from bounded stderr_tail text; relative times use the first DISPLAY line within that same log.",
            "The emulator trace elapsed_ms origin is not shown to be synchronized with wall-clock log timestamps.",
            "W3-281's missing later event is not proof of a different guest branch.",
            "W3-280/W3-281 instrumented binary and core-source hashes differ.",
            "No menu, gameplay, or first framebuffer claim is made by this timing audit.",
        ],
    }


def main() -> int:
    result = audit()
    output = ROOT / "evidence/w3_283_replay_timing_audit.json"
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "report_sequence_matches_trace": result["sequence_report_audit"]["matches"], "causality": result["correlation"]["causality"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
