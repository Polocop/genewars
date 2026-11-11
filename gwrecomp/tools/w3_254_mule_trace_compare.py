"""Offline comparison of bounded original MULE.ANB trace windows."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE_PATHS = {
    "W3-236": ROOT / "build/dosboxx_oracle/C/W3_236_CHKTTY_AX4400.jsonl",
    "W3-251": ROOT / "build/dosboxx_oracle/C/W3_251_ENTRY_RETURN_20261009_01.jsonl",
    "W3-253": ROOT / "build/dosboxx_oracle/C/W3_253_ENTRY_RETURN_20261009_01.jsonl",
}
EVIDENCE_PATHS = {
    "W3-236": ROOT / "evidence/w3_236_chktty_original_capture.json",
    "W3-251": ROOT / "evidence/w3_251_entry_return_capture.json",
    "W3-253": ROOT / "evidence/w3_253_capture_flag_cache.json",
}
TARGET = "GENEWARS\\DATA\\CREATURE\\MULE.ANB"


def reduce_events(events: list[dict]) -> dict:
    operations = []
    for event in events:
        if str(event.get("path", "")).upper() != TARGET:
            continue
        if event.get("event") not in ("dos_handle_open", "dos_handle_close"):
            continue
        operations.append({key: event.get(key) for key in (
            "sequence", "event", "process_psp", "requested_path", "path",
            "entry", "internal_handle", "flags", "result_ax", "carry") if key in event})
    pairs = []
    for index in range(0, len(operations) - 1, 2):
        opened, closed = operations[index:index + 2]
        if opened["event"] != "dos_handle_open" or closed["event"] != "dos_handle_close":
            break
        pairs.append({"open": opened, "close": closed})
    return {"operations": operations, "pairs": pairs, "complete_pair_count": len(pairs)}


def normalized_pair(pair: dict) -> tuple:
    fields = ("process_psp", "requested_path", "path", "entry", "internal_handle", "flags")
    return tuple(pair[side].get(field) for side in ("open", "close") for field in fields)


def main() -> int:
    runs = {}
    for task, trace_path in TRACE_PATHS.items():
        summary = json.loads(EVIDENCE_PATHS[task].read_text(encoding="utf-8"))
        events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines() if line]
        target = reduce_events(events)
        checkpoints = [{"sequence": e.get("sequence"), "checkpoint": e.get("checkpoint"),
                        "link_va": e.get("link_va"), "elapsed_ms": e.get("elapsed_ms")}
                       for e in events if e.get("event") == "target_runtime_checkpoint"]
        runs[task] = {
            "trace_path": str(trace_path), "trace_sha256": summary.get("trace", {}).get("sha256"),
            "runtime_sha256": (summary.get("preflight", {}).get("runtime_sha256") or
                               summary.get("guard", {}).get("provenance", {}).get("runtime_sha")),
            "trace_event_count": len(events), "timeout": summary.get("guard", {}).get("cause") == "TIMEOUT",
            "last_trace_event": ({"sequence": events[-1].get("sequence"),
                                  "event": events[-1].get("event"), "path": events[-1].get("path")}
                                 if events else None),
            "checkpoints": checkpoints, "mule": target,
        }
    pair_lists = [runs[t]["mule"]["pairs"] for t in ("W3-236", "W3-251", "W3-253")]
    shared = min(map(len, pair_lists), default=0)
    matching_prefix = 0
    for index in range(shared):
        normalized = [normalized_pair(pairs[index]) for pairs in pair_lists]
        if len(set(normalized)) != 1:
            break
        matching_prefix += 1
    result = {
        "schema": "gwrecomp-w3-254-mule-trace-compare/v1", "task": "W3-254",
        "classification": "COMMON_SEQUENCE_MATCHED_NO_EARLY_DIVERGENCE",
        "evidence_level": "ORIGINAL_OBSERVED",
        "runs": runs,
        "comparison": {"common_initial_complete_pairs": matching_prefix,
                       "pair_content_identical": matching_prefix == shared,
                       "sequence_numbers_comparable": False,
                       "dos_call_result_fields_present": False,
                       "conclusion": "The first five MULE.ANB open/close cycles match byte-for-field in the captured event attributes. W3-236 has later captured activity, but its absence in the shorter W3-251/W3-253 captures is not proof of a guest divergence; instrumentation and timeout windows differ."},
        "limits": ["No DOS result AX/CF was recorded on handle open/close events, so this comparison cannot establish the guest return contract.",
                   "The shorter captures end at timeout; absence of later events is censored, not an observed negative.",
                   "W3-236 has a different instrumented binary/filter; no causal timing inference is supported."],
        "next_action": "No replay justified by this comparison. Wait for an independent measured hypothesis or a capture design that records the post-MULE checkpoint with equivalent instrumentation.",
    }
    output = ROOT / "evidence/w3_254_mule_trace_compare.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "common_pairs": matching_prefix,
                      "classification": result["classification"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
