"""Read-only reconciliation of existing original WScreen samples."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "build/dosboxx_oracle/C/W3_181_SMACKINTERNAL010_PROGRESS_20261009_01.jsonl"
W181 = ROOT / "evidence/w3_181_smackinternal010_progress.json"
W171 = ROOT / "evidence/w3_171_wscreen_frame_boundary.json"
W154 = ROOT / "evidence/w3_154_source_destination_samples.json"
W188 = ROOT / "evidence/w3_188_b_screen_payload.json"
OUTPUT = ROOT / "evidence/w3_189_wscreen_temporal_reconciliation.json"


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _windows(event):
    rows = event["w3_177_sample_windows"]
    if len(rows) != 3 or sum(int(row["bytes"]) for row in rows) != 48:
        raise ValueError("W3-181 sample must contain exactly three 16-byte windows")
    if [int(row["offset"]) for row in rows] != [0, 32000, 63984]:
        raise ValueError("unexpected sample offsets")
    for row in rows:
        payload = bytes.fromhex(row["hex"])
        if len(payload) != 16 or int(row["bytes"]) != len(payload):
            raise ValueError("sample window length mismatch")
    return rows


def analyze(meta, events, w171, w154, w188):
    """Validate bounded provenance and return evidence; no emulator is invoked."""
    if len(events) != int(meta["trace"]["event_count"]):
        raise ValueError("raw JSONL event count does not match W3-181 evidence")
    by_name = {row.get("checkpoint"): row for row in events if row.get("checkpoint")}
    names = (
        "W3_148_SMACKDOFRAME_RETURN",
        "W3_151_COPY_NONVESA_PRE",
        "W3_151_COPY_NONVESA_POST",
        "W3_177_UNSMACK_DISPATCH_FIRST",
        "W3_177_UNSMACK_HANDLER_ENTRY",
        "W3_177_UNSMACK_DISPATCH_REENTRY",
    )
    if any(name not in by_name for name in names):
        raise ValueError("required checkpoint missing in W3-181 raw trace")
    frame, copy_pre, copy_post, first, handler, reentry = (by_name[name] for name in names)
    if not (frame["sequence"] < copy_pre["sequence"] < copy_post["sequence"] <
            first["sequence"] < handler["sequence"] < reentry["sequence"]):
        raise ValueError("W3-181 checkpoint order mismatch")
    if len({row["process_psp"] for row in (frame, copy_pre, copy_post, first, handler, reentry)}) != 1:
        raise ValueError("W3-181 checkpoints do not share one process PSP")
    if int(meta["psp"]) != int(first["process_psp"]):
        raise ValueError("W3-181 process identity mismatch")
    if int(first["link_va"]) != 0xEDE94 or int(reentry["link_va"]) != 0xEDE94:
        raise ValueError("dispatch checkpoints do not resolve to verified target")
    pointer = int(first["w3_177_wscreen_pointer"])
    if pointer != int(reentry["w3_177_wscreen_pointer"]) or not first["w3_177_wscreen_pointer_valid"] or not reentry["w3_177_wscreen_pointer_valid"]:
        raise ValueError("WScreen pointer not valid and stable across dispatch")
    if pointer != 0x394920:
        raise ValueError("unexpected measured WScreen pointer")
    for row in (first, reentry):
        if not (row["ds_descriptor_valid"] and row["ds_base"] == 0 and
                row["ds_limit"] >= pointer + 63984 + 16 and
                row["w3_177_sample_bounds_valid"] and row["w3_177_sample_valid"] and
                row["w3_177_sample_bytes"] == 48):
            raise ValueError("WScreen sample bounds/descriptor validation failed")
    first_windows, reentry_windows = _windows(first), _windows(reentry)
    diffs = []
    for a, b in zip(first_windows, reentry_windows):
        if a["hex"].lower() != b["hex"].lower():
            diffs.append({"offset": int(a["offset"]), "before_hex": a["hex"], "after_hex": b["hex"]})
    if int(w171["mapping"]["psp"]) != int(meta["psp"]):
        raise ValueError("W3-171 identity must be recorded separately; PSP mismatch is unexpected here")
    if w171["run_id"] == meta["run_id"] or w154["run_id"] == meta["run_id"]:
        raise ValueError("separate runs must not be merged with W3-181")
    if any(bytes.fromhex(row["hex"]) != bytes(16) for row in w171["samples"]["smackdoframe_return"]["w3_171_sample_windows"]):
        raise ValueError("expected W3-171 sparse zero samples changed")
    if any(bytes.fromhex(row["source_hex"]) != bytes(16) for row in w154["source_destination_samples"]["windows"]):
        raise ValueError("expected W3-154 sparse source samples changed")
    bscreen = int(w188["pointer"], 16)
    if bscreen == pointer or int(w188["sample_bytes"]) != 64:
        raise ValueError("W3-188 B_SCREEN sample must remain a distinct bounded object")
    return {
        "schema": "w3-189-wscreen-temporal-reconciliation/v1",
        "task": "W3-189",
        "classification": "ORIGINAL_OBSERVED_BOUNDED_SPARSE_WSCREEN_CHANGE",
        "provenance": {
            "target_sha256": meta["source"]["target_sha256"],
            "config_sha256": meta["source"]["config_sha256"],
            "cue_sha256": meta["source"]["cue_sha256"],
            "staging_revision": meta["source"]["staging_revision"],
            "instrumented_staging_sha256": meta["source"]["staging_binary_sha256"],
            "run_id": meta["run_id"],
            "trace_path": meta["trace"]["path"],
            "trace_bytes": meta["trace"]["bytes"],
            "trace_sha256": meta["trace"]["sha256"],
            "trace_events": len(events),
            "same_run_psp": int(meta["psp"]),
            "code_rebase": meta["code_rebase"],
            "data_rebase": meta["data_rebase"],
        },
        "w3_181_same_run": {
            "sequence_order": {name: int(by_name[name]["sequence"]) for name in names},
            "dispatcher_link_va": "0x000EDE94",
            "handler_link_va": "0x000ECCF0",
            "wscreen_pointer": hex(pointer),
            "descriptor_checks": "DS valid, base 0, limit covers all three samples; pointer and physical sample bounds passed in both events",
            "sample_bytes_per_event": 48,
            "first_dispatch": first_windows,
            "dispatcher_reentry": reentry_windows,
            "changed_windows": diffs,
            "timeline_note": "The trace has SmackDoFrame return and copy pre/post checkpoints before dispatch, but W3-181 did not sample WScreen bytes at those earlier checkpoints.",
        },
        "separate_run_comparison": {
            "w3_171_run_id": w171["run_id"],
            "w3_171_sampled_point": "SmackDoFrame return and copy pre; all sampled WScreen windows were zero in that distinct run",
            "w3_154_run_id": w154["run_id"],
            "w3_154_sampled_point": "copy completion; all three sampled source windows were zero in that distinct run",
            "not_merged": True,
        },
        "separate_object": {
            "w3_188_b_screen_pointer": hex(bscreen),
            "w3_188_sample_bytes": int(w188["sample_bytes"]),
            "w3_188_nonzero_bytes": int(w188["nonzero_bytes"]),
            "relationship": "B_SCREEN allocation pointer differs from WScreen; its zero prefix is not a WScreen observation.",
        },
        "interpretation": {
            "measured": "At the same original WScreen pointer, sampled offset 32000 was nonzero at the first dispatcher checkpoint and had different nonzero bytes at dispatcher re-entry; offset 63984 changed from nonzero to zero; offset 0 remained zero.",
            "not_established": ["pixel format", "full-buffer contents", "decoded-frame semantics", "VGA presentation", "visible framebuffer", "menu or gameplay"],
        },
        "next_action": "WORK2 can compare the native WScreen buffer at the equivalent pre-dispatch and dispatcher-reentry checkpoints. Keep the comparison sparse and use the measured native pointer/mapping; do not claim visible presentation from these bytes.",
    }


def build():
    raw = TRACE.read_bytes()
    meta = _read(W181)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != meta["trace"]["sha256"] or len(raw) != int(meta["trace"]["bytes"]):
        raise ValueError("W3-181 raw trace provenance mismatch")
    events = [json.loads(line) for line in raw.splitlines()]
    result = analyze(meta, events, _read(W171), _read(W154), _read(W188))
    return result


def main():
    result = build()
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"classification": result["classification"], "trace_sha256": result["provenance"]["trace_sha256"], "changed_windows": result["w3_181_same_run"]["changed_windows"], "output": str(OUTPUT)}, indent=2))


if __name__ == "__main__":
    main()
