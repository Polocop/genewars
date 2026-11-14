from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

MAX_BYTES = 1024 * 1024
MAX_ROWS = 2048
COMMON_LINKS = {0x92030, 0x92A16, 0x92A24, 0x92ADD}
GPRS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")


def read_trace(path: Path, expected_bytes: int, expected_rows: int,
               expected_sha256: str) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES or len(raw) != expected_bytes:
        raise ValueError("trace byte limit or manifest size mismatch")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("trace hash mismatch")
    lines = raw.splitlines()
    if len(lines) > MAX_ROWS or len(lines) != expected_rows:
        raise ValueError("trace row limit or manifest count mismatch")
    rows = [json.loads(line) for line in lines]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("trace contains non-object JSON")
    return rows


def _after_second_entry(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries = [row for row in rows if row.get("event") == "w3_275_second_smacker_entry"]
    if len(entries) != 1:
        raise ValueError("expected exactly one measured 0x929D0 entry")
    start = int(entries[0]["sequence"])
    selected = []
    for row in rows:
        sequence = int(row.get("sequence", -1))
        link = int(row.get("link_va", -1))
        event = row.get("event")
        if sequence <= start:
            continue
        if (event == "target_runtime_checkpoint" and link in COMMON_LINKS) or (
            event in {"w3_275_second_smacker_callsite", "w3_275_second_smacker_media_entry",
                      "w3_278_later_play_smk_entry"}
        ):
            selected.append(row)
    return selected


def compare_runs(manifest_a: dict[str, Any], rows_a: list[dict[str, Any]],
                 manifest_b: dict[str, Any], rows_b: list[dict[str, Any]]) -> dict[str, Any]:
    prov_a, prov_b = manifest_a["provenance"], manifest_b["provenance"]
    identity_fields = ("target_sha256", "fixture_bytes", "config_sha256", "cue_sha256",
                       "cue_read_only", "staging_revision")
    identity = {field: prov_a.get(field) == prov_b.get(field) for field in identity_fields}
    if not all(identity.values()):
        raise ValueError("original fixture/config/CUE/source identity differs")
    map_a = [row for row in rows_a if row.get("event") == "main_mapping"]
    map_b = [row for row in rows_b if row.get("event") == "main_mapping"]
    if (len(map_a) != 1 or len(map_b) != 1 or
        map_a[0].get("mapping_matches") is not True or map_b[0].get("mapping_matches") is not True):
        raise ValueError("fresh verified mappings missing")
    rebase_a, rebase_b = int(map_a[0]["code_rebase"]), int(map_b[0]["code_rebase"])
    if rebase_a != rebase_b:
        raise ValueError("fresh code rebases differ")

    sequence_a = _after_second_entry(rows_a)
    sequence_b = _after_second_entry(rows_b)
    signatures_a = [(row.get("event"), int(row.get("link_va", -1))) for row in sequence_a]
    signatures_b = [(row.get("event"), int(row.get("link_va", -1))) for row in sequence_b]
    common = 0
    while common < min(len(signatures_a), len(signatures_b)) and signatures_a[common] == signatures_b[common]:
        common += 1

    entry_a = next(row for row in rows_a if row.get("event") == "w3_275_second_smacker_entry")
    entry_b = next(row for row in rows_b if row.get("event") == "w3_275_second_smacker_entry")
    entry_compare = {
        register: {"a": int(entry_a[register]), "b": int(entry_b[register]),
                   "equal": int(entry_a[register]) == int(entry_b[register])}
        for register in GPRS
    }
    first_difference = {
        "index_after_shared_entry": common,
        "run_a_next": ({"event": signatures_a[common][0],
                         "link_va": f"0x{signatures_a[common][1]:08X}"}
                        if common < len(signatures_a) else None),
        "run_b_next": ({"event": signatures_b[common][0],
                         "link_va": f"0x{signatures_b[common][1]:08X}"}
                        if common < len(signatures_b) else None),
    }
    last_common_link = signatures_a[common - 1][1] if common else None
    last_common_a = next((row for row in reversed(sequence_a)
                          if int(row.get("link_va", -1)) == last_common_link), None)
    last_common_b = next((row for row in reversed(sequence_b)
                          if int(row.get("link_va", -1)) == last_common_link), None)
    timeout_a = float(manifest_a["guard"].get("limits", {}).get("timeout_s", 120))
    timeout_b = float(manifest_b["guard"].get("limits", {}).get("timeout_s", 120))
    remaining_a = (timeout_a - int(last_common_a["elapsed_ms"]) / 1000
                   if last_common_a and "elapsed_ms" in last_common_a else None)
    remaining_b = (timeout_b - int(last_common_b["elapsed_ms"]) / 1000
                   if last_common_b and "elapsed_ms" in last_common_b else None)
    time_budget_hypothesis = bool(remaining_b is not None and 0 <= remaining_b < 5 and
                                  remaining_a is not None and remaining_a > remaining_b)
    guard_a, guard_b = manifest_a["guard"], manifest_b["guard"]
    run_metadata = []
    for manifest, prov, guard in ((manifest_a, prov_a, guard_a), (manifest_b, prov_b, guard_b)):
        run_metadata.append({
            "task": manifest["task"], "run_id": manifest["run_id"],
            "binary_sha256": prov.get("binary_sha256"),
            "source_core_sha256": prov.get("source_sha256", {}).get("src/cpu/core_dyn_x86.cpp"),
            "code_rebase": f"0x{int(manifest['analysis']['code_rebase'],16):08X}",
            "trace_bytes": manifest["trace"]["bytes"], "trace_rows": manifest["trace"]["rows"],
            "trace_sha256": manifest["trace"]["sha256"],
            "guard_cause": guard.get("cause"), "guard_duration_s": guard.get("duration_s"),
            "host_free_before": guard.get("host_free_before"),
            "host_free_after": guard.get("host_free_after"),
            "selected_after_entry": [
                {"sequence": int(row["sequence"]), "event": row.get("event"),
                 "link_va": f"0x{int(row.get('link_va',0)):08X}",
                 "elapsed_ms": row.get("elapsed_ms")}
                for row in _after_second_entry(read_trace(
                    Path(manifest["_trace_path"]), manifest["trace"]["bytes"],
                    manifest["trace"]["rows"], manifest["trace"]["sha256"]))
            ],
        })
    return {
        "identity_equal": identity,
        "fresh_code_rebase": f"0x{rebase_a:08X}",
        "second_smacker_entry_registers": entry_compare,
        "common_post_entry_checkpoint_prefix_length": common,
        "common_post_entry_checkpoint_prefix": [
            {"event": event, "link_va": f"0x{link:08X}"}
            for event, link in signatures_a[:common]
        ],
        "first_observed_difference": first_difference,
        "remaining_timeout_after_last_common_checkpoint_s": {
            "W3-280": remaining_a, "W3-281": remaining_b,
        },
        "cause_classification": "PLAUSIBLE" if time_budget_hypothesis else "UNKNOWN",
        "root_cause_status": "UNKNOWN",
        "causal_note": (
            "Run B reached the last common checkpoint with less than five seconds remaining under the 120-second timeout; this timing plausibly explains the missing later event, but does not prove it would have occurred. The instrumented binary/source hashes also differ. The absent checkpoint is not proof of a different guest branch."
            if time_budget_hypothesis else
            "The absent later checkpoints do not prove a different guest branch. Captured timing does not isolate a cause, and the instrumented binary/source hashes differ."
        ),
        "menu_verified": False,
        "gameplay_verified": False,
        "runs": run_metadata,
    }


def load_manifest_and_trace(root: Path, relative_manifest: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = root / relative_manifest
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    trace_path = root / manifest["trace"]["path"]
    rows = read_trace(trace_path, manifest["trace"]["bytes"],
                      manifest["trace"]["rows"], manifest["trace"]["sha256"])
    manifest["_trace_path"] = str(trace_path)
    return manifest, rows


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path_a = "evidence/w3_280_play_smk_step.json"
    path_b = "evidence/w3_281_play_smk_gate.json"
    manifest_a, rows_a = load_manifest_and_trace(root, path_a)
    manifest_b, rows_b = load_manifest_and_trace(root, path_b)
    comparison = compare_runs(manifest_a, rows_a, manifest_b, rows_b)
    runner_a = (root / "tools/w3_280_capture_runner.py").read_text(encoding="utf-8")
    runner_b = (root / "tools/w3_281_capture_runner.py").read_text(encoding="utf-8")
    opt_ins = ("GWRECOMP_W3_279_BRANCH_STEP", "GWRECOMP_W3_281_BRANCH_STEP")
    declared = {
        "W3-280": {key: f'"{key}": "1"' in runner_a for key in opt_ins},
        "W3-281": {key: f'"{key}": "1"' in runner_b for key in opt_ins},
    }
    comparison["runner_declared_opt_ins"] = declared
    comparison["effective_environment_fully_recorded"] = False
    comparison["instrumentation_hashes_equal"] = (
        manifest_a["provenance"]["binary_sha256"] == manifest_b["provenance"]["binary_sha256"]
        and manifest_a["provenance"]["source_sha256"]["src/cpu/core_dyn_x86.cpp"] ==
            manifest_b["provenance"]["source_sha256"]["src/cpu/core_dyn_x86.cpp"]
    )
    out = {
        "schema": "w3-282-replay-divergence/v1", "task": "W3-282",
        "evidence_level": "ORIGINAL_OBSERVED_COMPARISON",
        "input_evidence": [path_a, path_b],
        "comparison": comparison,
        "limits": [
            "Offline analysis only; no Oracle, DOSBox, or build executed.",
            "Run B missing a later checkpoint is not proof it took a different guest path.",
            "The captured environment is not a complete snapshot of all process environment values.",
        ],
    }
    destination = root / "evidence/w3_282_replay_divergence.json"
    temp = destination.with_suffix(".json.tmp")
    temp.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, destination)
    print(json.dumps({"output": str(destination), "common_prefix": comparison[
        "common_post_entry_checkpoint_prefix"], "first_difference": comparison[
        "first_observed_difference"], "cause": comparison["cause_classification"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
