"""Read-only reconciliation of the bounded W3-168 trace and screen copy."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "build/dosboxx_oracle/C/W3_168_WSCREEN_GATE_CAPTURE_20261009_01.jsonl"
CAPTURE = ROOT / "evidence/w3_168_wscreen_gate_capture.json"
RELATED = {
    "W3-152": ROOT / "evidence/w3_152_rep_copy_capture.json",
    "W3-153": ROOT / "evidence/w3_153_screen_samples.json",
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _link_va(row: dict[str, Any], code_rebase: int) -> int:
    if "link_va" in row:
        return int(row["link_va"])
    return int(row["eip"]) - code_rebase


def audit(trace_path: Path = TRACE,
          capture_path: Path = CAPTURE,
          related_paths: dict[str, Path] = RELATED) -> dict[str, Any]:
    capture = _load_json(capture_path)
    trace_info = capture["trace"]
    raw = trace_path.read_bytes()
    if len(raw) != trace_info["bytes"]:
        raise ValueError("trace byte count does not match capture manifest")
    trace_sha = hashlib.sha256(raw).hexdigest()
    if trace_sha != trace_info["sha256"]:
        raise ValueError("trace SHA-256 does not match capture manifest")
    if len(raw) > 1024 * 1024:
        raise ValueError("trace exceeds the recorded 1 MiB cap")
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    if len(rows) != trace_info["event_count"]:
        raise ValueError("trace event count does not match capture manifest")

    code_rebase = int(capture["mapping"]["code_rebase"])
    data_rebase = int(capture["mapping"]["data_rebase"])
    relevant_names = {
        "W3_160_WSCREEN_GATE_117662",
        "W3_158_WSCREEN_LOADER_ENTRY",
        "W3_158_WSCREEN_CALL_RETURN",
        "VIDEO_SCREEN_SETUP_ANY_MODE",
        "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
        "W3_151_COPY_NONVESA_PRE",
        "W3_151_COPY_NONVESA_POST",
        "W3_149_LBSCREENSWAP_RETURN",
    }
    selected = [r for r in rows if r.get("checkpoint") in relevant_names]
    if not selected:
        raise ValueError("no expected downstream checkpoints in trace")
    psps = {int(r["process_psp"]) for r in selected}
    if psps != {int(capture["main_checkpoint"]["process_psp"])}:
        raise ValueError("selected checkpoints do not share the captured MAIN PSP")
    sequences = [int(r["sequence"]) for r in selected]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise ValueError("selected checkpoint order is not strictly increasing")
    for row in selected:
        if _link_va(row, code_rebase) != int(row["link_va"]):
            raise ValueError("runtime/link mapping mismatch in selected checkpoint")

    by_name = {r["checkpoint"]: r for r in selected}
    needed = ("W3_160_WSCREEN_GATE_117662", "W3_158_WSCREEN_LOADER_ENTRY",
              "W3_158_WSCREEN_CALL_RETURN", "W3_151_COPY_NONVESA_PRE",
              "W3_151_COPY_NONVESA_POST")
    missing = [name for name in needed if name not in by_name]
    if missing:
        raise ValueError("missing required same-run checkpoint(s): " + ", ".join(missing))
    gate, loader, loader_return, pre, post = (by_name[name] for name in needed)
    if not (gate["sequence"] < loader["sequence"] < loader_return["sequence"] < pre["sequence"] < post["sequence"]):
        raise ValueError("gate/loader/copy causal sequence is not ordered")
    if int(pre["link_va"]) != 0xA0013 or int(post["link_va"]) != 0xA0015:
        raise ValueError("copy checkpoints do not match exact-target pre/post link VAs")
    if int(gate.get("w3_160_data_rebase", -1)) != data_rebase:
        raise ValueError("gate did not use the fresh DATA mapping")
    loader_return_runtime = int(loader.get("w3_158_raw_return_address", 0))
    if loader_return_runtime - code_rebase != 0x94DC1:
        raise ValueError("loader stack return does not map to 0x94DC1")

    count = int(pre["ecx"])
    copied_bytes = count * 4
    source = int(pre["esi"])
    destination = int(pre["edi"])
    copy_completed = (
        int(post["ecx"]) == 0
        and int(post["esi"]) - source == copied_bytes
        and int(post["edi"]) - destination == copied_bytes
        and bool(post["w3_151_copy_sample_valid"])
        and bool(post["w3_151_copy_ds_valid"])
        and bool(post["w3_151_copy_es_valid"])
        and bool(post["w3_151_copy_source_bounds_valid"])
        and bool(post["w3_151_copy_destination_bounds_valid"])
    )
    if not copy_completed:
        raise ValueError("copy completion/bounds predicates did not all validate")
    sample = bytes.fromhex(post["w3_151_copy_sample_hex"])
    if len(sample) != int(post["w3_151_copy_sample_bytes"]):
        raise ValueError("bounded destination sample length mismatch")
    assign_after = next((r for r in selected
                         if r.get("checkpoint") == "VIDEO_FRAMEBUFFER_ASSIGN_AFTER"
                         and int(r["sequence"]) > int(loader_return["sequence"])), None)
    if assign_after is None:
        raise ValueError("no same-run display-base assignment-after checkpoint")
    base_sample = next((s for s in assign_after.get("framebuffer_global_samples", [])
                        if int(s.get("link_offset", -1)) == 0x19CA58), None)
    if base_sample is None or int(base_sample.get("value_u32", -1)) != 0xA0000:
        raise ValueError("display-base global sample did not verify value 0xA0000")

    related = {}
    for task_id, path in related_paths.items():
        p = _load_json(path)
        related[task_id] = {
            "run_id": p["run_id"],
            "trace_sha256": p["trace"]["sha256"],
            "same_original_target": p["source"]["target_sha256"] == capture["source"]["target_sha256"],
            "same_config": p["source"]["config_sha256"] == capture["source"]["config_sha256"],
            "same_cue": p["source"]["cue_sha256"] == capture["source"]["cue_sha256"],
            "same_staging_revision": p["source"]["staging_revision"] == capture["source"]["staging_revision"],
            "different_run": p["run_id"] != capture["run_id"],
            "copy_confirmed": bool(p["copy_confirmed"]),
            "screen_geometry": p.get("screen_geometry"),
        }

    return {
        "schema": "w3-169-loader-screen-copy-reconciliation/v1",
        "task": "W3-169",
        "classification": "ORIGINAL_OBSERVED",
        "replay_performed": False,
        "capture": {
            "task": capture["task"],
            "run_id": capture["run_id"],
            "trace": trace_info,
            "mapping": {"code_rebase": hex(code_rebase), "data_rebase": hex(data_rebase), "fresh": True},
            "target_sha256": capture["source"]["target_sha256"],
            "config_sha256": capture["source"]["config_sha256"],
            "cue_sha256": capture["source"]["cue_sha256"],
            "staging_revision": capture["source"]["staging_revision"],
            "staging_binary_sha256": capture["source"]["staging_binary_sha256"],
            "guard": {"sandbox_verified": capture["guard"]["sandbox_verified"],
                      "timeout_seconds": capture["guard"]["limits"]["timeout_s"],
                      "trace_cap_bytes": 1048576,
                      "exit_cause": capture["guard"]["cause"]},
        },
        "same_run_path": {
            "psp": next(iter(psps)),
            "checkpoints": [{"sequence": int(r["sequence"]), "checkpoint": r["checkpoint"],
                             "link_va": hex(int(r["link_va"]))} for r in selected],
            "gate_value": int(gate["w3_160_global_117662_value"]),
            "gate_eflags": hex(int(gate["eflags"])),
            "loader_entry": {"link_va": hex(int(loader["link_va"])),
                             "raw_return_runtime": hex(loader_return_runtime),
                             "return_link_va": hex(loader_return_runtime - code_rebase),
                             "descriptor": loader.get("w3_158_descriptor_name")},
            "display_base_assignment": {
                "checkpoint_sequence": int(assign_after["sequence"]),
                "checkpoint_link_va": hex(int(assign_after["link_va"])),
                "global_link_va": "0x19ca58",
                "global_value": hex(int(base_sample["value_u32"])),
            },
            "copy": {
                "pre_link_va": hex(int(pre["link_va"])),
                "post_link_va": hex(int(post["link_va"])),
                "source_guest_linear": hex(source),
                "destination_guest_linear": hex(destination),
                "count_dwords": count,
                "completed_bytes": copied_bytes,
                "post_ecx": int(post["ecx"]),
                "post_esi": hex(int(post["esi"])),
                "post_edi": hex(int(post["edi"])),
                "ds_es_and_bounds_valid": True,
                "post_sample_bytes": len(sample),
                "post_sample_hex": sample.hex(),
            },
            "claims": {
                "guest_screen_memory_copy_completed": True,
                "guest_destination_is_assigned_0xa0000_candidate": destination == 0xA0000,
                "host_vga_mapping_independently_verified": False,
                "decoded_pixels_or_visible_presentation_proven": False,
                "first_framebuffer_claim": False,
            },
        },
        "cross_run_comparison": related,
        "limitations": [
            "W3-168 guard ended by its configured timeout after the recorded checkpoints; DOSBox did not exit naturally.",
            "W3-152 and W3-153 are separate runs. Matching fixture/config/CUE/revision corroborates, but events are not one invocation.",
            "The evidence proves a completed guest-memory copy to guest linear 0xA0000 and a bounded all-zero destination sample, not host VGA aperture mapping, pixel semantics, visible output, menu, or gameplay.",
        ],
    }


def write_result(output: Path) -> dict[str, Any]:
    result = audit()
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    out = ROOT / "evidence/w3_169_loader_screen_copy_reconcile.json"
    result = write_result(out)
    print(json.dumps({"output": str(out), "classification": result["classification"],
                      "copy_completed": result["same_run_path"]["claims"]["guest_screen_memory_copy_completed"],
                      "bytes": result["same_run_path"]["copy"]["completed_bytes"]}, indent=2))
