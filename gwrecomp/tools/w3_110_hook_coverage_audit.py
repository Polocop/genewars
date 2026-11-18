"""Read-only audit of dynamic-core capture-site gates for W3-109."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
W3_109 = ROOT / "evidence/w3_109_playintro_return_capture.json"
W3_107 = ROOT / "evidence/w3_107_main_transition.json"
TARGETS = (0x92983, 0x9FEAF, 0x92A16, 0x94347)


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_source_coverage(source: str) -> dict[str, Any]:
    selected_start = source.index("const bool selected_capture_site")
    selected_end = source.index("// Before MAIN's runtime mapping is known", selected_start)
    selected_block = source[selected_start:selected_end]
    selected = {int(value, 16) for value in re.findall(r"candidate_link_va\s*==\s*(0x[0-9a-fA-F]+)", selected_block)}

    video_start = source.index("const bool video_probe_window")
    video_end = source.index("in_target_function =", video_start)
    video_block = source[video_start:video_end]
    point_matches = re.findall(r"candidate_link_va\s*==\s*(0x[0-9a-fA-F]+)", video_block)
    range_matches = re.findall(
        r"candidate_link_va\s*>=\s*(0x[0-9a-fA-F]+)\s*&&\s*candidate_link_va\s*<=\s*(0x[0-9a-fA-F]+)",
        video_block,
    )
    ranges = [(int(low, 16), int(high, 16)) for low, high in range_matches]
    points = {int(value, 16) for value in point_matches}

    name_block = source.index("const char* checkpoint_name", selected_end)
    checkpoint_gate = source.rfind("if (trace_candidate) {", selected_end, name_block)
    if checkpoint_gate < 0:
        raise ValueError("checkpoint naming is not nested in the trace_candidate gate")
    w3_109_switch = source.index("uint32_t w3_109_target_bit", name_block)
    return {
        "selected_capture_sites": selected,
        "video_probe_points": points,
        "video_probe_ranges": ranges,
        "checkpoint_code_is_inside_trace_candidate_gate": checkpoint_gate < name_block < w3_109_switch,
    }


def in_range(value: int, ranges: list[tuple[int, int]]) -> bool:
    return any(low <= value <= high for low, high in ranges)


def build_evidence() -> dict[str, Any]:
    source = CORE.read_text(encoding="utf-8")
    w3_109 = json.loads(W3_109.read_text(encoding="utf-8"))
    w3_107 = json.loads(W3_107.read_text(encoding="utf-8"))
    coverage = extract_source_coverage(source)
    targets = []
    for link in TARGETS:
        selected = link in coverage["selected_capture_sites"]
        probed = link in coverage["video_probe_points"] or in_range(link, coverage["video_probe_ranges"])
        targets.append({
            "link_va": f"0x{link:08X}",
            "in_selected_capture_site_whitelist": selected,
            "in_one_cycle_video_probe_window": probed,
            "trace_candidate_can_run_for_target_context": selected,
        })
    raw_trace = ROOT / w3_109["trace"]["path"]
    rows = [json.loads(line) for line in raw_trace.read_text(encoding="utf-8").splitlines() if line.strip()]
    final = rows[-1] if rows else None
    return {
        "schema": "w3-110-hook-coverage-audit/v1",
        "task": "W3-110",
        "target_sha256": w3_109["preflight"]["fixture_sha256"],
        "inputs": {
            "dynamic_core": {"path": str(CORE.relative_to(ROOT)), "sha256": file_hash(CORE)},
            "w3_109_capture": {"path": str(W3_109.relative_to(ROOT)), "sha256": file_hash(W3_109)},
            "w3_107_capture": {"path": str(W3_107.relative_to(ROOT)), "sha256": file_hash(W3_107)},
            "w3_109_raw_trace": {"path": str(raw_trace.relative_to(ROOT)), "sha256": w3_109["trace"]["sha256"]},
        },
        "source_coverage": {
            "capture_callback": "CPU_Core_Dyn_X86_Run computes candidate_link_va from current CS:EIP and the measured MAIN rebase.",
            "trace_candidate_gate": "trace_candidate requires target_context and (selected_capture_site or possible_main_entry). Checkpoint naming, W3-109 predicates, and event serialization are nested inside if (trace_candidate).",
            "cache_behavior": "Only trace_candidate addresses enter the detailed checkpoint block. The selected-address flag also requests a one-instruction dynrec block on cache creation. Existing cached blocks may still contain selected addresses; the source's one-cycle normal-core fallback is limited to setup_this_probe_window and video_probe_window.",
            "selected_capture_site_count": len(coverage["selected_capture_sites"]),
            "video_probe_ranges": [[f"0x{low:08X}", f"0x{high:08X}"] for low, high in coverage["video_probe_ranges"]],
            "targets": targets,
        },
        "replay_reconciliation": {
            "w3_109_target_event_count": len(w3_109["trace"]["target_events"]),
            "w3_109_raw_event_count": w3_109["trace"]["raw_event_count"],
            "w3_107_observed_link_vas": w3_107["trace"]["target_order"],
            "last_raw_event": None if final is None else {
                "sequence": final.get("sequence"),
                "checkpoint": final.get("checkpoint"),
                "link_va": f"0x{final['link_va']:08X}" if isinstance(final.get("link_va"), int) else None,
                "elapsed_ms": final.get("elapsed_ms"),
            },
            "guard_cause": w3_109["guard"]["cause"],
        },
        "root_cause": "The W3-109 link VAs were added to checkpoint_name/target-bit logic but not to selected_capture_site or the one-cycle video probe window. Since checkpoint evaluation and serialization are gated by trace_candidate, the W3-109 predicates could not execute at those addresses. This is instrumentation coverage suppression, not evidence the guest skipped the instructions.",
        "minimal_next_change": "Add the exact W3-109 target addresses to the selected capture-site set and ensure the existing cached dynrec block cannot run across them: use a narrow first-hit probe window spanning the PlayIntro call/return slice and extend the mode setup probe only through 0x9FEAF, with one-cycle normal-core stepping. Keep per-target first-hit and the 12-record cap. Validate the predicates synthetically before any new one-shot guarded replay.",
        "scope": {"read_only_source_audit": True, "build_or_replay_performed": False},
    }


def main() -> None:
    output = ROOT / "evidence/w3_110_hook_coverage_audit.json"
    output.write_text(json.dumps(build_evidence(), indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
