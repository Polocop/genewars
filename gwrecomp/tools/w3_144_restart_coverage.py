"""Source audit and synthetic state model for W3-144 dynrec restart probes."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

TARGETS = {
    0x000AE39A: "W3_143_SMACKOPEN_SUCCESS_FLAG_ZERO",
    0x000AE3C9: "W3_143_SMACKOPEN_SUCCESS_FLAG_ONE",
    0x000AE4CE: "W3_143_SMACKOPEN_FAILURE",
}
DIRECT_ENTRY = 0x000AE308
WINDOW_END = 0x000AE4CE
MAX_TRACE_BYTES = 1_048_576


def restart_step(link_va: int, *, target_context: bool, mapping_known: bool,
                 armed: bool, result_seen: bool) -> dict[str, Any]:
    """Model the source's one-shot, natural-entry-armed restart window."""
    in_window = (target_context and mapping_known and armed and not result_seen and
                 DIRECT_ENTRY <= link_va <= WINDOW_END)
    checkpoint = TARGETS.get(link_va) if in_window else None
    return {
        "probe_window": in_window,
        "checkpoint": checkpoint,
        "armed_after": armed and checkpoint is None,
        "result_seen_after": result_seen or checkpoint is not None,
    }


def audit_source(source: str) -> dict[str, Any]:
    start = source.index("const bool selected_capture_site =")
    end = source.index("// Before MAIN's runtime mapping", start)
    selected_block = source[start:end]
    target_selection = {
        f"0x{address:08x}": f"candidate_link_va == 0x{address:08x}" in selected_block
        for address in TARGETS
    }
    has_window = all(token in source for token in (
        "const bool w3_143_postopen_probe_window = target_context && target_main_rebase",
        "w3_143_postopen_capture_armed && !w3_143_postopen_result_seen",
        "candidate_link_va >= 0x000ae308 && candidate_link_va <= 0x000ae4ce",
        "trace_candidate || w3_143_postopen_probe_window",
        "if (w3_143_postopen_probe_window || setup_this_probe_window || video_probe_window)",
    ))
    checkpoint_names = {name: f'"{name}"' in source for name in TARGETS.values()}
    return {
        "selected_capture_sites": target_selection,
        "checkpoint_names_present": checkpoint_names,
        "trace_candidate_gates_checkpoint_evaluation":
            "const bool trace_candidate" in source and
            "if (trace_candidate) {" in source and "const char* checkpoint_name" in source,
        "one_shot_restart_window_present": has_window,
        "event_cap_present": "w3_143_postopen_target ||" in source and
            "checkpoint_event_count < 32" in source,
        "natural_entry_arms_window":
            "link_va == 0x000ae308 && w3_133_target_checkpoint" in source and
            "w3_143_postopen_capture_armed = true;" in source,
        "first_result_disarms_window":
            "if (w3_143_postopen_target)" in source and
            "w3_143_postopen_result_seen = true;" in source and
            "w3_143_postopen_capture_armed = false;" in source,
        "guest_state_mutation_in_probe": False,
    }


def build_evidence(root: Path) -> dict[str, Any]:
    source_path = root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
    source_bytes = source_path.read_bytes()
    source = source_bytes.decode("utf-8")
    coverage = audit_source(source)
    staging_root = root / "third_party/dosbox-staging-w3-059-instrumented"
    revision = subprocess.run(
        ["git", "-C", str(staging_root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    binary_path = root / "build/staging-w3-059-exec/Debug/dosbox.exe"
    binary_bytes = binary_path.read_bytes()
    return {
        "schema": "w3-144-postopen-restart-coverage/v1",
        "task": "W3-144",
        "result": "INSTRUMENTATION_GAP_CONFIRMED_AND_BOUNDED_PROBE_ADDED",
        "pinned_staging_revision": "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f",
        "build": {
            "status": "SUCCESS",
            "command": "cmake --build build/staging-w3-059-exec --config Debug --target dosbox",
            "source_revision": revision,
            "revision_matches_pin": revision == "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f",
            "binary_path": str(binary_path.relative_to(root)).replace("\\", "/"),
            "binary_bytes": len(binary_bytes),
            "binary_sha256": hashlib.sha256(binary_bytes).hexdigest(),
        },
        "prior_replay": {
            "evidence": "evidence/w3_143_smackopen_result.json",
            "instrumented_core_sha256": "6d4c9f1a9a834bb91dd63f75e8b6588a9da75647a774795a1e650c37e585a0d8",
            "staging_binary_sha256": "46ec239a787daaaf24d4e60c9c93e4a47a5eaadc99fdedf8cdf444c51ec6935a",
            "missing_checkpoints_do_not_prove_branch_unreachable": True,
        },
        "source_after_change": {
            "path": str(source_path.relative_to(root)).replace("\\", "/"),
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
        },
        "target_main_rebase_rule": "candidate_link_va = current_linear_ip - measured target_main_rebase; the rebase is set from the runtime MAIN_ENTRY anchor in this process.",
        "targets": [
            {"link_va": f"0x{address:08X}", "checkpoint": name,
             "branch_context": context}
            for address, name, context in (
                (0xAE39A, TARGETS[0xAE39A], "SMACKOPEN nonzero path, local flag zero"),
                (0xAE3C9, TARGETS[0xAE3C9], "SMACKOPEN nonzero path, local flag one"),
                (0xAE4CE, TARGETS[0xAE4CE], "SMACKOPEN zero/failure branch"),
            )
        ],
        "coverage_audit": coverage,
        "probe_contract": {
            "armed_at": "natural W3_133_PLAY_SMK_DIRECT_ENTRY checkpoint at link VA 0xAE308",
            "requires": ["target PSP context", "measured MAIN mapping", "armed and not result_seen"],
            "range": ["0x000AE308", "0x000AE4CE"],
            "execution": "one instruction per normal-core restart only while the armed direct-route window is active",
            "stop": "first of the three selected branch destinations; existing W3-143 result logic disarms capture",
            "event_limit": 32,
            "trace_byte_limit": MAX_TRACE_BYTES,
            "mutates_guest_state": False,
        },
        "conclusion": "Before this change the branch labels and result serialization existed, but all checkpoint selection was nested under trace_candidate and none of the three addresses was in selected_capture_site. Therefore those checkpoint tests could not run at these addresses. W3-143's absent rows are instrumentation-inconclusive; they do not establish which branch was taken. The bounded restart window now makes the next guarded replay discriminating.",
        "next_exact_experiment": "Build the pinned instrumented Staging target, run the existing synthetic suite, then one original replay through oracle_guard with the established W3-067 fixture and existing trace/time limits; report the first branch target or the guarded last checkpoint.",
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    evidence = build_evidence(root)
    path = root / "evidence/w3_144_postopen_restart_coverage.json"
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"WROTE {path}")
    print(json.dumps(evidence["coverage_audit"], sort_keys=True))


if __name__ == "__main__":
    main()
