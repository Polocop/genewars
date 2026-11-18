from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
INPUTS = {
    "static_frontier": "evidence/w3_108_playintro_continuation.json",
    "missed_capture_109": "evidence/w3_109_playintro_return_capture.json",
    "missed_capture_111": "evidence/w3_111_playintro_return_capture.json",
    "first_callsite_113": "evidence/w3_113_playintro_dynrec_capture.json",
    "play_smacker_116": "evidence/w3_116_play_smacker_state.json",
    "media_call_118": "evidence/w3_118_play_smacker_call_boundary.json",
    "reset_inputs_121": "evidence/w3_121_reset_inputs_boundary.json",
    "b_screen_129": "evidence/w3_129_b_screen_capture.json",
    "screen_path": "evidence/w3_187_post_dpmi_screen_path.json",
    "full_viewport": "evidence/w3_267_viewport_hash.json",
}
INTRO_TARGETS = (0x92983, 0x92996, 0x929A9, 0x929C8, 0x92A11, 0x92A16, 0x92A24, 0x92ADD, 0x94347)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_evidence() -> dict:
    paths = {key: ROOT / value for key, value in INPUTS.items()}
    data = {key: json.loads(path.read_text(encoding="utf-8")) for key, path in paths.items()}
    core_text = CORE.read_text(encoding="utf-8")
    core_hash = sha256(CORE)

    required_source = (
        "restart_core:",
        "const auto candidate_link_va = target_main_rebase",
        "const bool trace_candidate = target_context &&",
        "goto restart_core;",
        "const bool video_probe_window = target_context && target_main_rebase",
        "candidate_link_va >= 0x00092930 && candidate_link_va <= 0x00092add",
        "CPU_Cycles = 1;",
        "sync_dh_fpu_and_run_normal_core();",
    )
    missing = [part for part in required_source if part not in core_text]
    if missing:
        raise ValueError(f"dynamic-core source missing expected callback behavior: {missing}")

    static = data["static_frontier"]
    expected_links = {f"0x{address:08X}" for address in INTRO_TARGETS}
    chain_links = {row["link_va"] for row in static["static_chain"]}
    if not expected_links.issubset(chain_links):
        raise ValueError("static frontier evidence does not cover all selected return checkpoints")

    w3_267 = data["full_viewport"]
    events = w3_267["trace"]["events"]
    expected_order = ["main_mapping", "copy_pre", "copy_post", "opengl_backbuffer_pre_swap", "backend_present_return"]
    observed_order = [event["event"] for event in events]
    if observed_order != expected_order or not w3_267["analysis"]["same_run_full_frame_verified"]:
        raise ValueError("W3-267 does not contain the expected same-run ordered present evidence")
    if w3_267["trace"]["events"][-1].get("guest_eip") is not None:
        raise ValueError("expected W3-267 to leave guest EIP after backend present unmeasured")

    prior_hashes = {
        "W3-109": data["missed_capture_109"]["preflight"]["core_source_sha256"],
        "W3-111": data["missed_capture_111"]["preflight"]["core_source_sha256"],
        "W3-113": data["first_callsite_113"]["preflight"]["core_source_sha256"],
        "W3-267": data["full_viewport"]["provenance"]["instrumented_source_sha256"]["src/cpu/core_dyn_x86.cpp"],
    }
    matching_build_source = {key: value == core_hash for key, value in prior_hashes.items()}
    first_callsite = data["first_callsite_113"]["trace"]["target_events"]
    first_callsite_observed = any(event.get("link_va") == 0x92983 for event in first_callsite)
    if not first_callsite_observed:
        raise ValueError("W3-113 did not dynamically record the first PlayIntro callsite")
    def observed_links(key: str) -> list[str]:
        trace = data[key]["trace"]
        events = trace.get("target_events", trace.get("target_checkpoints", []))
        return [f"0x{event['link_va']:08X}" for event in events]

    play_smacker_chain = {
        "W3-116": observed_links("play_smacker_116"),
        "W3-118": observed_links("media_call_118"),
        "W3-121": observed_links("reset_inputs_121"),
        "W3-129": observed_links("b_screen_129"),
    }

    # W3-267 has an ordered renderer present return, but it does not pair that
    # host callback with the first subsequent guest dispatcher EIP. That is the
    # discriminating next measurement; static PlayIntro addresses remain candidates.
    return {
        "schema": "w3-268-playintro-frontier-audit/v1",
        "task": "W3-268",
        "evidence_level": "ORIGINAL_OBSERVED_PLUS_STATIC_SOURCE_AUDIT",
        "inputs": {key: {"path": INPUTS[key], "sha256": sha256(path)} for key, path in paths.items()},
        "target": {
            "gw_exe_sha256": static["target_sha256"],
            "pinned_disassembly_sha256": static["inputs"]["disassembly"]["sha256"],
            "link_va_space": "GeneWars 1.1 MAIN link VAs from hash-bound corrected-VA closure",
        },
        "dynamic_core": {
            "path": str(CORE.relative_to(ROOT)).replace("\\", "/"),
            "sha256": core_hash,
            "dispatch_model": "The candidate link VA and trace_candidate predicate are evaluated at restart_core. BR_Normal returns to restart_core; BR_Link can enter a cached block directly unless an explicit range/site guard redirects it.",
            "playintro_window": {
                "range": ["0x00092930", "0x00092ADD"],
                "one_cycle_normal_core": True,
                "restart_after_normal_core": True,
                "meaning": "In this source revision, once dispatch is inside this bounded range, the normal core is run with one cycle and restart_core reevaluates the current guest EIP. A site being in selected_capture_site alone would not provide this guarantee.",
            },
            "historical_source_match": matching_build_source,
            "historical_source_hashes": prior_hashes,
            "conclusion": "W3-109/W3-111 did not record 0x92983 and have no last guest EIP. W3-113 then widened the one-cycle range to start at observed PlayIntro entry 0x92930 and recorded 0x92983; W3-116/118 recorded the natural PlaySmacker screen-setup and media call/return. This source-level coverage issue explains the missing first callsite in the older captures, but not the later absence of menu/game checkpoints.",
        },
        "original_static_control_flow": {
            "playintro_entry": "0x00092930",
            "playintro_calls_play_smacker": ["0x00092983", "0x00092996", "0x000929A9"],
            "first_play_smacker_screen_setup_call": "0x00092A11",
            "earliest_return_checkpoint": "0x00092A16",
            "later_play_smacker_checkpoints": ["0x00092A24", "0x00092ADD"],
            "playintro_return": "0x000929C8",
            "main_game_call": "0x00094347",
            "classification": "STATIC_ONLY",
            "dynamic_first_callsite_w3_113": {
                "observed": first_callsite_observed,
                "link_va": "0x00092983",
                "runtime_eip": first_callsite[0].get("eip"),
                "mapping_rebase": "0x001EB000",
                "classification": "ORIGINAL_OBSERVED",
            },
            "later_original_sequences": {
                "ordered_link_vas": play_smacker_chain,
                "same_invocation_as_w3_267_viewport": False,
            },
        },
        "latest_original_present": {
            "task": "W3-267",
            "same_run_events": observed_order,
            "full_viewport_hash_fnv1a64": w3_267["trace"]["events"][3]["fnv1a64"],
            "backend_present_returned": w3_267["analysis"]["backend_present_returned"],
            "guest_eip_after_present": "UNKNOWN_NOT_CAPTURED",
            "menu": "PENDING",
            "gameplay": "PENDING",
        },
        "next_discriminating_measurement": {
            "method": "Use a one-shot present-return marker consumed at the next restart_core dispatch. Record fresh MAIN mapping, CS:EIP/link VA and ordinal. In the same single bounded replay, retain capped checkpoints for the already measured PlaySmacker return/media path and main_ game call/entry (0x92996, 0x929A9, 0x929C8, 0x94347, 0x92710).",
            "why": "Pairs the measured renderer present with the first subsequent guest PC, then determines whether this run completes the three intro calls and enters game initialization.",
            "duplicate_control": "Do not repeat W3-116/118/121/129 targets as standalone tasks; only use them as same-run ordering/context anchors for the new present-to-guest-resume question.",
            "oracle_replay_authorized_by_this_task": False,
        },
        "tests": {
            "source_audit": "PASS; see evidence/autopilot_test_w3-268_20261009_221348.json",
            "oracle_run": False,
            "build": False,
        },
    }


def main() -> None:
    output = ROOT / "evidence/w3_268_playintro_frontier.json"
    output.write_text(json.dumps(build_evidence(), indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
