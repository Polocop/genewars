"""Pure bounded-state helpers for the ECD40 continuation instrumentation."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
START_LINK = 0x000ECD31
TARGET_LINK = 0x000ECD40
MAX_ADDITIONAL_STEPS = 5


def runtime_target(code_rebase: int) -> int:
    if code_rebase <= 0:
        raise ValueError("missing measured code rebase")
    return code_rebase + TARGET_LINK


def next_action(current_runtime: int, code_rebase: int, psp: int,
                expected_psp: int, expected_target_runtime: int,
                step_count: int) -> str:
    if code_rebase <= 0 or current_runtime < code_rebase:
        return "mapping_invalid"
    if psp != expected_psp or runtime_target(code_rebase) != expected_target_runtime:
        return "context_changed"
    current_link = current_runtime - code_rebase
    if current_runtime == expected_target_runtime:
        return "stop_at_target"
    if not START_LINK <= current_link < TARGET_LINK:
        return "path_diverged"
    if step_count >= MAX_ADDITIONAL_STEPS:
        return "step_cap"
    return "step_once"


def after_step(before_runtime: int, after_runtime: int, code_rebase: int,
               target_runtime: int, step_count: int, normal_core_return: int = 0) -> tuple[int, str]:
    count = step_count + 1
    if after_runtime == target_runtime:
        return count, "target_pending_checkpoint"
    if after_runtime <= before_runtime:
        return count, "path_diverged"
    after_link = after_runtime - code_rebase
    if after_link < START_LINK or after_link > TARGET_LINK:
        return count, "path_diverged"
    if normal_core_return:
        return count, "normal_core_exit"
    if count >= MAX_ADDITIONAL_STEPS:
        return count, "step_cap"
    return count, "continue"


def inspect_source(text: str) -> dict:
    compact = "".join(text.split())
    checks = {
        "continuation_state_is_bounded": "w3_198_ecd40_continuation_steps<5" in compact,
        "runtime_target_uses_current_rebase": "target_main_rebase+0x000ecd40" in compact,
        "handler_and_psp_gate": "w3_177_target_entry_seen" in compact and
                                  "dos.psp()!=w3_198_ecd40_continuation_psp" in compact,
        "cross_block_step_does_not_require_cache_span": "w3_198_ecd40_continue_step" in compact and
                                                           "if(w3_198_ecd40_continue_step)w3_167_cache_span_step=true;" in compact,
        "bounded_step_event": "W3_198_ECD40_CONTINUATION_STEP" in compact,
        "stop_event_is_one_shot": "W3_198_ECD40_CONTINUATION_STOP" in compact and
                                  "w3_198_ecd40_stop_event_logged" in compact,
        "target_stops_before_core_step": "ip_point==w3_198_ecd40_target_runtime" in compact,
    }
    if not all(checks.values()):
        raise ValueError("W3-198 source invariant failed: " +
                         ", ".join(k for k, value in checks.items() if not value))
    return {"checks": checks, "all_checks_pass": True}
