"""Synthetic-only checks for the armed, one-shot ECD40 step result event."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


def cache_target_seen(progress_seen, handler_entry_seen):
    return bool(progress_seen or not handler_entry_seen)


def should_log_step(target_step, handler_entry_seen, progress_seen, event_attempted):
    return bool(target_step and handler_entry_seen and not progress_seen and not event_attempted)


def inspect_source(text):
    compact = "".join(text.split())
    checks = {
        "pre_handler_target_is_unarmed": "target_seen=w3_181_progress_seen||!w3_177_target_entry_seen;break;" in compact,
        "only_ecd40_sets_step_tag": "if(i==5)w3_193_ecd40_cache_step=true;" in compact,
        "result_event_requires_armed_handler": "w3_193_ecd40_cache_step&&w3_177_target_entry_seen&&!w3_181_progress_seen&&!w3_193_ecd40_step_event_attempted" in compact,
        "event_is_one_shot_before_append": "w3_193_ecd40_step_event_attempted=true;" in compact and compact.index("w3_193_ecd40_step_event_attempted=true;") < compact.index("W3_193_ECD40_STEP_RESULT"),
        "event_contains_pre_post_and_return": all(x in compact for x in ("W3_193_ECD40_STEP_RESULT", "before_runtime", "before_link_va", "after_runtime", "after_link_va", "normal_core_return")),
        "event_is_after_normal_core_step": compact.index("sync_dh_fpu_and_run_normal_core();", compact.index("if(w3_167_cache_span_step)")) < compact.index("W3_193_ECD40_STEP_RESULT"),
        "existing_exact_progress_latch_preserved": "if(w3_181_progress_candidate)w3_181_progress_seen=true;" in compact,
    }
    if not all(checks.values()):
        raise ValueError("W3-193 source invariant failed: " + ", ".join(k for k, v in checks.items() if not v))
    return {"checks": checks, "all_checks_pass": True}


def build():
    return inspect_source(SOURCE.read_text(encoding="utf-8"))
