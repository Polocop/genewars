"""Synthetic-only checks for the bounded ECD40 cache-span probe wiring."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


def should_step(target_in_cached_block, target_runtime, current_runtime, target_seen):
    """Mirror the one-cycle split gate used by the existing cache-span probe."""
    return bool(target_in_cached_block and target_runtime > current_runtime and not target_seen)


def inspect_source(source_text):
    compact = "".join(source_text.split())
    start = source_text.index("static constexpr uint32_t w3_167_target_link_vas[]")
    end = source_text.index("};", start)
    array_text = source_text[start:end]
    targets = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{8})", array_text)]
    required = [0x94CE1, 0x94CEE, 0x94CF4, 0x94D9F, 0x94DBC, 0xECD40]
    if targets != required:
        raise ValueError("cache-span target list differs from the bounded expected set")
    checks = {
        "target_context_and_fresh_main_rebase": "if(target_context&&target_main_rebase&&block&&block->page.handler==chandler)" in compact,
        "cached_block_page_contains_target": "target_page_offset<block->page.start||target_page_offset>block->page.end" in compact,
        "ecd40_latch_case": "case5:target_seen=w3_181_progress_seen;break;" in compact,
        "single_step_only_before_unseen_target": "if(target_runtime>ip_point&&!target_seen)w3_167_cache_span_step=true;" in compact,
        "one_cycle_normal_core": "if(w3_167_cache_span_step){int32_told_cycles=CPU_Cycles;CPU_Cycles=1;constautonc_retcode=sync_dh_fpu_and_run_normal_core();" in compact,
        "progress_candidate_still_one_shot": "w3_177_target_entry_seen&&!w3_181_progress_seen&&candidate_link_va==0x000ecd40;" in compact,
        "progress_latch_after_successful_serialization": "if(exec_trace::append_event(record)){++checkpoint_event_count;" in compact and "if(w3_181_progress_candidate)w3_181_progress_seen=true;" in compact,
    }
    if not all(checks.values()):
        raise ValueError("bounded probe invariant failed: " + ", ".join(k for k, ok in checks.items() if not ok))
    return {"target_link_vas": [hex(v) for v in targets], "checks": checks, "all_checks_pass": True}


def build():
    return inspect_source(SOURCE.read_text(encoding="utf-8"))
