from __future__ import annotations

from pathlib import Path

from tools.w3_279_play_smk_step import analyze, parse


def verify_fallback_integration(source: str) -> bool:
    marker = "if (w3_143_postopen_probe_window || w3_146_transfer_probe_window"
    start = source.find(marker)
    if start < 0:
        return False
    end = source.find("sync_dh_fpu_and_run_normal_core()", start)
    if end < 0:
        return False
    fallback = source[start:end]
    return (
        "w3_279_branch_probe_window" in fallback
        and "CPU_Cycles = 1" in fallback
        and "candidate_link_va >= 0x000ae2d0 && candidate_link_va <= 0x000ae2e8" in source
        and "w3_279_step_instruction_count < 16" in source
        and 'GWRECOMP_W3_279_BRANCH_STEP' in source
        and "w3_278_later_play_smk_entry_seen" in source
    )


def verify_fallback_file(path: Path) -> bool:
    return verify_fallback_integration(path.read_text(encoding="utf-8"))
