"""Host-only checks for the incoming dynrec block at PlayIntro entry."""
from __future__ import annotations

import re
import hashlib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
PLAYINTRO_LOW = 0x92930
PLAYINTRO_HIGH = 0x92ADD
PLAYINTRO_TARGETS = (
    0x92983, 0x92996, 0x929A9, 0x92A11, 0x92A16, 0x92A24, 0x92ADD,
)


def source_facts(source: str) -> dict[str, Any]:
    start = source.index("const bool video_probe_window")
    end = source.index("in_target_function =", start)
    window = source[start:end]
    ranges = [
        (int(low, 16), int(high, 16))
        for low, high in re.findall(
            r"candidate_link_va\s*>=\s*(0x[0-9a-fA-F]+)\s*&&\s*candidate_link_va\s*<=\s*(0x[0-9a-fA-F]+)",
            window,
        )
    ]
    create = re.search(r"CreateCacheBlock\(chandler,\s*ip_point,\s*in_target_function\s*\?\s*1\s*:\s*32\)", source)
    fallback = "if (setup_this_probe_window || video_probe_window)" in source
    candidate_entry = "candidate_link_va == 0x00092930" in source
    return {
        "video_probe_ranges": ranges,
        "create_block_limits_selected_candidate": create is not None,
        "normal_core_one_cycle_fallback": fallback,
        "playintro_entry_selected_site": candidate_entry,
    }


def in_probe_window(link_va: int, facts: dict[str, Any]) -> bool:
    return any(low <= link_va <= high for low, high in facts["video_probe_ranges"])


def build_evidence() -> dict[str, Any]:
    source = CORE.read_text(encoding="utf-8")
    facts = source_facts(source)
    return {
        "schema": "w3-113-playintro-dynrec-coverage/v1",
        "task": "W3-113",
        "source_path": str(CORE.relative_to(ROOT)),
        "source_sha256": hashlib.sha256(CORE.read_bytes()).hexdigest(),
        "old_window_hypothesis": {
            "range_start": "0x00092983",
            "incoming_block_start_outside_window": "0x00092931",
            "maximum_dynrec_block_instruction_count": 32,
            "risk": "A block beginning at 0x92931 can be created outside the one-cycle window and may include callsite 0x92983 before CPU_Core_Dyn_X86_Run re-enters."
        },
        "updated_window": {
            "expected_range": [f"0x{PLAYINTRO_LOW:08X}", f"0x{PLAYINTRO_HIGH:08X}"],
            "actual_ranges": [[f"0x{low:08X}", f"0x{high:08X}"] for low, high in facts["video_probe_ranges"]],
            "entry_in_one_cycle_window": in_probe_window(PLAYINTRO_LOW, facts),
            "all_targets_covered": all(in_probe_window(target, facts) for target in PLAYINTRO_TARGETS),
            "targets": [f"0x{x:08X}" for x in PLAYINTRO_TARGETS],
        },
        "source_facts": facts,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(build_evidence(), indent=2))
