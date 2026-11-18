"""Static validation of the W3-133 selected restart-candidate gate."""
from __future__ import annotations

import re
from pathlib import Path

CORE = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp")
TARGETS = {
    "play_smk_direct": "0x000ae308",
    "play_smk_via_buffer": "0x000ae4d8",
    "SMACKOPEN": "0x000c62f0",
    "RADMALLOC": "0x000ae63c",
    "copy_to_screen": "0x000ae668",
}


def inspect_source(source: str) -> dict[str, bool]:
    match = re.search(r"const bool selected_capture_site =.*?;", source, re.S)
    gate = match.group(0) if match else ""
    return {
        "selected_gate_found": bool(match),
        **{f"target_{name}": address in gate for name, address in TARGETS.items()},
        "dynamic_callback_armed_and_valid": all(token in gate for token in (
            "w3_133_capture_armed", "w3_133_draw_callback_valid",
            "w3_133_draw_callback_value", "candidate_link_va == w3_133_draw_callback_value")),
        "target_event_cap": "w3_133_checkpoint_count < 12" in source,
        "target_event_scope": "w3_133_target_checkpoint" in source and
                              "w3_133_checkpoint_count >= 12" in source,
    }


def main() -> int:
    report = inspect_source(CORE.read_text(encoding="utf-8", errors="replace"))
    if not all(report.values()):
        raise SystemExit(f"restart coverage incomplete: {report}")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
