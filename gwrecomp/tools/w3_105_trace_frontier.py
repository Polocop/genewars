"""Inspect persisted bounded original traces for selected video anchors."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

TARGETS = {
    0x92710: "game_entry", 0x834C0: "draw_game_entry", 0x9FFE0: "screen_swap_entry",
    0xA0049: "page_callsite", 0xA3A5C: "page_function_entry",
    0xA3A91: "int10_callsite_1", 0xA3AB7: "int10_callsite_2",
    0x9FDCC: "mode_callsite", 0xA3A00: "set_mode_entry", 0x9FDF9: "mode_continuation",
}
TRACE_NAMES = (
    "W3_073_VIDEO_20261008_01.jsonl", "W3_073_VIDEO_20261008_02.jsonl",
    "W3_074_PAGE_20261008_01.jsonl", "W3_075_STARTUP_VIDEO_20261008_01.jsonl",
    "W3_095_ORIGINAL_PSP_TAIL_20261009_01.jsonl",
    "W3_100_TARGETED_VESA_20261009_01.jsonl", "W3_103_VESA_PAGE_20261009_01.jsonl",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_events(text: str) -> list[dict[str, Any]]:
    events = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            value["_source_line"] = line_no
            events.append(value)
    return events


def link_address(event: dict[str, Any]) -> int | None:
    value = event.get("link_va")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            if re.fullmatch(r"[0-9a-fA-F]+", value):
                return int(value, 16)
    return None


def summarize_trace(path: Path) -> dict[str, Any]:
    events = parse_events(path.read_text(encoding="utf-8", errors="replace"))
    matches = []
    for event in events:
        address = link_address(event)
        if address in TARGETS:
            matches.append({
                "sequence": event.get("sequence"), "checkpoint": event.get("checkpoint"),
                "link_va": f"0x{address:08X}", "target": TARGETS[address],
                "code_rebase": event.get("code_rebase", event.get("main_code_rebase")),
                "runtime_eip": event.get("runtime_eip", event.get("eip")),
                "source_line": event["_source_line"],
            })
    return {
        "path": str(path).replace("\\", "/"), "sha256": sha256(path),
        "bytes": path.stat().st_size, "event_count": len(events), "matches": matches,
        "target_hit_counts": {name: sum(m["target"] == name for m in matches)
                              for name in sorted(set(TARGETS.values()))},
    }


def build_evidence(root: Path) -> dict[str, Any]:
    traces = [summarize_trace(root / "build/dosboxx_oracle/C" / name) for name in TRACE_NAMES]
    return {
        "schema": "w3-105-trace-frontier/v1", "task": "W3-105",
        "source_static_evidence": "evidence/w3_104_vesa_page_callers.json",
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "selected_traces": traces,
        "conclusion": {
            "game_draw_swap_page_chain_observed": False,
            "mode_setup_path_observed": True,
            "page_hook_observation": "W3-074 and W3-075 used bounded page/INT10 filters and persisted no A3A5C/A3A91/A3AB7 hit. W3-103 armed a page filter after natural mode call 0x101/0x180 and recorded no page hit before its 30-second guard timeout.",
            "game_draw_swap_observation": "These traces did not target game/draw_game/screen_swap checkpoints; missing records do not establish those functions did not execute.",
            "new_replay_decision": "No existing trace establishes the static chain dynamically. A new capture requires build integration of game/draw_game/screen_swap filters; this task performed no build or replay.",
            "next_exact_capture": [
                "game entry 0x92710", "game-to-draw_game callsite 0x928A0",
                "draw_game entry 0x834C0", "first taken draw_game-to-LbScreenSwap_ callsite 0x83985 or 0x839A2",
                "LbScreenSwap_ entry 0x9FFE0", "page callsite 0xA0049 and entry 0xA3A5C",
                "INT 10 sites 0xA3A91 and 0xA3AB7 if naturally reached",
            ],
        },
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_evidence(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
