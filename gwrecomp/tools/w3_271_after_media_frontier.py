from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_TRACE_BYTES = 1024 * 1024
MAX_TRACE_ROWS = 2048
MAX_TARGET_EVENTS = 16
POST_MEDIA_RETURN = 0x00092AE2
GAME_CALL = 0x00094347
GAME_ENTRY = 0x00092710


def runtime_to_link(runtime_linear: int, code_rebase: int) -> int | None:
    if runtime_linear < code_rebase:
        return None
    value = runtime_linear - code_rebase
    return value if value <= 0xFFFFFFFF else None


def parse_bounded_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB cap")
    lines = raw.splitlines()
    if len(lines) > MAX_TRACE_ROWS:
        raise ValueError("trace exceeds 2048-row cap")
    rows = []
    for number, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid JSONL at line {number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"JSONL line {number} is not an object")
        rows.append(row)
    return rows


def analyze_rows(rows: list[dict[str, Any]], raw_bytes: int) -> dict[str, Any]:
    if len(rows) > MAX_TRACE_ROWS or raw_bytes > MAX_TRACE_BYTES:
        raise ValueError("capture exceeds bounded trace limits")
    targets = [
        row for row in rows
        if row.get("event") == "w3_269_game_transition_checkpoint"
        and int(row.get("link_va", -1)) in {POST_MEDIA_RETURN, GAME_CALL, GAME_ENTRY}
    ]
    if len(targets) > MAX_TARGET_EVENTS:
        raise ValueError("target event cap exceeded")
    mappings = [row for row in rows if row.get("event") == "main_mapping"]
    markers = [row for row in rows
               if row.get("event") == "w3_269_first_guest_checkpoint_after_present"]
    if len(mappings) > 1 or len(markers) > 1:
        raise ValueError("duplicate mapping or one-shot present checkpoint")
    mapping = mappings[0] if mappings else None
    marker = markers[0] if markers else None
    if marker and runtime_to_link(int(marker["runtime_linear"]),
                                  int(marker["code_rebase"])) != int(marker["link_va"]):
        raise ValueError("post-present runtime/link mapping mismatch")
    event_order = []
    for row in rows:
        if row.get("event") in {
            "opengl_backbuffer_pre_swap", "w3_269_post_present_marker_set",
            "backend_present_return", "w3_269_first_guest_checkpoint_after_present",
        }:
            event_order.append(row["event"])
    return {
        "main_mapping_seen": mapping is not None and mapping.get("mapping_matches") is True,
        "post_present_checkpoint_seen": marker is not None,
        "post_present_link_va": f"0x{int(marker['link_va']):08X}" if marker else None,
        "post_present_order": event_order,
        "post_media_return_seen": any(int(row["link_va"]) == POST_MEDIA_RETURN for row in targets),
        "game_call_seen": any(int(row["link_va"]) == GAME_CALL for row in targets),
        "game_entry_seen": any(int(row["link_va"]) == GAME_ENTRY for row in targets),
        "target_count": len(targets),
        "target_events": targets,
        "menu_verified": False,
        "gameplay_verified": False,
    }


def validate_source(source: str) -> bool:
    compact = " ".join(source.split()).lower()
    return (
        "0x00092ae2" in compact
        and "0x00094347" in compact
        and "0x00092710" in compact
        and "w3_269_game_target_count < 6" in compact
    )


def main() -> None:
    raise SystemExit("Use tools/w3_271_capture_runner.py for the single guarded replay.")


if __name__ == "__main__":
    main()
