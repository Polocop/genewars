from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_TARGET_EVENTS = 16
MAX_TRACE_BYTES = 1024 * 1024
MAX_TRACE_EVENTS = 2048
REQUIRED_ORDER = (
    "opengl_backbuffer_pre_swap",
    "w3_269_post_present_marker_set",
    "backend_present_return",
    "w3_269_first_guest_checkpoint_after_present",
)
GAME_TARGETS = (0x92996, 0x929A9, 0x929C8, 0x94347, 0x92710)


def parse_bounded_trace(raw: bytes) -> list[dict[str, Any]]:
    """Parse this task's bounded JSONL without the older 128-event cap.

    The byte cap is authoritative for payload size; this event cap prevents
    pathological line counts while allowing the selected 1 MiB capture to
    retain the ordinary DOS activity preceding the targeted checkpoints.
    """
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds the 1 MiB cap")
    lines = raw.splitlines()
    if len(lines) > MAX_TRACE_EVENTS:
        raise ValueError("trace exceeds the 2048-event cap")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid JSONL at line {number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"JSONL line {number} is not an object")
        rows.append(row)
    return rows


@dataclass
class OneShotPresentMarker:
    """Host-only model of the atomic 0 -> marked -> consumed state."""

    state: int = 0

    def mark(self, *, enabled: bool, copy_capture_armed: bool) -> bool:
        if enabled and copy_capture_armed and self.state == 0:
            self.state = 1
            return True
        return False

    def consume(self) -> bool:
        if self.state == 1:
            self.state = 2
            return True
        return False


def guest_link_va(runtime_linear: int, code_rebase: int) -> int | None:
    if runtime_linear < code_rebase:
        return None
    value = runtime_linear - code_rebase
    return value if value <= 0xFFFFFFFF else None


def validate_trace(raw: bytes, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds the 1 MiB cap")
    marker_rows = [r for r in rows if r.get("event") == "w3_269_first_guest_checkpoint_after_present"]
    set_rows = [r for r in rows if r.get("event") == "w3_269_post_present_marker_set"]
    backend_rows = [r for r in rows if r.get("event") == "backend_present_return"]
    viewport_rows = [r for r in rows if r.get("event") == "opengl_backbuffer_pre_swap"]
    target_rows = [r for r in rows if r.get("event") == "w3_269_game_transition_checkpoint"]
    if len(marker_rows) > 1 or len(set_rows) > 1:
        raise ValueError("one-shot post-present marker duplicated")
    if len(target_rows) > MAX_TARGET_EVENTS:
        raise ValueError("target checkpoint cap exceeded")
    indices = {name: next((i for i, row in enumerate(rows) if row.get("event") == name), None)
               for name in REQUIRED_ORDER}
    order_valid = all(indices[name] is not None for name in REQUIRED_ORDER) and all(
        indices[left] < indices[right] for left, right in zip(REQUIRED_ORDER, REQUIRED_ORDER[1:])
    )
    checkpoint = marker_rows[0] if marker_rows else None
    if checkpoint:
        calculated = guest_link_va(int(checkpoint["runtime_linear"]), int(checkpoint["code_rebase"]))
        if calculated is None or calculated != int(checkpoint["link_va"]):
            raise ValueError("post-present guest checkpoint does not match fresh runtime mapping")
    return {
        "viewport_readback_seen": bool(viewport_rows),
        "post_present_marker_set_seen": bool(set_rows),
        "backend_present_return_seen": bool(backend_rows),
        "first_guest_checkpoint_seen": bool(marker_rows),
        "post_present_order_valid": order_valid,
        "target_checkpoint_count": len(target_rows),
        "target_link_vas": [f"0x{int(row['link_va']):08X}" for row in target_rows],
        "first_guest_link_va": f"0x{int(checkpoint['link_va']):08X}" if checkpoint else None,
        "first_guest_mapping_valid": checkpoint is not None,
        "event_count": len(rows),
        "trace_bytes": len(raw),
        "timeout_or_no_present": not order_valid,
    }


def build_evidence() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    prior_path = root / "evidence/w3_267_viewport_hash.json"
    prior = json.loads(prior_path.read_text(encoding="utf-8"))
    return {
        "schema": "w3-269-post-present-guest-checkpoint/v1",
        "task": "W3-269",
        "evidence_level": "INCONCLUSIVE",
        "prior_viewport": {
            "path": "evidence/w3_267_viewport_hash.json",
            "sha256": __import__("hashlib").sha256(prior_path.read_bytes()).hexdigest(),
            "target_sha256": prior["provenance"]["target_sha256"],
            "source_run_id": prior["run_id"],
            "viewport_hash_fnv1a64": prior["trace"]["events"][3]["fnv1a64"],
            "same_invocation_as_new_run": False,
        },
        "replay": {
            "run_id": None,
            "staging_revision": None,
            "instrumented_binary_sha256": None,
            "fixture_sha256": None,
            "config_sha256": None,
            "cue_sha256": None,
            "guard": None,
            "trace": None,
            "analysis": None,
        },
        "scope": {
            "original_replays_this_task": 0,
            "all_dosbox_via_oracle_guard": True,
            "global_trace": False,
            "bulk_memdump": False,
            "guest_modified": False,
            "menu_verified": False,
            "gameplay_verified": False,
        },
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / "evidence/w3_269_post_present_checkpoint.json"
    path.write_text(json.dumps(build_evidence(), indent=2) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
