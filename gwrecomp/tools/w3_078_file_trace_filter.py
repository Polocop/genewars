"""Exact event filtering and checkpoint summaries for W3-078."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

SUPPRESS_WHEN_FILE_IO_DISABLED = {
    "dos_file_read", "dos_file_seek", "dos_file_read_batch",
}
TARGET_CHECKPOINTS = {
    "MAIN_ENTRY_CHECKPOINT", "MAIN_GATE_CHECKPOINT", "SETUP_GAME_ENTRY",
    "SETUP_FIRST_CALLEE", "PLAYINTRO_ENTRY", "PLAYINTRO_CALLSITE",
    "GAME_CALLSITE", "GAME_RETURN_CONTINUATION", "VIDEO_SCREEN_SETUP_ANY_MODE",
    "VIDEO_VESA_MODE_CALLSITE", "VIDEO_VESA_SET_MODE_ENTRY",
    "VIDEO_VESA_SET_PAGE_ENTRY", "VIDEO_INT10_FIRST_ENTRY",
    "VIDEO_INT10_FIRST_RETURN", "VIDEO_INT10_SECOND_ENTRY",
    "VIDEO_INT10_SECOND_RETURN", "VIDEO_FRAMEBUFFER_ASSIGN_BEFORE",
    "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
}


def should_append_event(event_name: str, file_io_enabled: bool) -> bool:
    return file_io_enabled or event_name not in SUPPRESS_WHEN_FILE_IO_DISABLED


def summarize_events(events: Iterable[dict]) -> dict:
    ordered = sorted(events, key=lambda event: event.get("sequence", 0))
    counts = Counter(event.get("event", "unknown") for event in ordered)
    checkpoints = [event for event in ordered
                   if event.get("event") == "target_runtime_checkpoint"
                   and event.get("checkpoint") in TARGET_CHECKPOINTS]
    return {
        "event_count": len(ordered),
        "event_counts": dict(sorted(counts.items())),
        "target_checkpoints": checkpoints,
        "last_target_checkpoint": checkpoints[-1] if checkpoints else None,
        "dos_file_io_events": sum(counts[name] for name in SUPPRESS_WHEN_FILE_IO_DISABLED),
    }
