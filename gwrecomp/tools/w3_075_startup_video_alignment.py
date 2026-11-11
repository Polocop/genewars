"""Bounded selection of startup continuation and VESA page events."""
from __future__ import annotations

from collections.abc import Iterable

STARTUP_CHECKPOINTS = {
    "PLAYINTRO_ENTRY", "PLAYINTRO_CALLSITE", "GAME_CALLSITE",
    "GAME_RETURN_CONTINUATION",
}
PAGE_CHECKPOINTS = {
    "VIDEO_FRAMEBUFFER_ASSIGN_AFTER", "VIDEO_VESA_SET_PAGE_ENTRY",
    "VIDEO_INT10_FIRST_ENTRY", "VIDEO_INT10_FIRST_RETURN",
    "VIDEO_INT10_SECOND_ENTRY", "VIDEO_INT10_SECOND_RETURN",
}
ALL_CHECKPOINTS = STARTUP_CHECKPOINTS | PAGE_CHECKPOINTS


def first_startup_video_events(events: Iterable[dict], limit: int = 10) -> list[dict]:
    if limit < 0 or limit > len(ALL_CHECKPOINTS):
        raise ValueError("event limit exceeds selected checkpoint set")
    found: dict[str, dict] = {}
    for event in events:
        name = event.get("checkpoint")
        if name in ALL_CHECKPOINTS and name not in found and len(found) < limit:
            found[name] = event
    return sorted(found.values(), key=lambda event: event.get("sequence", 0))
