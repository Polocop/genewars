"""Pure bounded event selection for the original VESA page/INT10 frontier."""
from __future__ import annotations

from collections.abc import Iterable

PAGE_CHECKPOINTS = {
    "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
    "VIDEO_VESA_SET_PAGE_ENTRY",
    "VIDEO_INT10_FIRST_ENTRY",
    "VIDEO_INT10_FIRST_RETURN",
    "VIDEO_INT10_SECOND_ENTRY",
    "VIDEO_INT10_SECOND_RETURN",
}


def first_page_events(events: Iterable[dict], limit: int = 6) -> list[dict]:
    if limit < 0 or limit > len(PAGE_CHECKPOINTS):
        raise ValueError("page event limit exceeds selected site set")
    found: dict[str, dict] = {}
    for event in events:
        name = event.get("checkpoint")
        if name in PAGE_CHECKPOINTS and name not in found and len(found) < limit:
            found[name] = event
    return sorted(found.values(), key=lambda event: event.get("sequence", 0))


def framebuffer_value(event: dict) -> int | None:
    for sample in event.get("framebuffer_global_samples", []):
        if sample.get("link_offset") == 0x19CA58:
            return sample.get("value_u32")
    return None
