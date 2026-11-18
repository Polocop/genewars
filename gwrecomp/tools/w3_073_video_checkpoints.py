"""Pure bounded parsing helpers for the natural GeneWars video frontier."""
from __future__ import annotations

from collections.abc import Iterable

VIDEO_SITES = {
    0x9FD40: "VIDEO_SCREEN_SETUP_ANY_MODE",
    0x9FDCC: "VIDEO_VESA_MODE_CALLSITE",
    0x9FDEF: "VIDEO_FRAMEBUFFER_ASSIGN_BEFORE",
    0x9FDF9: "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
    0xA3A00: "VIDEO_VESA_SET_MODE_ENTRY",
    0xA3A5C: "VIDEO_VESA_SET_PAGE_ENTRY",
    0xA3A91: "VIDEO_INT10_FIRST_ENTRY",
    0xA3A93: "VIDEO_INT10_FIRST_RETURN",
    0xA3AB7: "VIDEO_INT10_SECOND_ENTRY",
    0xA3AB9: "VIDEO_INT10_SECOND_RETURN",
}
FRAMEBUFFER_GLOBAL_LINK = 0x19CA58


def runtime_address(link_va: int, code_rebase: int | None) -> int | None:
    if code_rebase is None or code_rebase < 0 or link_va < 0:
        return None
    address = code_rebase + link_va
    return address if address <= 0xFFFFFFFF else None


def first_video_events(events: Iterable[dict], limit: int = 10) -> list[dict]:
    if limit < 0 or limit > len(VIDEO_SITES):
        raise ValueError("video event limit exceeds the known checkpoint set")
    found: dict[str, dict] = {}
    for event in events:
        name = event.get("checkpoint")
        if name in VIDEO_SITES.values() and name not in found and len(found) < limit:
            found[name] = event
    return sorted(found.values(), key=lambda event: event.get("sequence", 0))


def global_sample(event: dict, link_offset: int = FRAMEBUFFER_GLOBAL_LINK) -> dict | None:
    samples = list(event.get("framebuffer_global_samples", []))
    samples.extend(event.get("selected_global_samples", []))
    for sample in samples:
        if sample.get("link_offset") == link_offset:
            return sample
    return None
