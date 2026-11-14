"""Pure helpers for bounded setup_game this-slot checkpoints."""
from __future__ import annotations

from collections.abc import Iterable

SITES = {
    0x94AC0: "SETUP_GAME_ENTRY",
    0x94B51: "SETUP_THIS_GLOBAL_READ",
    0x94B5A: "SETUP_THIS_GLOBAL_WRITE",
}
THIS_LINK_OFFSET = 0x114CA8


def runtime_address(link_va: int, code_rebase: int | None) -> int | None:
    if code_rebase is None or code_rebase < 0 or link_va < 0:
        return None
    address = code_rebase + link_va
    return address if address <= 0xFFFFFFFF else None


def this_linear_address(data_rebase: int | None,
                        data_segment_base: int | None) -> int | None:
    if data_rebase is None or data_segment_base is None:
        return None
    if data_rebase < 0 or data_segment_base < 0:
        return None
    address = data_segment_base + data_rebase + THIS_LINK_OFFSET
    return address if address <= 0xFFFFFFFF else None


def select_first_checkpoints(events: Iterable[dict]) -> dict[str, dict | None]:
    selected: dict[str, dict | None] = {name: None for name in SITES.values()}
    for event in events:
        name = event.get("checkpoint")
        if name in selected and selected[name] is None:
            selected[name] = event
    return selected


def sample_this_value(event: dict) -> int | None:
    for sample in event.get("selected_global_samples", []):
        if sample.get("link_offset") == THIS_LINK_OFFSET:
            return sample.get("value_u32")
    return None
