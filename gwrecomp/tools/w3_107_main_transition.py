"""Host-only model for the bounded main_/PlayIntro/game filter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CAP = 14
TARGETS = {
    0x93F30: "main_entry", 0x9432F: "main_gate_before", 0x9433B: "main_gate_after",
    0x9433D: "setup_callsite", 0x94AC0: "setup_entry", 0x94AE9: "setup_return",
    0x94342: "playintro_callsite", 0x92930: "playintro_entry", 0x94347: "game_callsite",
    0x9434C: "game_return", 0x92710: "game_entry", 0x9FDCC: "late_mode_callsite",
    0xA3A00: "set_mode_entry", 0x9FDF9: "mode_continuation",
}


@dataclass
class FilterState:
    armed: bool = False
    complete: bool = False
    seen: set[int] = field(default_factory=set)
    events: list[dict[str, Any]] = field(default_factory=list)


def accept(state: FilterState, link_va: int, *, eax: int = 0, edx: int = 0,
           event: dict[str, Any] | None = None) -> bool:
    if state.complete or len(state.events) >= CAP or link_va not in TARGETS:
        return False
    if link_va == 0x9FDCC and ((eax & 0xFFFF) != 0x101 or edx != 0x180):
        return False
    if link_va != 0x93F30 and not state.armed:
        return False
    if link_va in state.seen:
        return False
    if link_va == 0xA3A00 and 0x9FDCC not in state.seen:
        return False
    if link_va == 0x9FDF9 and 0xA3A00 not in state.seen:
        return False
    state.seen.add(link_va)
    state.events.append(event or {"link_va": link_va})
    if link_va == 0x93F30:
        state.armed = True
    if len(state.events) == CAP:
        state.armed = False
        state.complete = True
    return True


def parse_target_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("w3_107_targeted_main_transition") is True][:CAP]


def measured_rebase(event: dict[str, Any]) -> int:
    link = event.get("link_va")
    runtime = event.get("eip", event.get("runtime_eip"))
    if not isinstance(link, int) or not isinstance(runtime, int):
        raise ValueError("link VA and runtime EIP are required")
    return runtime - link
