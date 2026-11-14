"""Host-side model and parser for the bounded W3-106 caller-chain capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


ORDER = (
    (0x92710,),
    (0x928A0,),
    (0x834C0,),
    (0x83985, 0x839A2),
    (0x9FFE0,),
    (0xA0049,),
    (0xA3A5C,),
    (0xA3A91,),
    (0xA3A93,),
    (0xA3AB7,),
    (0xA3AB9,),
)
CAP = 12


@dataclass
class FilterState:
    stage: int = 0
    complete: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)


def accept(state: FilterState, link_va: int, event: dict[str, Any] | None = None) -> bool:
    if state.complete or state.stage >= len(ORDER) or len(state.events) >= CAP:
        return False
    if link_va not in ORDER[state.stage]:
        return False
    state.events.append(event or {"link_va": link_va})
    state.stage += 1
    if state.stage == len(ORDER):
        state.complete = True
    return True


def parse_target_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = [row for row in rows if row.get("w3_106_targeted_game_page") is True]
    return selected[:CAP]


def sequence_matches(links: list[int]) -> bool:
    for index, address in enumerate(links):
        if index >= len(ORDER) or address not in ORDER[index]:
            return False
    return True


def validate_mapping(event: dict[str, Any], expected_rebase: int | None = None) -> int:
    link = event.get("link_va")
    runtime = event.get("eip", event.get("runtime_eip"))
    if not isinstance(link, int) or not isinstance(runtime, int):
        raise ValueError("link VA and runtime EIP must be present as integers")
    rebase = runtime - link
    if expected_rebase is not None and rebase != expected_rebase:
        raise ValueError("event mapping differs from the measured mapping")
    return rebase
