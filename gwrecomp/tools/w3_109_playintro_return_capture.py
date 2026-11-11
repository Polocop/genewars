"""Pure helpers for the bounded original PlayIntro return capture."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CAP = 12
TARGETS = {
    0x9FEAF, 0x962FC, 0x962FF, 0x92A11, 0x92A16, 0x92A24,
    0x92ADD, 0x92983, 0x92996, 0x929A9, 0x929C8, 0x94347,
}


@dataclass
class FilterState:
    armed: bool = False
    complete: bool = False
    seen: set[int] = field(default_factory=set)
    events: list[dict[str, Any]] = field(default_factory=list)


def arm_at_natural_main_entry(state: FilterState, link_va: int) -> None:
    if link_va == 0x93F30 and not state.complete:
        state.armed = True


def accept(state: FilterState, link_va: int, event: dict[str, Any] | None = None) -> bool:
    if state.complete or not state.armed or link_va not in TARGETS:
        return False
    if link_va in state.seen or len(state.events) >= CAP:
        return False
    state.seen.add(link_va)
    state.events.append(event if event is not None else {"link_va": link_va})
    if len(state.events) >= CAP or link_va == 0x94347:
        state.armed = False
        state.complete = True
    return True


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    import json

    rows = []
    for line in raw.splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def parse_target_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("w3_109_targeted_playintro_return") is True][:CAP]


def measured_rebase(event: dict[str, Any]) -> int:
    link = event.get("link_va")
    runtime = event.get("eip", event.get("runtime_eip"))
    if not isinstance(link, int) or not isinstance(runtime, int):
        raise ValueError("link VA and runtime EIP are required")
    rebase = runtime - link
    if rebase < 0:
        raise ValueError("runtime EIP precedes link VA")
    return rebase


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    rebases = sorted({measured_rebase(event) for event in events})
    return {
        "event_count": len(events),
        "link_vas": [f"0x{event['link_va']:08X}" for event in events],
        "rebases": [f"0x{value:08X}" for value in rebases],
        "mapping_consistent": len(rebases) <= 1,
        "last_observed_checkpoint": events[-1].get("checkpoint") if events else None,
    }
