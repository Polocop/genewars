"""Host-only helpers and source-coverage checks for W3-111."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tools.w3_110_hook_coverage_audit import extract_source_coverage, in_range

CAP = 12
TARGETS = (
    0x9FEAF, 0x962FC, 0x962FF, 0x92A11, 0x92A16, 0x92A24,
    0x92ADD, 0x92983, 0x92996, 0x929A9, 0x929C8, 0x94347,
)
PREVIOUS = {0x94342, 0x9FDF9}
PREREQUISITES = {
    0x92983: {0x94342},
    0x92A11: {0x92983},
    0x9FEAF: {0x92A11, 0x9FDF9},
    0x962FC: {0x9FEAF},
    0x962FF: {0x962FC},
    0x92A16: {0x962FF},
    0x92A24: {0x92A16},
    0x92ADD: {0x92A24},
    0x92996: {0x92ADD},
    0x929A9: {0x92996},
    0x929C8: {0x92ADD, 0x929A9},
    0x94347: {0x929C8},
}


@dataclass
class FilterState:
    armed: bool = False
    complete: bool = False
    seen: set[int] = field(default_factory=set)
    events: list[dict[str, Any]] = field(default_factory=list)


def observe_prior(state: FilterState, link_va: int) -> None:
    if link_va == 0x93F30:
        state.armed = True
    if link_va in PREVIOUS:
        state.seen.add(link_va)


def accept(state: FilterState, link_va: int, event: dict[str, Any] | None = None) -> bool:
    if state.complete or not state.armed or link_va not in TARGETS:
        return False
    if link_va in state.seen or len(state.events) >= CAP:
        return False
    if not PREREQUISITES[link_va].issubset(state.seen):
        return False
    state.seen.add(link_va)
    state.events.append(event if event is not None else {"link_va": link_va})
    if len(state.events) >= CAP or link_va == 0x94347:
        state.armed = False
        state.complete = True
    return True


def source_coverage(source: str) -> dict[int, dict[str, bool]]:
    coverage = extract_source_coverage(source)
    result = {}
    for link in TARGETS:
        selected = link in coverage["selected_capture_sites"]
        probed = link in coverage["video_probe_points"] or in_range(link, coverage["video_probe_ranges"])
        result[link] = {"selected": selected, "one_cycle": probed, "observable": selected and probed}
    return result


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    import json

    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def parse_target_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("w3_109_targeted_playintro_return") is True][:CAP]


def measured_rebase(event: dict[str, Any]) -> int:
    link = event.get("link_va")
    eip = event.get("eip", event.get("runtime_eip"))
    if not isinstance(link, int) or not isinstance(eip, int) or eip < link:
        raise ValueError("valid link VA and runtime EIP are required")
    return eip - link


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    rebases = sorted({measured_rebase(event) for event in events})
    return {
        "event_count": len(events),
        "link_vas": [f"0x{event['link_va']:08X}" for event in events],
        "rebases": [f"0x{value:08X}" for value in rebases],
        "mapping_consistent": len(rebases) <= 1,
    }
