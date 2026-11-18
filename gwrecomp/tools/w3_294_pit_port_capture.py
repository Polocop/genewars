"""Bounded parser and validators for W3-294 original PIT port observations."""

from __future__ import annotations

import json
from typing import Any

MAX_TRACE_BYTES = 1_048_576
MAX_TRACE_ROWS = 4096
MAX_TARGET_EVENTS = 1024
PORT_EVENT = "W3_294_PIT_PORT_IO"
BRANCH_EVENT = "W3_294_PIT_LOOP_BRANCH"
CHECKPOINT_EVENT = "w3_269_first_guest_checkpoint_after_present"


def parse_trace(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds the 1 MiB cap")
    lines = raw.splitlines()
    if len(lines) > MAX_TRACE_ROWS:
        raise ValueError("trace exceeds the 4096-row cap")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid JSONL at row {number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"JSONL row {number} is not an object")
        rows.append(row)
    if len(rows) > MAX_TRACE_ROWS:
        raise ValueError("trace exceeds the 4096-row cap")
    return rows


def _integer(value: Any, field: str) -> int:
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"missing or invalid integer field: {field}") from exc


def analyze(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mappings = [row for row in rows if row.get("event") == "main_mapping" and row.get("mapping_matches") is True]
    if len(mappings) > 1:
        raise ValueError("fresh matching MAIN mapping was duplicated")
    if not mappings:
        if any(row.get("event") in (PORT_EVENT, BRANCH_EVENT) for row in rows):
            raise ValueError("targeted port/branch event exists without a fresh MAIN mapping")
        last = max((row for row in rows if isinstance(row.get("sequence"), int)),
                   key=lambda row: row["sequence"], default=None)
        return {
            "code_rebase": None,
            "fresh_main_mapping": None,
            "post_present_checkpoint": None,
            "port_events": [],
            "branch_events": [],
            "port_event_count": 0,
            "branch_event_count": 0,
            "complete_loop_iterations": 0,
            "sequence_complete": False,
            "last_emitted_event": last,
            "conclusion": "INCONCLUSIVE_MAIN_MAPPING_NOT_OBSERVED",
            "framebuffer_pixels_verified": False,
            "menu_verified": False,
            "gameplay_verified": False,
        }
    mapping = mappings[0]
    rebase = _integer(mapping.get("code_rebase"), "main_mapping.code_rebase")
    port_events = [row for row in rows if row.get("event") == PORT_EVENT]
    branch_events = [row for row in rows if row.get("event") == BRANCH_EVENT]
    if len(port_events) > MAX_TARGET_EVENTS or len(branch_events) > MAX_TARGET_EVENTS:
        raise ValueError("targeted event cap exceeded")
    if [int(row.get("ordinal", -1)) for row in port_events] != list(range(1, len(port_events) + 1)):
        raise ValueError("port event ordinals are not a contiguous prefix")
    if [int(row.get("ordinal", -1)) for row in branch_events] != list(range(1, len(branch_events) + 1)):
        raise ValueError("branch event ordinals are not a contiguous prefix")

    checkpoints = [row for row in rows if row.get("event") == CHECKPOINT_EVENT]
    if len(checkpoints) > 1:
        raise ValueError("post-present checkpoint was duplicated")
    checkpoint = checkpoints[0] if checkpoints else None
    if checkpoint:
        runtime = _integer(checkpoint.get("runtime_linear"), "checkpoint.runtime_linear")
        checkpoint_rebase = _integer(checkpoint.get("code_rebase"), "checkpoint.code_rebase")
        link = _integer(checkpoint.get("link_va"), "checkpoint.link_va")
        if checkpoint_rebase != rebase or runtime - rebase != link:
            raise ValueError("post-present checkpoint does not match fresh MAIN mapping")

    for row in port_events:
        runtime = _integer(row.get("instruction_runtime"), "port.instruction_runtime")
        link = _integer(row.get("link_va"), "port.link_va")
        event_rebase = _integer(row.get("code_rebase"), "port.code_rebase")
        operation = row.get("operation")
        port = _integer(row.get("port"), "port.port")
        width = _integer(row.get("width"), "port.width")
        value = _integer(row.get("value"), "port.value")
        if runtime - rebase != link or event_rebase != rebase:
            raise ValueError("port event does not use the fresh MAIN runtime mapping")
        if operation == "OUT":
            expected = ("OUT", 0x43, 1, "e643")
        elif operation == "IN":
            expected = ("IN", 0x40, 1, "e440")
        else:
            raise ValueError("unexpected port operation")
        if operation == "OUT" and link != 0xC427A:
            raise ValueError("OUT event is outside the measured instruction")
        if operation == "IN" and link not in (0xC427E, 0xC4282):
            raise ValueError("IN event is outside the measured loop")
        if (operation, port, width) != expected[:3] or row.get("instruction_bytes") != expected[3]:
            raise ValueError("port event does not match hash-verified instruction bytes")
        if not 0 <= value <= 0xff or not isinstance(row.get("io_completed"), bool):
            raise ValueError("invalid byte value or I/O completion flag")

    for row in branch_events:
        runtime = _integer(row.get("instruction_runtime"), "branch.instruction_runtime")
        link = _integer(row.get("link_va"), "branch.link_va")
        dest_runtime = _integer(row.get("destination_runtime"), "branch.destination_runtime")
        dest_link = _integer(row.get("destination_link_va"), "branch.destination_link_va")
        if runtime - rebase != link or link != 0xC4293 or dest_runtime - rebase != dest_link:
            raise ValueError("branch event mapping is inconsistent")
        if dest_link != (0xC4272 if row.get("taken") is True else 0xC4295):
            raise ValueError("JNE destination does not match the observed branch outcome")

    merged = sorted(
        [(int(row.get("sequence", index)), "port", row) for index, row in enumerate(port_events)] +
        [(int(row.get("sequence", index)), "branch", row) for index, row in enumerate(branch_events)],
        key=lambda item: item[0],
    )
    state = "expect_out"
    completed_iterations = 0
    sequence_complete = False
    for _, kind, row in merged:
        if kind == "port":
            link = _integer(row["link_va"], "port.link_va")
            if state == "expect_out" and row["operation"] == "OUT" and link == 0xC427A:
                state = "expect_first_in"
            elif state == "expect_first_in" and row["operation"] == "IN" and link == 0xC427E:
                state = "expect_second_in"
            elif state == "expect_second_in" and row["operation"] == "IN" and link == 0xC4282:
                state = "expect_branch"
        elif state == "expect_branch" and _integer(row.get("link_va"), "branch.link_va") == 0xC4293:
            if row.get("taken") is True:
                completed_iterations += 1
                state = "expect_out"
            else:
                completed_iterations += 1
                sequence_complete = True
                state = "done"
                break

    last = max((row for row in rows if isinstance(row.get("sequence"), int)),
               key=lambda row: row["sequence"], default=None)
    if sequence_complete:
        conclusion = "ORIGINAL_PIT_SEQUENCE_OBSERVED"
    elif port_events:
        conclusion = "PARTIAL_ORIGINAL_PIT_SEQUENCE"
    elif checkpoint:
        conclusion = "POST_PRESENT_CHECKPOINT_REACHED_PORT_CALLBACK_NOT_OBSERVED"
    else:
        conclusion = "INCONCLUSIVE_TARGET_SEQUENCE_NOT_REACHED"
    return {
        "code_rebase": rebase,
        "fresh_main_mapping": mapping,
        "post_present_checkpoint": checkpoint,
        "port_events": port_events,
        "branch_events": branch_events,
        "port_event_count": len(port_events),
        "branch_event_count": len(branch_events),
        "complete_loop_iterations": completed_iterations,
        "sequence_complete": sequence_complete,
        "last_emitted_event": last,
        "conclusion": conclusion,
        "framebuffer_pixels_verified": False,
        "menu_verified": False,
        "gameplay_verified": False,
    }
