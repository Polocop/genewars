"""Bounded correlator for natural original AH=4400/BX=1 CPU callers."""
from __future__ import annotations

import json

MAX_TRACE_BYTES = 1_048_576
MAX_CPU_ENTRIES = 8
MAX_EVENTS = 512
TARGET_LINK_VA = 0xC8973
CPU_EVENT = "original_cpu_int21_ah44_bx1_entry"


class TraceLimitError(ValueError):
    pass


def _int(value):
    if isinstance(value, str):
        return int(value, 0)
    return value


def parse_trace(raw: bytes) -> list[dict]:
    if len(raw) > MAX_TRACE_BYTES:
        raise TraceLimitError("trace exceeds 1 MiB")
    events = []
    seen = set()
    cpu_count = 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("event")
        keep_cpu = kind == CPU_EVENT
        keep_callback = (
            kind == "setup_dos_api"
            and event.get("operation") == "INT21_AH44"
            and (_int(event.get("in_ax", 0)) & 0xFFFF) == 0x4400
            and (_int(event.get("in_bx", 0)) & 0xFFFF) == 1
        )
        if not (keep_cpu or keep_callback):
            continue
        if keep_cpu:
            cpu_count += 1
            if cpu_count > MAX_CPU_ENTRIES:
                raise TraceLimitError("AH=4400/BX=1 CPU entry cap exceeded")
        key = (event.get("sequence"), kind)
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
        if len(events) > MAX_EVENTS:
            raise TraceLimitError("filtered event count exceeds 512")
    return events


def summarize(events: list[dict]) -> dict:
    ordered = sorted(events, key=lambda e: _int(e.get("sequence", -1)))
    cpu_entries = [e for e in ordered if e.get("event") == CPU_EVENT]
    callbacks = [e for e in ordered if e.get("event") == "setup_dos_api"]
    pairs = []
    caller_entries = [e for e in cpu_entries
                      if e.get("mapping_valid") is True
                      and e.get("int21_bytes_verified") is True]
    for cpu in caller_entries:
        ordinal = _int(cpu.get("setup_dos_api_callback_ordinal", -1))
        callback = next((e for e in callbacks
                         if _int(e.get("ordinal", -2)) == ordinal
                         and e.get("process_psp") == cpu.get("process_psp")), None)
        if callback is None:
            continue
        mapping_valid = cpu.get("mapping_valid") is True
        opcode_valid = cpu.get("int21_bytes_verified") is True
        link = cpu.get("int_instruction_link_va")
        if link is not None:
            link = _int(link)
        pairs.append({
            "cpu_entry": cpu,
            "dos_callback": callback,
            "caller_mapping_valid": mapping_valid,
            "int21_bytes_verified": opcode_valid,
            "caller_int_instruction_link_va": link if opcode_valid else None,
            "matches_native_link_c8973": bool(opcode_valid and link == TARGET_LINK_VA),
            "response": {
                "ax": _int(callback.get("out_ax", 0)) & 0xFFFF,
                "dx": _int(callback.get("out_dx", 0)) & 0xFFFF,
                "cf": bool(callback.get("cf")),
                "handle": callback.get("entry"),
                "resolved_path": callback.get("resolved_path"),
                "cwd": callback.get("cwd"),
            },
        })
    return {
        "classification": "ORIGINAL_CALLER_AND_RESPONSE_CORRELATED" if pairs else "INCONCLUSIVE",
        "cpu_entries": cpu_entries,
        "protected_caller_entries": caller_entries,
        "unmapped_dispatch_entries": [e for e in cpu_entries if e not in caller_entries],
        "callbacks": callbacks,
        "pairs": pairs,
        "matches_native_link_c8973": any(p["matches_native_link_c8973"] for p in pairs),
        "caller_link_unknown": bool(callbacks) and not bool(pairs),
    }
