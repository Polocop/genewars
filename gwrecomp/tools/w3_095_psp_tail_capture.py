"""Fail-closed validation for the bounded PSP command-tail observation."""
from __future__ import annotations

import json
from dataclasses import dataclass

PSP_BYTES = 0x100
TAIL_OFFSET = 0x80
MAX_TAIL_BYTES = 126
MAX_EVENTS = 1


@dataclass(frozen=True)
class TailSample:
    status: str
    psp_segment: int
    next_segment: int
    length: int
    tail_hex: str
    cr_present: bool
    valid: bool


def sample_tail(psp_segment: int, next_segment: int, psp_bytes: bytes) -> TailSample:
    """Validate a synthetic PSP image and return its bounded command tail."""
    if not (0 < psp_segment <= 0xFFFF and psp_segment < next_segment <= 0x10000):
        return TailSample("invalid_psp_segment", psp_segment, next_segment, 0, "", False, False)
    if next_segment - psp_segment < PSP_BYTES // 16:
        return TailSample("psp_range_invalid", psp_segment, next_segment, 0, "", False, False)
    if (psp_segment << 4) + PSP_BYTES > 0x100000:
        return TailSample("psp_range_invalid", psp_segment, next_segment, 0, "", False, False)
    if len(psp_bytes) < PSP_BYTES:
        return TailSample("psp_image_too_short", psp_segment, next_segment, 0, "", False, False)
    length = psp_bytes[TAIL_OFFSET]
    if length > MAX_TAIL_BYTES:
        return TailSample("length_exceeds_dos_psp_limit", psp_segment, next_segment, 0, "", False, False)
    start = TAIL_OFFSET + 1
    stop = start + length
    if stop >= PSP_BYTES:
        return TailSample("tail_range_invalid", psp_segment, next_segment, 0, "", False, False)
    tail = psp_bytes[start:stop]
    cr_present = psp_bytes[stop] == 0x0D
    return TailSample("sampled", psp_segment, next_segment, length, tail.hex(), cr_present, True)


def bounded_jsonl_event(event: dict, seen: int) -> tuple[str | None, int]:
    """Serialize at most one valid event, returning compact JSON and new count."""
    if seen >= MAX_EVENTS:
        return None, seen
    serialized = json.dumps(event, separators=(",", ":"), sort_keys=True)
    json.loads(serialized)
    return serialized, seen + 1
