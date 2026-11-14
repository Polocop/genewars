"""Pure helpers for the bounded W3-093 DS:EDX evidence parser."""

from __future__ import annotations

from typing import Any


MAX_SAMPLE_BYTES = 32


def sample_range_is_safe(
    *,
    selector: int,
    descriptor_valid: bool,
    present: bool,
    readable_data: bool,
    base: int,
    limit: int,
    offset: int,
    length: int,
) -> bool:
    """Return whether the descriptor proves a bounded readable sample range."""
    if selector == 0 or not descriptor_valid or not present or not readable_data:
        return False
    if not (1 <= length <= MAX_SAMPLE_BYTES):
        return False
    if min(base, limit, offset) < 0 or max(base, offset, length) > 0xFFFFFFFF:
        return False
    if offset > limit or length - 1 > limit - offset:
        return False
    linear = base + offset
    return linear <= 0xFFFFFFFF and length - 1 <= 0xFFFFFFFF - linear


def correlated_sample(cpu_events: list[dict[str, Any]], callbacks: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pair only a verified MAIN callsite sample with same PSP and callback ordinal."""
    by_key = {
        (int(c.get("process_psp", -1)), int(c.get("ordinal", -1))): c
        for c in callbacks
    }
    for event in cpu_events:
        if (
            event.get("mapping_valid") is not True
            or event.get("int21_bytes_verified") is not True
            or event.get("int_instruction_link_va") != 821619  # 0xC8973
            or event.get("sample_status") != "sampled"
        ):
            continue
        key = (
            int(event.get("process_psp", -1)),
            int(event.get("setup_dos_api_callback_ordinal", -1)),
        )
        callback = by_key.get(key)
        if callback is None:
            continue
        if callback.get("operation") != "INT21_AH44":
            continue
        if int(callback.get("in_ax", -1)) != 0x4400 or int(callback.get("in_bx", -1)) != 1:
            continue
        return {"cpu_entry": event, "callback": callback}
    return None

