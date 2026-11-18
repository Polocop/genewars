"""Bounded, source-backed validation for W3-264 renderer evidence."""
from __future__ import annotations

import json
from typing import Any

MAX_TRACE_BYTES = 1_048_576
MAX_EVENTS = 128
MAX_READBACK_BYTES = 1_048_576
BYTES_PER_PIXEL = 3
CHAINED_VGA_WINDOW_BYTES = 0x10000


def sample_region(width: int, height: int, cap_bytes: int = MAX_READBACK_BYTES) -> tuple[int, int, int]:
    if width <= 0 or height <= 0 or cap_bytes < BYTES_PER_PIXEL:
        raise ValueError("invalid dimensions or byte cap")
    max_pixels = cap_bytes // BYTES_PER_PIXEL
    sample_width = min(width, max_pixels)
    sample_height = min(height, max_pixels // sample_width)
    if sample_width <= 0 or sample_height <= 0:
        raise ValueError("sample region is empty")
    return sample_width, sample_height, sample_width * sample_height * BYTES_PER_PIXEL


def chained_vga_backing_offset(guest_offset: int) -> int:
    if not 0 <= guest_offset < CHAINED_VGA_WINDOW_BYTES:
        raise ValueError("guest offset is outside A0000's 64 KiB aperture")
    return ((guest_offset & ~3) << 2) + (guest_offset & 3)


def fnv1a64(data: bytes) -> int:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def parse_trace(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 1 MiB")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSONL line {line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"JSONL line {line_number} is not an object")
        rows.append(row)
        if len(rows) > MAX_EVENTS:
            raise ValueError("trace exceeds 128 events")
    return rows


def validate_opengl_event(event: dict[str, Any]) -> bool:
    if event.get("event") != "opengl_backbuffer_pre_swap":
        return False
    width = event.get("drawable_width_px", 0)
    height = event.get("drawable_height_px", 0)
    sw = event.get("sample_width_px", 0)
    sh = event.get("sample_height_px", 0)
    size = event.get("sample_bytes", 0)
    if not all(isinstance(v, int) and v > 0 for v in (width, height, sw, sh, size)):
        return False
    return bool(
        sw <= width and sh <= height and
        size == sw * sh * BYTES_PER_PIXEL and size <= MAX_READBACK_BYTES and
        isinstance(event.get("fnv1a64"), int) and
        event.get("gl_error_queried") is False and
        event.get("gl_status") == "readback_issued; error queue not consumed" and
        event.get("full_frame_covered") == (sw == width and sh == height)
    )


def analyze_trace(rows: list[dict[str, Any]]) -> dict[str, Any]:
    opengl = [row for row in rows if row.get("event") == "opengl_backbuffer_pre_swap"]
    if len(opengl) > 1:
        raise ValueError("duplicate OpenGL pre-swap event")
    copies = [row for row in rows if row.get("event") == "copy_post"]
    if len(copies) > 1:
        raise ValueError("duplicate copy_post event")
    copy = copies[0] if copies else None
    mapped = copy.get("guest_a0000_backing") if copy else None
    event_names = [row.get("event") for row in rows]
    opengl_index = next((i for i, row in enumerate(rows)
                         if row.get("event") == "opengl_backbuffer_pre_swap"), None)
    main_index = next((i for i, row in enumerate(rows)
                       if row.get("event") == "main_mapping"), None)
    copy_index = next((i for i, row in enumerate(rows)
                       if row.get("event") == "copy_post"), None)
    return {
        "event_order": event_names,
        "main_mapping": next((r for r in rows if r.get("event") == "main_mapping"), None),
        "copy_post": copy,
        "guest_a0000_backing_valid": bool(mapped and mapped.get("valid") is True),
        "opengl_backbuffer": opengl[0] if opengl else None,
        "opengl_event_valid": bool(opengl and validate_opengl_event(opengl[0])),
        "renderer_pixels_proven": bool(opengl and validate_opengl_event(opengl[0]) and
                                        opengl[0].get("nonzero_pixels", 0) > 0),
        "first_opengl_event_precedes_main_mapping": bool(
            opengl_index is not None and main_index is not None and opengl_index < main_index),
        "first_opengl_event_precedes_a0000_copy": bool(
            opengl_index is not None and copy_index is not None and opengl_index < copy_index),
        "game_frame_attribution_proven": False,
        "visible_screenshot_proven": False,
    }
