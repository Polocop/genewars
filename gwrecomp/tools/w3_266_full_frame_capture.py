"""Synthetic validation for the bounded W3-266 renderer frame record."""
from __future__ import annotations

from typing import Any

MAX_FRAME_BYTES = 1_048_576


def valid_renderer_input(event: dict[str, Any]) -> bool:
    width = event.get("renderer_input_width_px", 0)
    height = event.get("renderer_input_height_px", 0)
    byte_count = event.get("renderer_input_bytes", 0)
    return bool(
        event.get("renderer_input_full_frame_valid") is True and
        event.get("renderer_input_full_coverage") is True and
        isinstance(width, int) and width > 0 and
        isinstance(height, int) and height > 0 and
        isinstance(byte_count, int) and byte_count == width * height * 4 and
        byte_count <= MAX_FRAME_BYTES and
        event.get("renderer_input_pitch_bytes") == width * 4 and
        isinstance(event.get("renderer_input_fnv1a64"), int) and
        isinstance(event.get("renderer_input_nonzero_pixels"), int)
    )


def valid_visible_output_rect(event: dict[str, Any]) -> bool:
    try:
        canvas_w = float(event["canvas_width_px"])
        canvas_h = float(event["canvas_height_px"])
        x = float(event["visible_output_x_px"])
        y = float(event["visible_output_y_px"])
        width = float(event["visible_output_width_px"])
        height = float(event["visible_output_height_px"])
    except (KeyError, TypeError, ValueError):
        return False
    return bool(
        canvas_w > 0 and canvas_h > 0 and width > 0 and height > 0 and
        x >= 0 and y >= 0 and x + width <= canvas_w and y + height <= canvas_h
    )


def validate_same_present(rows: list[dict[str, Any]]) -> dict[str, Any]:
    names = [row.get("event") for row in rows]
    expected = ("main_mapping", "copy_pre", "copy_post",
                "opengl_backbuffer_pre_swap", "backend_present_return")
    indices = []
    for name in expected:
        try:
            indices.append(names.index(name))
        except ValueError:
            return {"valid": False, "reason": f"missing {name}"}
    main, copy, gl, backend = (rows[indices[i]] for i in (0, 2, 3, 4))
    backing = copy.get("guest_a0000_backing", {})
    valid = bool(
        indices == sorted(indices) and
        all(names.count(name) == 1 for name in expected) and
        main.get("mapping_matches") is True and copy.get("mapping_matches") is True and
        copy.get("full_copy_valid") is True and backing.get("valid") is True and
        gl.get("copy_capture_armed") is True and
        valid_renderer_input(gl) and valid_visible_output_rect(backend)
    )
    return {"valid": valid, "reason": "same-run post-copy frame and viewport verified" if valid else "capture contract validation failed",
            "event_order": names, "renderer_input_full_frame_valid": valid_renderer_input(gl),
            "viewport_rect_valid": valid_visible_output_rect(backend)}
