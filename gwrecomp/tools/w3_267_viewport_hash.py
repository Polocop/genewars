"""Synthetic validation for the bounded W3-267 post-shader viewport hash."""
from __future__ import annotations

from typing import Any

MAX_CHUNK_BYTES = 1_048_576
MAX_TOTAL_BYTES = 6 * 1_048_576


def plan_scanline_chunks(width: int, height: int, bytes_per_pixel: int = 3) -> list[dict[str, int]]:
    if width <= 0 or height <= 0 or bytes_per_pixel <= 0:
        raise ValueError("viewport dimensions must be positive")
    row_bytes = width * bytes_per_pixel
    total_bytes = row_bytes * height
    if row_bytes > MAX_CHUNK_BYTES or total_bytes > MAX_TOTAL_BYTES:
        raise ValueError("viewport exceeds bounded streaming limits")
    rows_per_chunk = MAX_CHUNK_BYTES // row_bytes
    chunks = []
    row_start = 0
    while row_start < height:
        rows = min(rows_per_chunk, height - row_start)
        chunks.append({"row_start": row_start, "rows": rows, "bytes": rows * row_bytes})
        row_start += rows
    return chunks


def validate_chunk_coverage(chunks: list[dict[str, int]], height: int,
                            row_bytes: int, total_bytes: int) -> bool:
    next_row = 0
    bytes_covered = 0
    for chunk in chunks:
        if chunk.get("row_start") != next_row:
            return False
        rows = chunk.get("rows", 0)
        size = chunk.get("bytes", 0)
        if rows <= 0 or size != rows * row_bytes or size > MAX_CHUNK_BYTES:
            return False
        next_row += rows
        bytes_covered += size
    return next_row == height and bytes_covered == total_bytes and total_bytes <= MAX_TOTAL_BYTES


def valid_viewport_event(event: dict[str, Any]) -> bool:
    try:
        width = int(event["sample_width_px"])
        height = int(event["sample_height_px"])
        byte_count = int(event["sample_bytes"])
        chunks = int(event["readback_chunk_count"])
    except (KeyError, TypeError, ValueError):
        return False
    if width <= 0 or height <= 0 or byte_count != width * height * 3:
        return False
    try:
        plan = plan_scanline_chunks(width, height)
    except ValueError:
        return False
    return bool(
        byte_count <= MAX_TOTAL_BYTES and chunks == len(plan) and
        event.get("max_readback_bytes") == MAX_CHUNK_BYTES and
        event.get("max_total_readback_bytes") == MAX_TOTAL_BYTES and
        event.get("full_visible_viewport_covered") is True and
        isinstance(event.get("fnv1a64"), int) and
        validate_chunk_coverage(plan, height, width * 3, byte_count)
    )


def same_visible_rect(gl: dict[str, Any], backend: dict[str, Any]) -> bool:
    return bool(
        gl.get("sample_x_px") == backend.get("visible_output_x_px") and
        gl.get("sample_y_px") == backend.get("visible_output_y_px") and
        gl.get("sample_width_px") == backend.get("visible_output_width_px") and
        gl.get("sample_height_px") == backend.get("visible_output_height_px")
    )


def analyze_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    names = [row.get("event") for row in rows]
    required = ("main_mapping", "copy_pre", "copy_post",
                "opengl_backbuffer_pre_swap", "backend_present_return")
    if any(names.count(name) != 1 for name in required):
        return {"same_run_full_frame_verified": False,
                "reason": "missing or duplicate required checkpoint"}
    main = next(row for row in rows if row.get("event") == "main_mapping")
    copy_pre = next(row for row in rows if row.get("event") == "copy_pre")
    copy_post = next(row for row in rows if row.get("event") == "copy_post")
    gl = next(row for row in rows if row.get("event") == "opengl_backbuffer_pre_swap")
    backend = next(row for row in rows if row.get("event") == "backend_present_return")
    geometry_matches = same_visible_rect(gl, backend)
    postshader_valid = valid_viewport_event(gl) and geometry_matches
    try:
        ordered = names.index("main_mapping") < names.index("copy_pre") < \
                names.index("copy_post") < names.index("opengl_backbuffer_pre_swap") < \
                names.index("backend_present_return")
    except ValueError:
        ordered = False
    mapping_valid = main.get("mapping_matches") is True
    copy_valid = (copy_post.get("mapping_matches") is True and
                  copy_post.get("full_copy_valid") is True and
                  copy_post.get("guest_a0000_backing", {}).get("valid") is True)
    input_valid = (gl.get("renderer_input_full_frame_valid") is True and
                   gl.get("renderer_input_full_coverage") is True and
                   0 < gl.get("renderer_input_bytes", MAX_CHUNK_BYTES + 1) <= MAX_CHUNK_BYTES)
    copy_armed = gl.get("copy_capture_armed") is True
    present_returned = backend.get("present_method_returned") is True
    valid = ordered and mapping_valid and copy_valid and input_valid and copy_armed and postshader_valid and present_returned
    return {
        "event_order": names,
        "main_mapping_valid": mapping_valid,
        "a0000_copy_valid": copy_valid,
        "renderer_input_full_frame_valid": input_valid,
        "copy_capture_armed": copy_armed,
        "postshader_viewport_valid": postshader_valid,
        "viewport_matches_backend_clip": geometry_matches,
        "backend_present_returned": present_returned,
        "same_run_full_frame_verified": valid,
        "desktop_screenshot_proven": False,
        "reason": "all same-run bounds and order verified" if valid else "capture validation failed",
    }
