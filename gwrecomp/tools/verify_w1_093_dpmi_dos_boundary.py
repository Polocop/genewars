from __future__ import annotations

import json
import pathlib
import re
import sys


def verify(path: pathlib.Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("task") != "W1-093" or data.get("evidence_level") != "NATIVE_REACHED":
        raise ValueError("W1-093 native-reached evidence identity is missing")
    if data.get("allocation_event_count") != 4338:
        raise ValueError("complete AX=0501 allocation sequence is missing")
    map_info = data.get("guest_memory_map", {})
    if map_info.get("guest_capacity") != "ffff0000":
        raise ValueError("host-backed guest map capacity changed")

    markers = data.get("allocator_events", [])
    seed = next((line for line in markers if line.startswith("NATIVE_DOS_MCB_SEED ")), "")
    fields = dict(re.findall(r"([a-z_]+)=([0-9a-fA-F]+)", seed))
    if (fields.get("free_data") != "0907" or fields.get("top") != "1000" or
            int(fields.get("free_data", "0"), 16) >= int(fields.get("top", "0"), 16)):
        raise ValueError("DOS MCB backing is not bounded below the fixed-link image")
    ah48 = [line for line in markers if line.startswith("NATIVE_DOS_AH48 ordinal=")]
    if len(ah48) != 2 or "response_eax=00000907" not in ah48[0] or "cf=0 handled=1" not in ah48[0]:
        raise ValueError("the one-paragraph guest MCB allocation is missing")
    if ("request_ebx=00001000" not in ah48[1] or "response_eax=00000008" not in ah48[1] or
            "response_ebx=000006f7" not in ah48[1] or "cf=1 handled=1" not in ah48[1]):
        raise ValueError("the bounded natural AH=48 insufficient-memory result changed")

    frontier = data.get("next_frontier", {})
    progress = frontier.get("last_progress", {})
    heap_list = frontier.get("last_heap_list", {})
    if progress.get("function") != "000ae0b0" or heap_list.get("stop") != "null" or heap_list.get("nodes") != "258":
        raise ValueError("the native allocator frontier or outer heap-list integrity is missing")
    snapshots = [line for line in markers if line.startswith("NATIVE_W1_093_BLOCK_SNAPSHOT ")]
    if not snapshots or not any("header=00000000" in line for line in snapshots):
        raise ValueError("the zero-header block snapshot at the allocator frontier is missing")
    graphics = data.get("graphics", {})
    if any(graphics.get(key) is not False for key in (
            "vesa_reached", "lb_screen_setup_reached", "lb_screen_setup_any_mode_reached",
            "authentic_framebuffer_observed")):
        raise ValueError("graphics reachability fields are inconsistent")
    return {"ax0501_events": data["allocation_event_count"],
            "guest_map_capacity": "0xFFFF0000",
            "dos_free_end_segment": fields["top"],
            "ah48_second_request": "failed naturally with AX=8/CF=1",
            "frontier": progress.get("function"),
            "guest_instructions": progress.get("guest_instructions"),
            "vesa_reached": graphics["vesa_reached"]}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_w1_093_dpmi_dos_boundary.py EVIDENCE.json", file=sys.stderr)
        return 2
    try:
        result = verify(pathlib.Path(sys.argv[1]))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"FAIL W1-093 DPMI/DOS boundary: {exc}", file=sys.stderr)
        return 1
    print("PASS W1-093 DPMI/DOS boundary: " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
