#!/usr/bin/env python3
"""Validate the preserved W1-092 native allocator replay receipt."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys


def verify(path: pathlib.Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != "gwrecomp.native-dpmi-allocator-lifecycle-w1-092/v2":
        raise ValueError("unexpected W1-092 evidence schema")
    if data.get("task") != "W1-092" or data.get("fresh_replay") is not True:
        raise ValueError("receipt is not a fresh W1-092 replay")
    if data.get("execution_mode") != "native_recompiled_guest" or data.get("evidence_level") != "NATIVE_REACHED":
        raise ValueError("receipt is not native replay evidence")
    if data.get("original_equivalence_claimed") is not False:
        raise ValueError("receipt overstates equivalence to the protected original")
    if data.get("target_sha256") != "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f":
        raise ValueError("canonical GeneWars 1.1 target hash mismatch")

    exe = path.resolve().parents[1] / "build" / "native_allocator_lifecycle_w1_092.exe"
    if hashlib.sha256(exe.read_bytes()).hexdigest() != data.get("build_sha256"):
        raise ValueError("receipt build hash does not match the native executable")
    memory = data.get("guest_memory_map", {})
    begin = int(memory.get("allocation_begin", "0"), 16)
    end = int(memory.get("allocation_end", "0"), 16)
    capacity = int(memory.get("guest_capacity", "0"), 16)
    if (memory.get("kind") != "host_backed" or memory.get("backing") != "VirtualAlloc_commit_on_allocate" or
            memory.get("lifetime") != "process_virtual_reservation" or begin != 0x200000 or
            end != capacity or capacity <= begin or int(memory.get("image_end", "0"), 16) > begin):
        raise ValueError("host-backed guest memory map is inconsistent")

    events = data.get("allocation_events", [])
    count = int(data.get("allocation_event_count", 0))
    if not events or count <= len(events):
        raise ValueError("full callback count or sampled trace is missing")
    ordinals = [int(event["ordinal"]) for event in events]
    if ordinals != sorted(set(ordinals)) or ordinals[-1] + 1 != count:
        raise ValueError("sample ordinals do not preserve the complete callback count")
    if data.get("event_sampling") != "all successes plus failures every 256 ordinals and the final event":
        raise ValueError("unexpected AX=0501 sample policy")
    if data.get("zero_fill_basis") != "VirtualAlloc MEM_COMMIT zero-fill guarantee plus first/last byte checks":
        raise ValueError("zero-fill evidence basis is missing")
    if data.get("native_compiler_options") != ["-O2", "-fwrapv", "-fno-strict-aliasing"]:
        raise ValueError("optimized native replay compiler options are missing")

    ranges: list[tuple[int, int]] = []
    handles: set[int] = set()
    successes = 0
    for event in events:
        size = int(event["size"], 16)
        requested = ((int(event["request_ebx"], 16) & 0xffff) << 16) | (int(event["request_ecx"], 16) & 0xffff)
        if (event.get("eip") != "000c3cc1" or event.get("request_eax") != "00000501" or
                event.get("provider") != "gw_dos_services_callback" or event.get("handled") != "1" or
                event.get("preserved") != "1" or size != requested):
            raise ValueError(f"AX=0501 event provenance/size mismatch at ordinal {event.get('ordinal')}")
        if event.get("success") == "1":
            base = int(event["base"], 16)
            handle = int(event["handle"], 16)
            if (event.get("carry") != "0" or event.get("response_eax") != event.get("request_eax") or
                    not handle or event.get("zero_filled") != "1" or base < begin or base + size > end or
                    base & 0xfff or int(event["cursor_after"], 16) != base + size):
                raise ValueError(f"invalid successful allocation at ordinal {event.get('ordinal')}")
            if handle in handles or any(base < right and left < base + size for left, right in ranges):
                raise ValueError("successful guest ranges or DPMI handles overlap/repeat")
            handles.add(handle)
            ranges.append((base, base + size))
            successes += 1
        elif event.get("unavailable") == "1":
            if (event.get("carry") != "1" or int(event["response_eax"], 16) & 0xffff != 0x8012 or
                    event.get("cursor_before") != event.get("cursor_after")):
                raise ValueError(f"invalid DPMI exhaustion result at ordinal {event.get('ordinal')}")
        else:
            raise ValueError(f"AX=0501 event has no outcome at ordinal {event.get('ordinal')}")
    sizes = [event["size"] for event in events if event.get("success") == "1"]
    if count != 4338 or sizes.count("01001000") != 255 or sizes.count("00ce8000") != 1 or len(sizes) != 256:
        raise ValueError("the complete 16 MiB probe and terminal partial allocation sequence changed")
    terminal = events[-1]
    if (int(terminal["ordinal"]) != 4337 or terminal.get("size") != "00010000" or
            terminal.get("unavailable") != "1"):
        raise ValueError("the natural terminal AX=0501 exhaustion event is missing")

    markers = data.get("allocator_events", [])
    seed = next((line for line in markers if line.startswith("NATIVE_DOS_MCB_SEED ")), None)
    ah48 = [line for line in markers if line.startswith("NATIVE_DOS_AH48 ordinal=")]
    if not seed or len(ah48) < 2 or any("cf=0 handled=1 provider=guest_mcb" not in line for line in ah48):
        raise ValueError("native guest MCB seed and two successful AH=48 events are required")
    frontier = data.get("next_frontier", {})
    progress = frontier.get("last_progress", {})
    heap_list = frontier.get("last_heap_list", {})
    if (frontier.get("kind") != "bounded_native_timeout" or progress.get("function") != "000ae0b0" or
            heap_list.get("nodes") != "258" or heap_list.get("next") != "00000000" or
            heap_list.get("stop") != "null"):
        raise ValueError("the bounded native allocator frontier or heap-list integrity evidence is missing")
    for key in ("vesa_reached", "lb_screen_setup_reached", "lb_screen_setup_any_mode_reached", "authentic_framebuffer_observed"):
        if data.get("graphics", {}).get(key) is not False:
            raise ValueError(f"graphics frontier field {key} is missing or inconsistent")
    return {"event_count": count, "sampled_events": len(events), "successes_sampled": successes,
            "guest_map_capacity": f"0x{capacity:08X}", "native_returncode": data.get("native_returncode"),
            "native_replay_timed_out": data.get("native_replay_timed_out"),
            "next_frontier": data.get("next_frontier")}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_w1_092_allocator_lifecycle.py EVIDENCE.json", file=sys.stderr)
        return 2
    try:
        result = verify(pathlib.Path(sys.argv[1]))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"FAIL W1-092 allocator evidence: {exc}", file=sys.stderr)
        return 1
    print("PASS W1-092 allocator evidence: " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
