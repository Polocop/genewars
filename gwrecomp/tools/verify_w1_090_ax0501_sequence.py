#!/usr/bin/env python3
"""Validate W1-090 native AX=0501 sequence evidence and provenance."""
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA256 = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main():
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evidence" / "native_ax0501_sequence_w1_090.json"
    evidence = json.loads(path.read_text(encoding="utf-8"))
    require(evidence.get("target_sha256") == TARGET_SHA256, "target SHA-256 is not canonical GeneWars 1.1")
    require(evidence.get("native_returncode") == 0, "native replay did not return zero")
    sequence = evidence.get("w1_090_ax0501_sequence")
    require(isinstance(sequence, dict), "missing AX=0501 sequence evidence")
    require(sequence.get("provider") == "gw_dos_services_callback", "provider provenance mismatch")
    arena = sequence.get("arena", {})
    require(arena.get("kind") == "synthetic_test_only" and arena.get("not_original_mapping_evidence") is True,
            "synthetic arena is not explicitly distinguished from original memory")
    events = sequence.get("events", [])
    require(events and sequence.get("event_count") == len(events), "sequence event list is empty or count mismatches")
    for ordinal, event in enumerate(events):
        require(int(event.get("ordinal", -1)) == ordinal, f"event {ordinal} has a non-contiguous ordinal")
        require(event.get("vector") == "31" and int(event.get("eip", "0"), 16) == 0xC3CC1,
                f"event {ordinal} is not the natural AX=0501 site")
        require(event.get("request_eax") == "00000501" and int(event.get("request_edx", "0"), 16) == 0,
                f"event {ordinal} request contract is inconsistent")
        size = int(event["size"], 16)
        request_size = ((int(event["request_ebx"], 16) & 0xFFFF) << 16) | (int(event["request_ecx"], 16) & 0xFFFF)
        require(size == request_size and size != 0, f"event {ordinal} size was not derived from guest registers")
        require(event.get("provider") == "gw_dos_services_callback" and event.get("arena") == "synthetic",
                f"event {ordinal} lacks Runtime/arena provenance")
        require(event.get("handled") == "1" and event.get("preserved") == "1", f"event {ordinal} callback failed invariants")
        if event.get("success") == "1":
            base = int(event["base"], 16)
            require(event.get("carry") == "0" and event["response_eax"] == event["request_eax"],
                    f"event {ordinal} success registers/flags invalid")
            require(base >= 0x200000 and base + size <= 0x400000 and base % 0x1000 == 0,
                    f"event {ordinal} escaped the bounded synthetic arena")
            require(int(event["handle"], 16) != 0 and event.get("zero_filled") == "1",
                    f"event {ordinal} success lacks handle/zero-fill evidence")
            require(int(event["cursor_after"], 16) == base + size, f"event {ordinal} cursor does not match allocation")
        else:
            require(event.get("unavailable") == "1" and event.get("carry") == "1" and
                    (int(event["response_eax"], 16) & 0xFFFF) == 0x8012,
                    f"event {ordinal} is not the Runtime allocator exhaustion result")
            require(event["cursor_after"] == event["cursor_before"], f"event {ordinal} failure moved allocator cursor")
            require(ordinal == len(events) - 1, "callbacks continued after allocator exhaustion")
    require(sequence.get("stopped_after_allocator_exhaustion") is (events[-1].get("unavailable") == "1"),
            "exhaustion stop marker disagrees with final event")
    frontier = sequence.get("next_frontier")
    require(isinstance(frontier, dict) and frontier.get("vector") == "31" and frontier.get("eip") == "000c3cc1",
            "missing next native frontier after AX=0501 sequence")
    print(f"PASS: {path}; {len(events)} bounded Runtime-backed AX=0501 events; arena explicitly synthetic")


if __name__ == "__main__":
    main()
