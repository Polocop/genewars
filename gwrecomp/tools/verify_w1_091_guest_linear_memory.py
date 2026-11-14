#!/usr/bin/env python3
"""Validate the W1-091 host-backed AX=0501 replay evidence."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def main():
    if len(sys.argv) != 2:
        fail("usage: verify_w1_091_guest_linear_memory.py EVIDENCE.json")
    path = pathlib.Path(sys.argv[1])
    if not path.is_absolute():
        path = ROOT / path
    evidence = json.loads(path.read_text(encoding="utf-8"))
    if evidence.get("fresh_replay") is not True or evidence.get("original_equivalence_claimed") is not False:
        fail("capture is not a fresh, native-only replay")
    result = evidence.get("w1_091_guest_linear_memory")
    if not isinstance(result, dict):
        fail("W1-091 result is missing")
    if (result.get("schema") != "gwrecomp.native-dpmi-host-backed-guest-memory-w1-091/v1" or
            result.get("evidence_level") != "NATIVE_REACHED" or
            result.get("target_sha256") != "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f" or
            result.get("original_equivalence_claimed") is not False or
            result.get("build_sha256") != evidence.get("build_id") or
            result.get("fixture_fingerprint") != evidence.get("fixtures", {}).get("native", {}).get("fingerprint") or
            result.get("authenticated_environment_sha256") != evidence.get("authenticated_environment", {}).get("sha256") or
            result.get("fixture_components", {}).get("address_txt_sha256") != "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee" or
            result.get("fixture_components", {}).get("config_ini_sha256") != "e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798" or
            not result.get("stdout_sha256")):
        fail("native-only build, fixture, or target provenance is invalid")
    arena = result.get("arena", {})
    expected_arena = {
        "kind": "host_backed_guest_map",
        "guest_range": ["0x00000000", "0x0220B000"],
        "image_end": "0x001B2000",
        "allocation_begin": "0x00200000",
        "capacity_bytes": "0x0220B000",
        "backing": "zeroed process-owned guest_memory",
        "duration": "single replay process",
        "not_original_mapping_evidence": True,
    }
    if arena != expected_arena:
        fail(f"guest map provenance differs from the one-run derived map: {arena}")
    if result.get("provider") != "gw_dos_services_callback" or result.get("guest_state_injected") is not False:
        fail("provider or no-injection provenance is invalid")
    events = result.get("events")
    if not isinstance(events, list) or len(events) != 3:
        fail("expected two allocations and one fail-closed exhaustion response")
    expected_sizes = [0x01001000, 0x01001000]
    expected_bases = [0x00209000, 0x0120A000]
    expected_cursors = [0x0120A000, 0x0220B000]
    for index, event in enumerate(events[:2]):
        size = int(event["size"], 16)
        if (int(event["ordinal"]) != index or int(event["eip"], 16) != 0x000C3CC1 or
                int(event["request_eax"], 16) & 0xffff != 0x0501 or
                size != expected_sizes[index] or int(event["base"], 16) != expected_bases[index] or
                int(event["cursor_before"], 16) != expected_bases[index] or
                int(event["cursor_after"], 16) != expected_cursors[index] or
                int(event["guest_capacity"], 16) != 0x0220B000 or
                event.get("success") != "1" or event.get("unavailable") != "0" or
                event.get("zero_filled") != "1" or event.get("arena") != "host_backed" or
                event.get("provider") != "gw_dos_services_callback" or event.get("preserved") != "1" or
                event.get("carry") != "0" or int(event.get("handle", "0"), 16) == 0 or
                (index and int(event["handle"], 16) <= int(events[index-1]["handle"], 16))):
            fail(f"natural allocation {index} violates the guest map/allocator contract: {event}")
    exhausted = events[2]
    if (exhausted.get("success") != "0" or exhausted.get("unavailable") != "1" or
            exhausted.get("carry") != "1" or int(exhausted["response_eax"], 16) & 0xffff != 0x8012 or
            exhausted["cursor_before"] != exhausted["cursor_after"] or
            int(exhausted["guest_capacity"], 16) != 0x0220B000 or
            result.get("next_frontier", {}).get("ecx") != "01000000"):
        fail(f"map exhaustion or preserved next frontier is inconsistent: {exhausted}")
    if result.get("event_count") != len(events):
        fail("event_count does not match captured natural events")
    if evidence.get("build_id") is None or evidence.get("runtime_fingerprint") is None:
        fail("native build or runtime fingerprint is missing")
    print(f"PASS: W1-091 host-backed AX=0501 replay, {len(events)} natural event(s), capacity 0x0220B000")


if __name__ == "__main__":
    main()
