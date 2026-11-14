from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def validate(path: pathlib.Path) -> dict:
    capture = json.loads(path.read_text(encoding="utf-8"))
    strict = capture["w1_063_strict_ax0501"]
    frontier = strict["frontier"]
    events = strict["allocator_chain_events"]
    normalized = [line.lower() for line in events]
    checks = {
        "native_recompiled_execution": capture.get("execution_mode") == "native_recompiled_guest",
        "expected_guest_trap_exit": capture.get("native_returncode_is_expected_trap_stop") is True,
        "full_command_tail_fixture": capture.get("command_tail") == "-k 38928",
        "first_natural_ax0501": frontier.get("vector") == "31" and frontier.get("eip") == "000c3cc1",
        "request_size_1000": strict.get("request_size_bytes") == "0x00001000",
        "no_ax0501_response": strict.get("response_records") == 0 and frontier.get("response_count") == "0",
        "success_handler_disabled": strict.get("synthetic_success_disabled") is True,
        "bounded_arena_retained": strict.get("memory_arena_bytes") == 0x400000,
        "fixture_sizes": (capture.get("fixture_fingerprint", {}).get("config_bytes") == 130 and
                          capture.get("fixture_fingerprint", {}).get("address_bytes") == 24 and
                          capture.get("fixture_fingerprint", {}).get("sound_ini_bytes") == 11),
        "w1_036_not_equated": strict.get("same_dynamic_invocation_claimed") is False,
        "recovery_reference_present": bool(capture.get("recovery", {}).get("verification_sha256")),
    }
    comparison = capture.get("comparison", {})
    checks["original_ordinal1_request_matches"] = (
        comparison.get("original_w3_068", {}).get("ax0501_request_size") == "0x0000:0x1000 = 4096 bytes" and
        comparison.get("native_w1_063", {}).get("first_request_size") == "0x00001000"
    )
    checks["not_equated_to_w1_036"] = (
        comparison.get("w1_036", {}).get("request") == "0x00008000" and
        comparison.get("w1_036", {}).get("equivalent_to_w3_068_ordinal1") is False and
        comparison.get("same_dynamic_invocation_claimed") is False
    )
    checks["w1_062_later_chain_qualification"] = (
        comparison.get("w1_062", {}).get("synthetic_ax0501_success_continuation_enabled") is True and
        len(comparison.get("w1_062", {}).get("callsite_sizes", [])) >= 2 and
        comparison.get("w1_062", {}).get("callsite_sizes", [])[0].get("size_hex") == "0x00001000" and
        comparison.get("w1_062", {}).get("callsite_sizes", [])[1].get("size_hex") == "0x00008000"
    )
    checks["adjustment_input_difference_and_equal_output"] = (
        comparison.get("original_w3_068", {}).get("adjustamount_input") == "0x40" and
        any("site=000c3d98" in line and "stack0=00000001" in line for line in normalized) and
        any("site=000c3d98" in line and "stack0=00001000" in line for line in normalized if "native_alloc_return" in line)
    )
    checks["native_adjustamount_threshold_sampled"] = any("global_10c828=" in line for line in normalized if "native_alloc_return" in line)
    checks["expand_caller_observed"] = any(
        "site=000ae038" in line and "caller=000adf95" in line and "target=000c3e2a" in line
        for line in normalized
    )
    checks["create_and_adjustamount_chain"] = (
        any("va=000c3e2a" in line for line in normalized) and
        any("va=000c3d7a" in line for line in normalized) and
        any("site=000c3d98" in line and "target=000c3f76" in line for line in normalized) and
        any("va=000c3f76" in line for line in normalized) and
        any("site=000c3d98" in line and "stack0=00001000" in line for line in normalized if "native_alloc_return" in line)
    )
    checks["rationalalloc_callsite_observed"] = any(
        "site=000c3db0" in line and "target=000c3ca9" in line and "eax=00001000" in line
        for line in normalized
    )
    checks["rationalalloc_entry_and_request_match"] = (
        any("va=000c3ca9" in line and "eax=00001000" in line for line in normalized) and
        frontier.get("caller_func") == "000c3ca9" and frontier.get("eax") == "00000501"
    )
    verification_path = ROOT / capture["recovery"]["verification"]
    verification = json.loads(verification_path.read_text(encoding="utf-8"))
    checks["recovery_hash_and_isolated_restore"] = bool(verification) and all(
        row.get("verified") is True and row.get("source_sha256") == row.get("backup_sha256") == row.get("isolated_restore_sha256")
        for row in verification
    )
    additional_path = capture.get("recovery", {}).get("additional_current_source_verification")
    if additional_path:
        additional = json.loads((ROOT / additional_path).read_text(encoding="utf-8"))
        checks["latest_source_recovery_verified"] = additional.get("verified") is True and additional.get("source_sha256") == additional.get("backup_sha256") == additional.get("isolated_restore_sha256")
    failed = [name for name, passed in checks.items() if not passed]
    return {"valid": not failed, "checks": checks, "failed": failed,
            "request_size_bytes": strict.get("request_size_bytes"),
            "frontier": frontier, "allocator_event_count": len(events)}


if __name__ == "__main__":
    evidence_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evidence" / "native_ax0501_strict_w1_063.json"
    result = validate(evidence_path)
    print(json.dumps(result, indent=2))
    if not result["valid"]:
        raise SystemExit(1)
    print("PASS W1-063 strict AX=0501 evidence validator")
