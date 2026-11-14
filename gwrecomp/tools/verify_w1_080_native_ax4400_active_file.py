"""Validate bounded W1-080 native active-file AX=4400 callback evidence."""
from __future__ import annotations

import json
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)


def validate_capture(capture: dict) -> list[str]:
    errors: list[str] = []
    observer = capture.get("w1_080_ax4400_active_file", {})
    events = observer.get("events", [])
    if observer.get("observer_enabled") is not True:
        errors.append("observer disabled")
    if observer.get("event_cap") != 4 or observer.get("event_count") != len(events) or not 1 <= len(events) <= 4:
        errors.append("event count is missing or exceeds the four-event bound")
    if observer.get("only_active_virtual_file_handle") is not True or observer.get("guest_state_injected") is not False:
        errors.append("active-file or no-injection constraint is missing")
    if capture.get("fresh_replay") is not True or capture.get("original_equivalence_claimed") is not False:
        errors.append("capture freshness/equivalence classification is invalid")
    if capture.get("target_sha256") != "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f":
        errors.append("target fingerprint mismatch")
    required = {
        "ordinal", "caller", "eip", "slot", "mapping_active", "owner", "callback_invoked",
        "eax_in", "ebx_in", "ecx_in", "edx_in", "esi_in", "edi_in", "ebp_in", "esp_in",
        "flags_k_in", "flags_a_in", "flags_b_in", "cf_in", "eax_out", "ebx_out", "ecx_out",
        "edx_out", "esi_out", "edi_out", "ebp_out", "esp_out", "flags_k_out", "flags_a_out",
        "flags_b_out", "cf_out", "callback_handled",
    }
    for expected_ordinal, line in enumerate(events):
        parsed = fields(line)
        if not required.issubset(parsed):
            errors.append(f"event {expected_ordinal} is missing fields")
            continue
        if parsed["ordinal"] != str(expected_ordinal):
            errors.append(f"event ordinal mismatch at {expected_ordinal}")
        if parsed["eip"].lower() != "000c8973" or parsed["eax_in"].lower() != "00004400" or parsed["ebx_in"].lower() != "00000002":
            errors.append(f"event {expected_ordinal} is not AX=4400/BX=2 at C8973")
        active = parsed["mapping_active"] == "1"
        invoked = parsed["callback_invoked"] == "1"
        if active != invoked:
            errors.append(f"event {expected_ordinal} callback does not match active mapping")
        if parsed["callback_handled"] not in {"0", "1"} or parsed["cf_out"] not in {"0", "1"}:
            errors.append(f"event {expected_ordinal} callback result/CF is malformed")
    return errors


def validate_file(path: Path) -> dict:
    capture = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(capture)
    observer = capture.get("w1_080_ax4400_active_file", {})
    return {"valid": not errors, "errors": errors, "capture_id": capture.get("capture_id"),
            "event_count": observer.get("event_count"), "evidence_level": capture.get("evidence_level")}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    result = validate_file(args.capture)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["valid"] else 1)
