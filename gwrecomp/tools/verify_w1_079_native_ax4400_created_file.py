"""Validate bounded W1-079 evidence for the natural handle-2 AX=4400 call."""
from __future__ import annotations

import json
from pathlib import Path


def _fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)


def validate_capture(capture: dict) -> list[str]:
    errors: list[str] = []
    observer = capture.get("w1_079_ax4400_handle2", {})
    events = observer.get("events", [])
    if observer.get("observer_enabled") is not True:
        errors.append("W1-079 observer was not enabled")
    if observer.get("event_cap") != 1 or observer.get("event_count") != len(events) or len(events) != 1:
        errors.append("expected exactly one event within the one-event cap")
    if observer.get("only_active_virtual_file_handle") is not True:
        errors.append("observer is not restricted to an active virtual file handle")
    if observer.get("guest_state_injected") is not False:
        errors.append("capture claims guest state injection")
    if capture.get("fresh_replay") is not True:
        errors.append("capture is not a fresh replay")
    if capture.get("target_sha256") != "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f":
        errors.append("target fingerprint mismatch")
    if capture.get("original_equivalence_claimed") is not False:
        errors.append("capture overclaims original equivalence")
    for line in events:
        try:
            fields = _fields(line)
            required = {
                "ordinal", "caller", "eip", "slot", "mapping_active", "owner", "callback_invoked",
                "eax_in", "ebx_in", "ecx_in", "edx_in", "esi_in", "edi_in", "ebp_in", "esp_in",
                "flags_k_in", "flags_a_in", "flags_b_in", "cf_in", "eax_out", "ebx_out", "ecx_out",
                "edx_out", "esi_out", "edi_out", "ebp_out", "esp_out", "flags_k_out", "flags_a_out",
                "flags_b_out", "cf_out", "callback_handled",
            }
            if not required.issubset(fields):
                errors.append("event is missing register, mapping, or callback fields")
                continue
            if fields["eip"].lower() != "000c8973" or fields["eax_in"].lower() != "00004400" or fields["ebx_in"].lower() != "00000002":
                errors.append("event is not the measured AX=4400/BX=2 guest request")
            if fields["ordinal"] != "0":
                errors.append("event ordinal is outside the one-event window")
            active = fields["mapping_active"] == "1"
            invoked = fields["callback_invoked"] == "1"
            if active != invoked:
                errors.append("callback invocation does not match the active file mapping")
            if fields["callback_handled"] not in {"0", "1"} or fields["cf_out"] not in {"0", "1"}:
                errors.append("callback result or carry flag is malformed")
        except (TypeError, ValueError):
            errors.append("malformed W1-079 event line")
    return errors


def validate_file(path: Path) -> dict:
    capture = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(capture)
    observer = capture.get("w1_079_ax4400_handle2", {})
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
