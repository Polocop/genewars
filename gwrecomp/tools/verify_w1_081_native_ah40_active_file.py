"""Validate the bounded W1-081 native virtual-file write event."""
from __future__ import annotations

import json
from pathlib import Path


def fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)


def validate_capture(capture: dict) -> list[str]:
    errors: list[str] = []
    observer = capture.get("w1_081_ah40_active_file", {})
    events = observer.get("events", [])
    if observer.get("observer_enabled") is not True:
        errors.append("observer disabled")
    if observer.get("event_cap") != 1 or observer.get("max_sample_bytes") != 64 or observer.get("event_count") != len(events) or len(events) != 1:
        errors.append("event/sample bound or count mismatch")
    if observer.get("only_active_virtual_file_handle") is not True or observer.get("host_write") is not False:
        errors.append("active-file mapping or host-write restriction missing")
    if observer.get("guest_state_injected") is not False or capture.get("original_equivalence_claimed") is not False:
        errors.append("capture overclaims injection or original equivalence")
    if capture.get("fresh_replay") is not True:
        errors.append("capture is not a fresh replay")
    if capture.get("target_sha256") != "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f":
        errors.append("target fingerprint mismatch")
    required = {
        "ordinal", "caller", "eip", "slot", "mapping_active", "owner", "callback_invoked",
        "eax_in", "ebx_in", "ecx_in", "edx_in", "esi_in", "edi_in", "ebp_in", "esp_in",
        "flags_k_in", "flags_a_in", "flags_b_in", "cf_in", "sample_valid", "sample_length", "sample_hex",
        "eax_out", "ebx_out", "ecx_out", "edx_out", "esi_out", "edi_out", "ebp_out", "esp_out",
        "flags_k_out", "flags_a_out", "flags_b_out", "cf_out", "callback_handled",
    }
    for line in events:
        parsed = fields(line)
        if not required.issubset(parsed):
            errors.append("event is missing request, response, or sample fields")
            continue
        if parsed["eip"].lower() != "000d219c" or parsed["eax_in"].lower() != "00004002" or parsed["ebx_in"].lower() != "00000002":
            errors.append("event is not AH=40/BX=2 at D219C")
        try:
            requested = int(parsed["ecx_in"], 16)
            sample_length = int(parsed["sample_length"], 10)
            sample = bytes.fromhex(parsed["sample_hex"])
        except (ValueError, TypeError):
            errors.append("malformed request length or source sample")
            continue
        if requested > 64 or sample_length != requested or len(sample) != sample_length:
            errors.append("source sample exceeds or disagrees with the bounded request")
        if parsed["sample_valid"] != "1":
            errors.append("guest source sample was not bounded in memory")
        active = parsed["mapping_active"] == "1"
        invoked = parsed["callback_invoked"] == "1"
        if active != invoked:
            errors.append("callback invocation does not match active file mapping")
        if parsed["callback_handled"] not in {"0", "1"} or parsed["cf_out"] not in {"0", "1"}:
            errors.append("callback result or CF is malformed")
    return errors


def validate_file(path: Path) -> dict:
    capture = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(capture)
    observer = capture.get("w1_081_ah40_active_file", {})
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
