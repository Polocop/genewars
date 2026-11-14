"""Validate W1-084's fresh two-event bounded AH=40 continuation capture."""
from __future__ import annotations
import json
from pathlib import Path

TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"

def fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)

def validate_capture(capture: dict) -> list[str]:
    errors: list[str] = []
    observer = capture.get("w1_081_ah40_active_file", {})
    events = observer.get("events", [])
    if capture.get("task") != "W1-084": errors.append("capture task must be W1-084")
    if capture.get("fresh_replay") is not True: errors.append("capture is not a fresh replay")
    if capture.get("original_equivalence_claimed") is not False: errors.append("capture overclaims original equivalence")
    if capture.get("target_sha256") != TARGET: errors.append("target fingerprint mismatch")
    if observer.get("observer_enabled") is not True: errors.append("observer disabled")
    if observer.get("event_cap") != 2 or observer.get("max_sample_bytes") != 64 or observer.get("event_count") != len(events) or len(events) != 2:
        errors.append("event/sample bound or two-event count mismatch")
    if observer.get("only_active_virtual_file_handle") is not True or observer.get("host_write") is not False:
        errors.append("active-file mapping or host-write restriction missing")
    if observer.get("guest_state_injected") is not False: errors.append("guest state was injected")
    for ordinal, line in enumerate(events):
        parsed = fields(line)
        required = {"ordinal", "caller", "eip", "slot", "mapping_active", "owner", "callback_invoked",
            "eax_in", "ebx_in", "ecx_in", "edx_in", "esi_in", "edi_in", "ebp_in", "esp_in",
            "flags_k_in", "flags_a_in", "flags_b_in", "cf_in", "sample_valid", "sample_length", "sample_hex",
            "eax_out", "ebx_out", "ecx_out", "edx_out", "esi_out", "edi_out", "ebp_out", "esp_out",
            "flags_k_out", "flags_a_out", "flags_b_out", "cf_out", "callback_handled"}
        if not required.issubset(parsed):
            errors.append(f"event {ordinal} lacks request, response, or sample fields")
            continue
        if int(parsed["ordinal"]) != ordinal: errors.append("event ordinals must be sequential from zero")
        if parsed["eip"].lower() != "000d219c" or parsed["eax_in"].lower() != "00004002" or parsed["ebx_in"].lower() != "00000002":
            errors.append(f"event {ordinal} is not AH=40/BX=2 at D219C")
        try:
            requested = int(parsed["ecx_in"], 16)
            sample_length = int(parsed["sample_length"], 10)
            sample = bytes.fromhex(parsed["sample_hex"])
        except (ValueError, TypeError):
            errors.append(f"event {ordinal} has malformed request/sample")
            continue
        if requested > 64 or sample_length != requested or len(sample) != sample_length:
            errors.append(f"event {ordinal} source sample violates its request bound")
        if parsed["sample_valid"] != "1": errors.append(f"event {ordinal} sample is not bounded in guest memory")
        if parsed["mapping_active"] != "1" or parsed["owner"] in {"unmapped", "unknown"}:
            errors.append(f"event {ordinal} is not associated with an active mapped virtual file")
        if parsed["callback_invoked"] != "1": errors.append(f"event {ordinal} did not invoke the Runtime callback")
        if parsed["callback_handled"] != "1": errors.append(f"event {ordinal} was not handled by the Runtime callback")
    frontier = capture.get("frontier", {})
    regs = frontier.get("request_registers", {})
    if frontier.get("newly_observed") is not True or frontier.get("fresh_replay") is not True or not frontier.get("stop_reason"):
        errors.append("fresh next frontier was not captured")
    if not frontier.get("guest_eip") or not regs.get("eip") or not regs.get("eax"):
        errors.append("next frontier CPU context is incomplete")
    if str(frontier.get("guest_eip", "")).lower() in {"0x000d219c", "000d219c"} and str(regs.get("eax", "")).lower() in {"00004002", "0x00004002"}:
        errors.append("the previously trapped AH=40 request was not advanced")
    return errors

def validate_file(path: Path) -> dict:
    capture=json.loads(path.read_text(encoding="utf-8"))
    errors=validate_capture(capture)
    observer=capture.get("w1_081_ah40_active_file", {})
    return {"valid": not errors, "errors": errors, "capture_id": capture.get("capture_id"),
        "event_count": observer.get("event_count"), "evidence_level": capture.get("evidence_level")}

if __name__ == "__main__":
    import argparse
    p=argparse.ArgumentParser(); p.add_argument("capture",type=Path); a=p.parse_args()
    result=validate_file(a.capture); print(json.dumps(result,indent=2)); raise SystemExit(0 if result["valid"] else 1)
