"""Validate bounded W1-077 native file-lifecycle evidence."""
from __future__ import annotations
import json
from pathlib import Path

def validate_capture(capture: dict) -> list[str]:
    errors=[]
    life=capture.get("w1_077_lifecycle",{})
    if capture.get("task")!="W1-077" or capture.get("schema")!="gwrecomp.native-gwerr-handle-lifecycle-w1-077/v1":
        errors.append("wrong task/schema")
    if capture.get("fresh_replay") is not True:
        errors.append("capture is not a fresh replay")
    if capture.get("target_sha256")!="2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f":
        errors.append("target fingerprint mismatch")
    if life.get("observer_enabled") is not True or life.get("event_cap")!=32:
        errors.append("bounded observer metadata missing")
    events=life.get("events",[])
    if len(events)>32 or life.get("request_event_count")!=len(events):
        errors.append("event cap/count mismatch")
    for n,event in enumerate(events):
        if event.get("ordinal")!=str(n): errors.append(f"event ordinal mismatch at {n}")
        if event.get("kind") not in {"open","create","close","dup","attributes","temp_create"}:
            errors.append(f"unknown event kind at {n}")
        if event.get("kind") in {"open","create","attributes","temp_create"}:
            try:
                length=int(event.get("path_length","-1")); valid=event.get("path_valid")=="1"
                terminated=event.get("path_terminated")=="1"; raw=bytes.fromhex(event.get("path_hex",""))
            except (ValueError,TypeError):
                errors.append(f"malformed path sample at {n}"); continue
            if not valid or not terminated or length<0 or length>128 or len(raw)!=length:
                errors.append(f"path bounds/terminator invalid at {n}")
    context=life.get("process_context",{})
    if context.get("model")!="single-native-guest" or not context.get("harness_psp_selector") or not context.get("harness_psp_linear"):
        errors.append("synthetic single-process context missing")
    ah=life.get("ah4400_observations",[])
    if not 1<=len(ah)<=8:
        errors.append("first-eight AH=4400 checkpoint set missing or oversized")
    for line in ah:
        fields=dict(token.split("=",1) for token in line.split()[1:] if "=" in token)
        if fields.get("eip")!="000c8973" or fields.get("eax_in")!="00004400":
            errors.append("AH=4400 observation is not the expected native site/service")
    if life.get("same_dynamic_invocation_claimed") is not False or life.get("causality_claimed") is not False:
        errors.append("evidence overclaims invocation identity or cause")
    if "no PSP JFT is inferred" not in life.get("lifecycle_coverage",""):
        errors.append("PSP/JFT model limitation missing")
    return errors

def validate_file(path: Path) -> dict:
    capture=json.loads(path.read_text(encoding="utf-8"))
    errors=validate_capture(capture)
    return {"valid":not errors,"errors":errors,"task":"W1-077","capture_id":capture.get("capture_id"),
            "event_count":capture.get("w1_077_lifecycle",{}).get("request_event_count"),
            "ah4400_count":capture.get("w1_077_lifecycle",{}).get("ah4400_observation_count")}

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("capture",type=Path)
    args=parser.parse_args()
    result=validate_file(args.capture)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result["valid"] else 1)
