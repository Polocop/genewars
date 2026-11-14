"""Build and validate bounded native caller provenance for AH=4400/BX=1."""
from __future__ import annotations
import json
from pathlib import Path

TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"

def fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)

def build_provenance(lines: list[str], file_events: list[dict]) -> dict:
    callsites=[fields(x) for x in lines if x.startswith("W1_AH44_CALLSITE ")]
    helpers=[fields(x) for x in lines if x.startswith("W1_AH44_HELPER_ENTRY ")]
    requests=[fields(x) for x in lines if x.startswith("W1_AH44_REQUEST ")]
    callsite_by_ordinal={int(x.get("ordinal","-1")):x for x in callsites}
    helper_by_ordinal={int(x.get("ordinal","-1")):x for x in helpers}
    correlated_pairs=[]
    for ordinal,call in sorted(callsite_by_ordinal.items()):
        helper=helper_by_ordinal.get(ordinal)
        correlated_pairs.append({"ordinal":ordinal,"callsite":call,"helper_entry":helper,
            "correlated":bool(helper and int(call.get("target","0"),16)==0x000C896A)})
    bx1=[]
    for request in requests:
        if int(request.get("ebx","0"),16)&0xffff != 1 or int(request.get("eax","0"),16)&0xffff != 0x4400:
            continue
        ordinal=int(request.get("helper_ordinal","-1"))
        call=callsite_by_ordinal.get(ordinal); helper=helper_by_ordinal.get(ordinal)
        valid=bool(call and helper and int(call.get("ordinal","-1"))==ordinal and
                   int(helper.get("ordinal","-1"))==ordinal and int(call.get("target","0"),16)==0x000C896A)
        bx1.append({"request":request,"callsite":call,"helper_entry":helper,"correlated":valid,
            "native_dynamic_caller_link_va":call.get("caller") if valid else None,
            "native_direct_callsite_link_va":call.get("site") if valid else None,
            "helper_entry_eax":helper.get("eax") if valid else None})
    dos_events=[line for line in lines if line.startswith(("W1_077_DOS_FILE_REQUEST ","W1_CRT_DOS_AX4400_FILE ",
        "W1_CRT_DOS_AH3D_GENERIC ","W1_CRT_DOS_AH3C_GENERIC ","W1_CRT_DOS_AH3E_FILE ",
        "NATIVE_DOS_AH3D ","NATIVE_DOS_AH3E ","NATIVE_NEXT_TRAP ","NATIVE_FRONTIER_CPU "))]
    return {"observer_enabled":True,"callsite_events":callsites,"helper_entry_events":helpers,
        "request_events":requests,"callsite_helper_pairs":correlated_pairs,
        "callsite_helper_correlated_by_ordinal":len(callsites)==len(helpers) and all(x["correlated"] for x in correlated_pairs),
        "request_helper_correlated_by_ordinal":all(int(x.get("helper_ordinal","-1")) in helper_by_ordinal and
            helper_by_ordinal[int(x["helper_ordinal"])].get("ordinal")==x.get("helper_ordinal") for x in requests),
        "bx1_requests":bx1,"bx1_caller_attribution":"MEASURED" if bx1 and all(x["correlated"] for x in bx1) else "UNRESOLVED",
        "file_handle_events_in_execution_order":dos_events,"original_equivalence_claimed":False,
        "dos_response_supplied":False,"captured_lifecycle_event_count":len(file_events)}

def validate_capture(capture: dict) -> list[str]:
    errors=[]
    if capture.get("task")!="W1-085": errors.append("capture task must be W1-085")
    if capture.get("fresh_replay") is not True: errors.append("capture must be fresh")
    if capture.get("original_equivalence_claimed") is not False: errors.append("capture overclaims original equivalence")
    if capture.get("target_sha256")!=TARGET: errors.append("target fingerprint mismatch")
    origin=capture.get("native_ah4400_origin",{})
    if origin.get("observer_enabled") is not True: errors.append("AH=4400 provenance observer missing")
    callsites=origin.get("callsite_events",[]); helpers=origin.get("helper_entry_events",[]); requests=origin.get("request_events",[])
    if not callsites or not helpers or not requests: errors.append("callsite/helper/request event sets must be preserved")
    if origin.get("callsite_helper_correlated_by_ordinal") is not True: errors.append("callsite/helper ordinal relation is not verified")
    if origin.get("request_helper_correlated_by_ordinal") is not True: errors.append("request/helper ordinal relation is not verified")
    bx1=origin.get("bx1_requests",[])
    if not bx1: errors.append("fresh replay did not preserve an AX=4400/BX=1 request")
    for event in bx1:
        if event.get("correlated") is not True:
            if event.get("native_dynamic_caller_link_va") is not None or event.get("helper_entry_eax") is not None:
                errors.append("uncorrelated BX=1 request must not claim caller or helper EAX")
        else:
            if not event.get("native_dynamic_caller_link_va") or not event.get("native_direct_callsite_link_va") or not event.get("helper_entry_eax"):
                errors.append("correlated BX=1 request lacks caller, callsite, or entry EAX")
            if int(event["helper_entry_eax"],16)&0xffff != 1:
                errors.append("BX=1 request helper entry EAX does not match the guest-produced handle")
    frontier=capture.get("frontier",{})
    if frontier.get("newly_observed") is not True or not frontier.get("guest_eip"):
        errors.append("fresh next native frontier missing")
    return errors

def validate_file(path: Path) -> dict:
    data=json.loads(path.read_text(encoding="utf-8")); errors=validate_capture(data)
    origin=data.get("native_ah4400_origin",{})
    return {"valid":not errors,"errors":errors,"capture_id":data.get("capture_id"),
        "bx1_caller_attribution":origin.get("bx1_caller_attribution"),"bx1_request_count":len(origin.get("bx1_requests",[]))}

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(); parser.add_argument("capture",type=Path); args=parser.parse_args()
    result=validate_file(args.capture); print(json.dumps(result,indent=2)); raise SystemExit(0 if result["valid"] else 1)
