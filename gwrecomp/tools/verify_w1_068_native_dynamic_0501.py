"""Validate a fresh native AX=0501 continuation using the existing bounded allocator."""
from __future__ import annotations
import argparse, hashlib, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV_SHA = "65c4d22c258efbf93a93cfcaa8d9d8c489e510cb2be76530646c36e0250ee895"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"

def validate(data: dict, *, project_root: pathlib.Path | None = None) -> list[str]:
    errors=[]
    if data.get("task") != "W1-068" or data.get("task_schema") != "gwrecomp.native-setenvp-dpmi-continue/v1": errors.append("W1-068 schema is missing")
    if data.get("target_sha256") != TARGET_SHA or data.get("evidence_level") != "NATIVE_REACHED": errors.append("capture target/evidence level is invalid")
    env=data.get("authenticated_environment", {})
    if env.get("sha256") != ENV_SHA or env.get("size_bytes") != 86 or env.get("exact_bytes_loaded") is not True: errors.append("authenticated W3-140 environment was not loaded exactly")
    prior=data.get("prior_capture", {})
    prior_size=prior.get("observed_request_size_bytes")
    alloc=data.get("native_generated_c_progress", {}).get("dpmi_linear_allocation") or {}
    try:
        request=((int(alloc.get("request_ebx", "0"),16)&0xffff)<<16)|(int(alloc.get("request_ecx", "0"),16)&0xffff)
        expected=int(prior_size,16)
        size=int(alloc.get("synthetic_size", "0"),16)
        base=int(alloc.get("synthetic_base", "0"),16)
        handle=int(alloc.get("synthetic_handle", "0"),16)
        returned_base=((int(alloc.get("response_ebx", "0"),16)&0xffff)<<16)|(int(alloc.get("response_ecx", "0"),16)&0xffff)
        returned_handle=((int(alloc.get("response_esi", "0"),16)&0xffff)<<16)|(int(alloc.get("response_edi", "0"),16)&0xffff)
    except (TypeError, ValueError):
        errors.append("AX=0501 request/response fields are malformed")
        request=expected=size=base=handle=returned_base=returned_handle=0
    if not request or request != expected or data.get("allocator_service", {}).get("request_matches_prior_capture") is not True: errors.append("fresh request does not match W1-066's measured request")
    if alloc.get("request_eax") != "0x00000501" or alloc.get("instruction_va") != "0x000C3CC1" or alloc.get("carry") != 0 or alloc.get("handled") != 1 or alloc.get("response_eax") != "0x00000501": errors.append("Runtime allocator response does not satisfy the measured success contract")
    if size != request or not base or not handle or base != returned_base or handle != returned_handle: errors.append("dynamic allocator return does not match its request/allocation record")
    if data.get("allocator_service", {}).get("arena_kind") != "synthetic_test_arena" or data.get("allocator_service", {}).get("response_is_guest_state_injection") is not False or data.get("allocator_service", {}).get("original_base_or_handle_reused") is not False: errors.append("synthetic arena provenance or dynamic base/handle qualification is missing")
    if data.get("allocator_service", {}).get("response_source") != "existing gw_dos_services_callback bounded linear allocator": errors.append("allocation did not use the existing bounded Runtime callback")
    if prior.get("path") != "evidence/native_setenvp_aligned_replay_w1_066.json" or prior.get("separate_dynamic_run") is not True: errors.append("W1-066 request provenance is missing or overclaims invocation identity")
    if not isinstance(data.get("next_frontier"), (dict, list)) or not data.get("next_frontier"): errors.append("next native frontier was not recorded")
    if data.get("menu_reached") is not False or data.get("framebuffer_reached") is not False: errors.append("capture overclaims menu/framebuffer reachability")
    crt=data.get("crt_startup", {})
    if not isinstance(crt.get("callback_count_before_stop"), int) or not isinstance(crt.get("argc"), int) or not isinstance(crt.get("argv"), list): errors.append("CRT/argc/argv context is missing")
    if data.get("setenvp_return", {}).get("observed") is True and not data["setenvp_return"].get("event"): errors.append("DFE12 flag has no return event")
    if project_root is not None:
        root=project_root.resolve()
        for key in ("path",):
            path=(root/prior.get(key, "")).resolve()
            try: path.relative_to(root)
            except ValueError: errors.append("prior capture path escapes workspace")
            else:
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=prior.get("sha256"): errors.append("prior W1-066 capture is missing or changed")
        for field, rel in (("native_executable_sha256","build/entry_path_native_boot.exe"),("closure_source_sha256","build/entry_path_closure.c"),("routed_object_sha256","build/entry_path_closure_routed.o"),("runtime_c_header_sha256","runtime/gw_dos_services.c"),("runtime_driver_sha256","tests/test_native_guest_image.py"),("native_harness_sha256","tests/test_native_guest_image.c")):
            path=root/rel
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=data.get("build_fingerprint",{}).get(field): errors.append(f"{rel} fingerprint is missing or stale")
    return errors

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("evidence",type=pathlib.Path);a=p.parse_args(argv)
    try: data=json.loads(a.evidence.read_text(encoding="utf-8"))
    except Exception as exc: print(f"INVALID evidence: {exc}",file=sys.stderr);return 2
    errors=validate(data,project_root=ROOT)
    if errors:
        print("FAIL W1-068 capture contract:");[print("- "+e) for e in errors];return 1
    print("PASS W1-068 fresh native AX=0501 continuation evidence")
    return 0
if __name__=="__main__": raise SystemExit(main())
