from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)


def validate(path: pathlib.Path) -> dict:
    capture = json.loads(path.read_text(encoding="utf-8"))
    strict = capture["w1_063_strict_ax0501"]
    lines = capture["stdout"]["selected_lines"]
    call = next((line for line in lines if line.startswith("NATIVE_ALLOC_CALLSITE ") and "site=000dfe0d" in line), "")
    entry = next((line for line in lines if line.startswith("NATIVE_ALLOC_ENTRY ") and "va=000adf95" in line), "")
    expand = next((line for line in lines if line.startswith("NATIVE_ALLOC_CALLSITE ") and "site=000ae038" in line), "")
    original = json.loads((ROOT / "evidence" / "w3_068_heap_alignment_original_20261008.json").read_text(encoding="utf-8"))
    original_adf = original["original_adf95"]
    original_regs = original_adf["registers"]
    call_f = _fields(call) if call else {}
    entry_f = _fields(entry) if entry else {}
    expand_f = _fields(expand) if expand else {}
    branch_capture_path = ROOT / "evidence" / "native_adf95_caller_w1_064_branch2.json"
    branch_capture = json.loads(branch_capture_path.read_text(encoding="utf-8"))
    branch_lines = [line for line in branch_capture["stdout"]["selected_lines"] if line.startswith("NATIVE_ADF95_BRANCH ")]
    branch_fields = [_fields(line) for line in branch_lines]
    branch_call = next((line for line in branch_capture["stdout"]["selected_lines"] if line.startswith("NATIVE_ALLOC_CALLSITE ") and "site=000dfe0d" in line), "")
    branch_call_f = _fields(branch_call) if branch_call else {}

    checks = {
        "native_recompiled_guest_and_full_tail": capture.get("execution_mode") == "native_recompiled_guest" and capture.get("command_tail") == "-k 38928",
        "fresh_natural_ax0501_no_response": capture.get("capture_only") is True and strict["response_records"] == 0 and strict["frontier"].get("eip") == "000c3cc1" and strict["frontier"].get("response_count") == "0",
        "native_setenvp_callback_reached": any("index=16" in line and "target=000dfdc1" in line for line in lines),
        "native_dfe0d_callsite_and_caller": bool(call_f) and call_f.get("caller") == "000dfdc1" and call_f.get("target") == "000adf95" and call_f.get("site") == "000dfe0d",
        "native_adf95_entry_after_callsite": bool(entry_f) and entry_f.get("va") == "000adf95" and entry_f.get("current_func") == "000adf95" and lines.index(call) < lines.index(entry),
        "original_w3_callsite_is_dynamic_return_proven": original_adf["ordinal"] == 1 and original_adf["callsite_link_va"] == "0x000DFE0D" and original_adf["return_link_va"] == "0x000DFE12",
        "first_register_mismatch_precedes_adf95_body": call_f.get("eax") == "00000001" and original_regs["eax"] == "0x00000040" and entry_f.get("eax") == "00000001",
        "same_logical_identity_not_overclaimed": capture.get("comparison", {}).get("same_dynamic_invocation_claimed") is False and original_adf["caller"].startswith("__setenvp_") and call_f.get("caller") == "000dfdc1",
        "first_native_heap_request_remains_1000": strict["request_size_bytes"] == "0x00001000" and expand_f.get("eax") == "00000001",
        "native_equal_compare_path_observed": len(branch_fields) == 2 and branch_fields[0].get("site") == "000dfe04" and branch_fields[0].get("eax") == "00000000" and branch_fields[0].get("edi") == "00000000" and branch_fields[1].get("site") == "000dfe08" and branch_fields[1].get("eax") == "00000000" and branch_call_f.get("eax") == "00000001",
        "runtime_untouched": capture["build_fingerprints"]["dos_services_source_sha256"] == "71993fb0d997fb0430e496ee04ab69f421d7fbe6e5a421f383485ec59a97e078",
    }
    recovery_rel = capture["recovery"]["verification"]
    recovery = json.loads((ROOT / recovery_rel).read_text(encoding="utf-8"))
    checks["source_recovery_verified"] = bool(recovery) and all(
        row.get("verified") is True and row.get("source_sha256") == row.get("backup_sha256") == row.get("isolated_restore_sha256")
        for row in recovery
    )
    failed = [name for name, ok in checks.items() if not ok]
    return {
        "valid": not failed,
        "checks": checks,
        "failed": failed,
        "native_dfe0d": call_f,
        "native_adf95_entry": entry_f,
        "original_adf95_registers": original_regs,
        "native_ax0501_request": strict["request_size_bytes"],
        "native_adf95_branch_events": branch_fields,
        "dynamic_equivalence_claimed": False,
    }


if __name__ == "__main__":
    evidence_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evidence" / "native_adf95_caller_w1_064.json"
    result = validate(evidence_path)
    print(json.dumps(result, indent=2))
    if not result["valid"]:
        raise SystemExit(1)
    print("PASS W1-064 native ADF95 caller evidence validator")
