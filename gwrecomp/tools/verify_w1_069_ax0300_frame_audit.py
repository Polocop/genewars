"""Validate an observational native DPMI AX=0300 frame capture."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
MARKER = re.compile(r"^W1_CRT_DPMI0300_CHECK (?P<fields>.+)$")


def parse_marker(text: str) -> dict[str, str]:
    match = MARKER.match(text.strip())
    if not match:
        raise ValueError("not a W1_CRT_DPMI0300_CHECK marker")
    fields = {}
    for token in match.group("fields").split():
        if "=" not in token:
            raise ValueError(f"malformed token: {token}")
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


def validate(data: dict, *, project_root: pathlib.Path | None = None) -> list[str]:
    errors: list[str] = []
    if data.get("task") != "W1-069" or data.get("task_schema") != "gwrecomp.native-ax0300-frame-audit/v1":
        errors.append("W1-069 evidence schema is missing")
    if data.get("target_sha256") != TARGET_SHA or data.get("native_returncode") != 0:
        errors.append("fresh native capture target or exit status is invalid")
    if data.get("capture_only") is not True:
        errors.append("capture must remain observational")
    stdout = data.get("stdout")
    if not isinstance(stdout, str):
        errors.append("raw stdout is missing")
        stdout = ""
    lines = [line for line in stdout.splitlines() if line.startswith("W1_CRT_DPMI0300_CHECK ")]
    if len(lines) != 1:
        errors.append(f"expected exactly one AX=0300 observer marker; got {len(lines)}")
        fields = {}
    else:
        try:
            fields = parse_marker(lines[0])
        except ValueError as exc:
            errors.append(str(exc))
            fields = {}
    required = ("eip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "flag_k", "flag_a", "flag_b",
                "cf", "cs", "ds", "es", "ss", "es_base", "frame", "frame_valid", "frame_bytes", "inner_eax",
                "env_address", "env_segment", "env_offset", "env_valid", "env_word", "reject_mask")
    if any(key not in fields for key in required):
        errors.append("AX=0300 pre-response CPU/frame fields are incomplete")
    if fields:
        if fields.get("eip") != "000bc765" or fields.get("eax", "")[-4:].lower() != "0300":
            errors.append("observed request is not the measured native AX=0300 frontier")
        if fields.get("inner_eax", "").lower() != "00006300":
            errors.append("inner real-mode request is not AH=63/AL=00")
        if fields.get("frame_valid") != "1" or len(fields.get("frame_bytes", "")) != 100:
            errors.append("bounded 0x32-byte DPMI frame was not captured")
        try:
            mask = int(fields.get("reject_mask", "0"), 16)
        except ValueError:
            errors.append("rejection mask is malformed")
            mask = 0
        count_line = next((line for line in stdout.splitlines() if line.startswith("W1_CRT_DPMI0300 count=")), "")
        if "count=0" not in count_line:
            errors.append("the existing harness rejection state is not preserved")
        trap_line = next((line for line in stdout.splitlines() if line.startswith("NATIVE_NEXT_TRAP ")), "")
        if mask == 0 or "eip=000bc765" not in trap_line.lower():
            errors.append("fresh request was not rejected without a DOS response")
        audit = data.get("native_ax0300_frame_audit", {})
        if audit.get("cpu_frame", {}).get("frame_bytes", "").removeprefix("0x").lower() != fields.get("frame_bytes", "").lower():
            errors.append("structured native frame does not match the raw observer record")
        if audit.get("reject_mask_numeric") != mask or audit.get("observer_mutated_guest_state") is not False:
            errors.append("structured observer result is missing or claims a guest-state mutation")
        if audit.get("result") != "harness returned trapped; no DOS response was applied for this request":
            errors.append("captured response status is overstated or missing")
        original = data.get("original_comparator", {})
        if (original.get("request_ax") != "0x00006300" or original.get("response_ds") != "0x00001100" or
                original.get("response_si") != "0x00000000" or original.get("same_dynamic_invocation_claimed") is not False or
                original.get("same_context_claimed") is not False or original.get("config_size_bytes") != 0 or
                original.get("command_tail") != "-k"):
            errors.append("original AX=6300 reference or separate-run context is missing")
        if project_root is not None:
            root = project_root.resolve()
            harness = root / "tests" / "test_native_guest_image.c"
            fingerprint = data.get("build_fingerprints", {}).get("native_harness_source_sha256")
            if not harness.is_file() or hashlib.sha256(harness.read_bytes()).hexdigest() != fingerprint:
                errors.append("captured native harness fingerprint is stale")
            source = harness.read_text(encoding="utf-8") if harness.is_file() else ""
            observer_at = source.find('uint32_t frame=g_es_base+g_edi;')
            marker_at = source.find('printf("W1_CRT_DPMI0300_CHECK ', observer_at)
            guard_at = source.find('if ((g_ebx&0xffu)!=0x21u', marker_at)
            observer = source[observer_at:guard_at] if observer_at >= 0 and marker_at > observer_at and guard_at > marker_at else ""
            writes_guest = re.search(r"guest_memory\s*\[[^]]+\]\s*=", observer) is not None
            writes_cpu = re.search(r"\bg_(?:eax|ebx|ecx|edx|esi|edi|ebp|esp|flag_[a-z]+)\s*=", observer) is not None
            if not observer or "guest_memory[frame+i]" not in observer or writes_guest or writes_cpu:
                errors.append("read-only frame observer is not present in the fingerprinted harness")
            orig = root / "evidence" / "cd_present_gate_work3.json"
            if not orig.is_file():
                errors.append("original AX=6300 comparator evidence is missing")
            else:
                original_data = json.loads(orig.read_text(encoding="utf-8"))
                real_mode = next((item.get("real_mode_interrupt", {}) for item in original_data.get("interrupts", [])
                                  if item.get("real_mode_interrupt", {}).get("service") == "dos21.get_dbcs_lead_byte_table"), {})
                before = real_mode.get("registers_before", {})
                after = real_mode.get("registers_after", {})
                context_ok = (before.get("eax") == "0x00006300" and after.get("ds") == "0x00001100" and
                              after.get("esi") == "0x00000000" and original_data.get("fixture_mode", {}).get("command_tail") == "-k" and
                              original_data.get("fixture", {}).get("size") == 0)
                if not context_ok:
                    errors.append("original AX=6300 service/response or different-run fixture context did not verify")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.evidence.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"INVALID evidence: {exc}", file=sys.stderr)
        return 2
    errors = validate(data, project_root=ROOT)
    if errors:
        print("FAIL W1-069 frame audit:")
        for error in errors:
            print("- " + error)
        return 1
    print("PASS W1-069 observational AX=0300 frame audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
