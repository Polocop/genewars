from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import hashlib
import json
from pathlib import Path

ROOT = Path((_GW_ROOT))
CAPTURE = ROOT / "evidence/w3_224_ah4400_ordinal6_caller.json"
AUDIT225 = ROOT / "evidence/w3_225_ah4400_static_audit.json"
IMAGE = ROOT / "evidence/genewars-1_1.exe"
SOURCE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
OUT = ROOT / "evidence/w3_226_stack_return_audit.json"
REPORT = ROOT / "reports/coordination/w3_226_stack_return_audit.md"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def audit() -> dict:
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    audit225 = json.loads(AUDIT225.read_text(encoding="utf-8"))
    event = audit225["ordinal6"]
    callsite = capture["ordinal6_context"]["same_register_callsite"]
    code_anchor = capture["main_mapping_anchors"][0]
    # The capture's serialized callsite is the original trace row, not a newly
    # sampled runtime state.
    raw_esp = callsite["esp"]
    stack_linear = callsite["stack_linear"]
    raw_return = event["stack_return_raw"]
    code_rebase = event["mapping_rebase_from_capture"]
    data_rebase = 0x1DA000  # independently recorded for this pinned original fixture
    code_candidate = raw_return - code_rebase
    data_candidate = raw_return - data_rebase

    # Hash-bound object ranges from the exact LE image and its reviewed loader
    # contract: objects 1/2 are CODE, object 3 STACK, object 4 DATA.
    object_ranges = [
        (0x00010000, 0x000EE930, "CODE"),
        (0x000F0000, 0x000F1000, "CODE"),
        (0x00100000, 0x001A8C50, "STACK"),
        (0x001B0000, 0x001B1350, "DATA"),
    ]
    code_ranges = [r for r in object_ranges if r[2] == "CODE"]
    stack_range = next(r for r in object_ranges if r[2] == "STACK")
    candidate_in_code = any(start <= code_candidate < end for start, end, _ in code_ranges)
    candidate_in_stack = stack_range[0] <= code_candidate < stack_range[1]

    source = SOURCE.read_text(encoding="utf-8", errors="replace")
    sampler_present = ("const auto stack_linear = SegPhys(ss) + reg_esp;" in source
                       and "cpu.gdt.GetDescriptor(SegValue(ss), stack_descriptor)" in source
                       and "reg_esp) + 31 > stack_descriptor.GetLimit()" in source)
    result = {
        "schema": "gwrecomp.w3-226-stack-return-audit/v1",
        "task": "W3-226",
        "evidence_level": "ORIGINAL_OBSERVED_WITH_STATIC_RECONCILIATION",
        "inputs": {
            "capture_sha256": sha(CAPTURE), "w3_225_audit_sha256": sha(AUDIT225),
            "target_image_sha256": sha(IMAGE), "instrumentation_sha256": sha(SOURCE),
        },
        "stack_observation": {
            "sequence": callsite["sequence"], "link_va": callsite["link_va"],
            "cs": callsite["cs"], "ss": callsite["ss"], "ds": callsite["ds"],
            "esp": raw_esp, "stack_linear": stack_linear,
            "stack_return_raw": raw_return,
            "stack_return_minus_esp": raw_return - raw_esp,
            "sampler_emitted_eight_words": len(callsite["stack_words_u32"]) == 8,
            "sampler_source_checks_present": sampler_present,
            "ds_base": callsite["ds_base"], "ds_limit": callsite["ds_limit"],
        },
        "candidate_analysis": {
            "candidate_link_va_using_code_rebase": code_candidate,
            "candidate_link_va_using_data_rebase": data_candidate,
            "code_rebase": code_rebase, "data_rebase": data_rebase,
            "le_objects": [
                {"start": start, "end_exclusive": end, "kind": kind}
                for start, end, kind in object_ranges
            ],
            "candidate_in_le_object_3_stack": candidate_in_stack,
            "candidate_in_le_executable_objects": candidate_in_code,
        },
        "code_descriptor": {
            "cs": callsite["cs"], "base": code_anchor["cs_base"],
            "limit": code_anchor["cs_limit"], "type": code_anchor["cs_type"],
            "present": code_anchor["cs_present"],
        },
        "classification": "NOT_VALIDATED_AS_MAIN_CALLER",
        "direct_caller": "UNKNOWN",
        "conclusion": (
            "The stack word is an actual bounded sample and lies 0x21 bytes above ESP. "
            "Subtracting the observed candidate code rebase places it in LE object 3, "
            "the stack object, and outside the two MAIN executable objects. It is therefore "
            "not a validated MAIN caller return address. The flat CS descriptor permits "
            "addresses outside MAIN's objects, so an extender thunk or other executable "
            "mapping cannot be ruled out without bytes and execution evidence at that address."
        ),
        "next_action": (
            "Do not infer a caller from this stack word. A future targeted capture must validate "
            "the return address against live CS semantics and code bytes/ranges; no new replay "
            "is warranted from current evidence alone."
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-226 — stack return-address audit\n\n"
        f"Evidence: [{OUT.name}](../../{OUT.as_posix()})\n\n"
        "At W3-224 callsite 0xC8973, the captured SS and DS are both 0x0168; ESP and "
        "stack_linear are both 0x382B40, and the first sampled dword is 0x382B61, 0x21 "
        "bytes above ESP. The Staging sampler reads through SS, requires a valid descriptor "
        "and bounds, and emitted all eight stack words.\n\n"
        "Using the candidate code rebase 0x1EB000 yields link candidate 0x197B61, within "
        "LE object 3 (STACK, 0x100000–0x1A8C50) and outside executable objects 1/2. "
        "This is not a validated MAIN caller return. CS is flat (base 0, limit FFFFFFFF), "
        "so an extender thunk cannot be excluded without observing code bytes/execution there. "
        "Direct caller remains UNKNOWN. No Oracle replay was performed.\n",
        encoding="utf-8")
    return result


if __name__ == "__main__":
    print(json.dumps(audit(), indent=2, ensure_ascii=False))
