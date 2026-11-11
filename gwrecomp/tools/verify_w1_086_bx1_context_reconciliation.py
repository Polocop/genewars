#!/usr/bin/env python3
"""Build/validate an offline W3-236 vs W1-085 BX=1 context reconciliation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
NATIVE_PATH = ROOT / "evidence/native_setup_replay_w1_085.json"
ORIGINAL_PATH = ROOT / "evidence/w3_236_chktty_original_capture.json"
TRACE_PATH = ROOT / "build/dosboxx_oracle/C/W3_236_CHKTTY_AX4400.jsonl"
OUTPUT_PATH = ROOT / "evidence/native_ah4400_w3_236_reconciliation_w1_086.json"
REPORT_PATH = ROOT / "reports/coordination/native_ah4400_w3_236_reconciliation_w1_086.md"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_reconciliation() -> dict:
    native = read_json(NATIVE_PATH)
    original = read_json(ORIGINAL_PATH)
    trace = [json.loads(line) for line in TRACE_PATH.read_text(encoding="utf-8").splitlines() if line]

    original_points = original["chktty_and_bx1"]
    checkpoints = original_points["chktty_checkpoints"]
    by_name = {item["checkpoint"]: item for item in checkpoints}
    original_isatty = by_name["AH44_ISATTY_ENTRY"]
    original_chktty = by_name["AH44_CHKTTY_ENTRY"]
    original_call = by_name["AH44_CHKTTY_ISATTY_CALL"]
    original_bx1 = original_points["bx1_callsites"][0]

    native_origin = native["native_ah4400_origin"]
    native_call = next(
        item for item in native_origin["callsite_events"]
        if item["caller"] == "000ba4d6" and item["site"] == "000ba4e4"
        and item["target"] == "000c896a" and item["eax"] == "00000001"
    )
    native_helper = next(
        item for item in native_origin["helper_entry_events"]
        if item["ordinal"] == native_call["ordinal"] and item["eip"] == "000c896a"
    )
    native_frontier = native["frontier"]["request_registers"]

    trace_bx1 = next(
        item for item in trace
        if item.get("sequence") == original_bx1["sequence"]
        and item.get("event") == "original_cpu_int21_ah44_bx1_entry"
    )
    original_call_events = [
        item for item in trace
        if item.get("sequence") == original_call["sequence"]
        and item.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL"
    ]
    original_entry_events = [
        item for item in trace
        if item.get("sequence") == original_isatty["sequence"]
        and item.get("checkpoint") == "AH44_ISATTY_ENTRY"
    ]

    evidence = {
        "schema": "gwrecomp-w1-086-bx1-context-reconciliation/v1",
        "task": "W1-086",
        "classification": "INCONCLUSIVE_CAUSAL_ALIGNMENT",
        "source_artifacts": {
            "native_w1_085": {"path": str(NATIVE_PATH.relative_to(ROOT)), "sha256": sha256(NATIVE_PATH)},
            "original_w3_236": {"path": str(ORIGINAL_PATH.relative_to(ROOT)), "sha256": sha256(ORIGINAL_PATH)},
            "original_trace_w3_236": {
                "path": str(TRACE_PATH.relative_to(ROOT)),
                "sha256": sha256(TRACE_PATH),
                "event_count": len(trace),
            },
        },
        "run_context": {
            "native_capture_id": native["capture_id"],
            "native_fixture_id": native["fixture_id"],
            "native_command_tail": native["command_tail"],
            "native_original_equivalence_claimed": native["original_equivalence_claimed"],
            "original_run_id": original["guard"]["run_id"],
            "original_effective_psp_tail": original["effective_psp_tail"],
            "original_target_sha256": original["preflight"]["target_sha256"],
            "original_cue_sha256": original["preflight"]["cue_sha256"],
            "original_config_sha256": original["preflight"]["config_sha256"],
        },
        "original_observations": {
            "chktty_entry": {
                "sequence": original_chktty["sequence"],
                "link_va": f"0x{original_chktty['link_va']:X}",
                "return_address_runtime": f"0x{original_chktty['return_address']:X}",
                "eax": f"0x{original_chktty['eax']:X}",
                "ebx": f"0x{original_chktty['ebx']:X}",
                "esp": f"0x{original_chktty['esp']:X}",
            },
            "chktty_isatty_call": {
                "sequence": original_call["sequence"],
                "link_va": f"0x{original_call['link_va']:X}",
                "eax": f"0x{original_call['eax']:X}",
                "stream_field_value": f"0x{original_call['eax']:X}",
                "ebx": f"0x{original_call['ebx']:X}",
                "esp": f"0x{original_call['esp']:X}",
            },
            "observed_isatty_entry": {
                "sequence": original_isatty["sequence"],
                "link_va": f"0x{original_isatty['link_va']:X}",
                "eax": f"0x{original_isatty['eax']:X}",
                "return_address_runtime": f"0x{original_isatty['return_address']:X}",
                "esp": f"0x{original_isatty['esp']:X}",
            },
            "bx1_request": {
                "sequence": original_bx1["sequence"],
                "int_link_va": f"0x{original_bx1['int_instruction_link_va']:X}",
                "return_link_va": f"0x{original_bx1['return_link_va']:X}",
                "eax": f"0x{original_bx1['eax']:X}",
                "ebx": f"0x{original_bx1['ebx']:X}",
                "edx": f"0x{original_bx1['edx']:X}",
                "esp": f"0x{original_bx1['esp']:X}",
                "eflags": f"0x{original_bx1['eflags']:X}",
                "caller": "UNKNOWN",
                "stream_field_value": f"0x{original[ 'chktty_and_bx1']['bx1_callsites'][0]['value_at_plus_0x10'] if 'value_at_plus_0x10' in original['chktty_and_bx1']['bx1_callsites'][0] else 1:X}",
            },
            "timeline": {
                "observed_isatty_entry_sequence": original_isatty["sequence"],
                "chktty_callsite_sequence": original_call["sequence"],
                "bx1_request_sequence": original_bx1["sequence"],
                "same_dynamic_invocation_id_available": False,
                "chktty_call_records": len(original_call_events),
                "observed_isatty_entry_records": len(original_entry_events),
                "mapped_bx1_int_records": 1 if trace_bx1.get("mapping_valid") else 0,
                "unpaired_original_bx1_event": True,
            },
        },
        "native_observations": {
            "caller": "__chktty_ 0xBA4D6 -> isatty_ callsite 0xBA4E4",
            "callsite_ordinal": native_call["ordinal"],
            "target_link_va": f"0x{int(native_call['target'], 16):X}",
            "eax_at_callsite": f"0x{int(native_call['eax'], 16):X}",
            "eax_at_helper_entry": f"0x{int(native_helper['eax'], 16):X}",
            "frontier_link_va": f"0x{int(native[ 'frontier']['guest_eip'], 16):X}",
            "frontier_request_ax": f"0x{int(native_frontier['eax'], 16):X}",
            "frontier_request_bx": f"0x{int(native_frontier['ebx'], 16):X}",
        },
        "classification": {
            "same_dynamic_invocation_established": False,
            "same_address_is_insufficient": True,
            "reason": "The original captured __chktty_ -> isatty_ call has EAX/stream value 5 and precedes BX=5 callbacks; the mapped BX=1 request is a later event whose caller is unknown. W1-085's native EAX=1 invocation is separately identified, but no original BX=1 caller is paired to it.",
            "first_causal_divergence_proven": False,
            "core_defect_demonstrated": False,
        },
        "minimal_original_observation_needed": {
            "scope": "one changed-instrumentation original capture; no fixture or register injection",
            "at_function_entry": "Record every dynamic entry at link VA 0xC896A with invocation ordinal, EAX/EBX/ECX/EDX/ESI/EDI/EBP/ESP, EFLAGS, SS:ESP stack words, and the real return address/callsite.",
            "at_interrupt": "At link VA 0xC8973 record the same fields plus [DS:EDX+0x10], and correlate to the active 0xC896A invocation using a per-entry token or a validated stack/return relation.",
            "required_result": "Identify the caller/entry context that produces the natural BX=1 event, or report no matching 0xC896A activation; do not equate the separate EAX=5 __chktty_ call with BX=1.",
        },
        "no_new_original_replay_performed": True,
        "dos_response_supplied": False,
        "menu_framebuffer_or_gameplay_claimed": False,
    }
    validate_evidence(evidence)
    return evidence


def validate_evidence(data: dict) -> None:
    assert data["schema"] == "gwrecomp-w1-086-bx1-context-reconciliation/v1"
    assert data["classification"]["same_dynamic_invocation_established"] is False
    assert data["classification"]["first_causal_divergence_proven"] is False
    assert data["original_observations"]["chktty_isatty_call"]["eax"] == "0x5"
    assert data["original_observations"]["bx1_request"]["ebx"] == "0x1"
    assert data["original_observations"]["bx1_request"]["caller"] == "UNKNOWN"
    assert data["native_observations"]["eax_at_helper_entry"] == "0x1"
    assert data["native_observations"]["frontier_request_bx"] == "0x1"
    assert data["original_observations"]["chktty_isatty_call"]["sequence"] < data["original_observations"]["bx1_request"]["sequence"]
    assert data["minimal_original_observation_needed"]["at_function_entry"].startswith("Record every dynamic entry")
    assert data["no_new_original_replay_performed"] is True
    assert data["dos_response_supplied"] is False


def render_report(data: dict) -> str:
    original = data["original_observations"]
    native = data["native_observations"]
    hashes = data["source_artifacts"]
    return f"""# W1-086 — BX=1 dynamic-context reconciliation

## Result

The captures are **not established as the same dynamic invocation**. The original W3-236 capture records `__chktty_` entry `{original['chktty_entry']['link_va']}` and its callsite `{original['chktty_isatty_call']['link_va']}` to `isatty_` entry `0xC896A`, with EAX/stream value `{original['chktty_isatty_call']['eax']}`. The mapped BX=1 request at `{original['bx1_request']['int_link_va']}` occurs later at sequence {original['bx1_request']['sequence']}; its caller remains unknown. The original trace does not pair that request to the captured EAX=5 invocation.

W1-085's native caller is `{native['caller']}`, with EAX `{native['eax_at_callsite']}` at the callsite and `{native['eax_at_helper_entry']}` at helper entry, followed by the BX={native['frontier_request_bx']} frontier at `{native['frontier_link_va']}`. Matching link VAs do not establish dynamic identity across these separate runs.

**No first causal divergence or Core defect is proven.** No DOS response was supplied and no new original replay was run.

## Minimal next observation for WORK3

On one changed-instrumentation original capture, log every dynamic entry at link VA `0xC896A` with ordinal, full general registers, EFLAGS, SS:ESP stack sample, and real return address/callsite. At `0xC8973`, capture the same context plus `[DS:EDX+0x10]`, then correlate it to the active `0xC896A` entry using an invocation token or validated stack/return relation. The deliverable is the caller and state that naturally produce BX=1, or an explicit no-match. Do not pair the separate EAX=5 call with BX=1 by address alone.

## Source fingerprints

- W1-085 native JSON: `{hashes['native_w1_085']['sha256']}`
- W3-236 original JSON: `{hashes['original_w3_236']['sha256']}`
- W3-236 bounded trace: `{hashes['original_trace_w3_236']['sha256']}` ({hashes['original_trace_w3_236']['event_count']} events)
"""


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in {"--write", str(OUTPUT_PATH)}:
        data = read_json(Path(sys.argv[1]))
        validate_evidence(data)
        print("W1-086 reconciliation evidence: PASS")
        return 0
    data = build_reconciliation()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT_PATH.write_text(render_report(data), encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.relative_to(ROOT)}")
    print(f"Wrote {REPORT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
