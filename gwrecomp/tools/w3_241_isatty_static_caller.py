#!/usr/bin/env python3
"""Correlate the W3-239 first isatty return address to hash-bound static data."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "build/dosboxx_oracle/C/GENEWARS/GW.EXE"
STATIC = ROOT / "evidence/critical_path_static_work1.json"
DYNAMIC = ROOT / "evidence/w3_239_bx1_dynamic_pairing.json"
OLD_ORIGINAL = ROOT / "evidence/w3_236_chktty_original_capture.json"
OUT = ROOT / "evidence/w3_241_isatty_static_caller.json"
REPORT = ROOT / "reports/coordination/w3_241_isatty_static_caller.md"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
TARGET_SIZE = 1_251_658


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def analyze() -> dict:
    if not TARGET.is_file() or TARGET.stat().st_size != TARGET_SIZE:
        raise ValueError("authentic GW.EXE size is absent or changed")
    target_hash = sha256(TARGET)
    if target_hash != TARGET_SHA:
        raise ValueError("authentic GW.EXE SHA-256 does not match W3-067 target")
    static = json.loads(STATIC.read_text(encoding="utf-8-sig"))
    dynamic = json.loads(DYNAMIC.read_text(encoding="utf-8-sig"))
    old = json.loads(OLD_ORIGINAL.read_text(encoding="utf-8-sig"))
    if static.get("target_sha256") != target_hash:
        raise ValueError("static caller evidence is not bound to the current target")
    call = next((x for x in static["static_ah44_provenance"]["static_callers"]
                 if x.get("callsite") == "0x000AFCEF"), None)
    if not call or call.get("caller") != "sopen_":
        raise ValueError("expected hash-bound sopen_ callsite 0xAFCEF is absent")
    captured = dynamic["dynamic_caller_observation"]
    return_link = int(captured["entry_return_link_va"], 16)
    callsite = int(call["callsite"], 16)
    main_rebase = int(dynamic["main_mapping"]["code_rebase"])
    return_runtime = int(captured["entry_return_runtime"], 16)
    entry = dynamic["isatty_entries"][0]
    request = dynamic["ah4400_requests"][0]["event"]
    bx1 = dynamic["bx1_requests"]
    relation = (return_link == callsite + 5 and
                return_runtime - main_rebase == return_link and
                int(entry["link_va"]) == 0xC896A and
                entry["return_address"] == return_runtime)
    argument = {
        "static_source": call["entry_eax"],
        "dynamic_eax": f"0x{entry['eax']:X}",
        "dynamic_edi": f"0x{entry['edi']:X}",
        "dynamic_values_match": entry["eax"] == entry["edi"] == 5,
        "interpretation": "W1-047 static local dataflow says sopen_ passes the successfully opened DOS handle carried in EDI; W3-239 observes EAX=EDI=5 at the matching dynamic entry. This identifies the first captured invocation only.",
    }
    return {
        "schema": "gwrecomp-w3-241-isatty-static-caller/v1",
        "task": "W3-241",
        "evidence_level": "ORIGINAL_OBSERVED_WITH_STATIC_CORROBORATION",
        "target": {"path": str(TARGET.relative_to(ROOT)).replace("\\", "/"),
                   "size": TARGET.stat().st_size, "sha256": target_hash},
        "static_source": {"path": str(STATIC.relative_to(ROOT)).replace("\\", "/"),
                          "sha256": sha256(STATIC), "target_sha256": static["target_sha256"],
                          "caller": call["caller"], "function_entry": "0x000AFC8D",
                          "callsite": "0x000AFCEF", "target": "0x000C896A",
                          "callsite_return_link_va": "0x000AFCF4",
                          "entry_eax_flow": call["entry_eax"], "guard": call["guard"],
                          "other_static_callers": [x for x in static["static_ah44_provenance"]["static_callers"]
                                                   if x.get("callsite") != "0x000AFCEF"]},
        "dynamic_source": {"path": str(DYNAMIC.relative_to(ROOT)).replace("\\", "/"),
                           "sha256": sha256(DYNAMIC), "run_id": dynamic["guard"]["run_id"],
                           "entry_link_va": captured["entry_link_va"],
                           "entry_ordinal": captured["entry_ordinal"],
                           "entry_eax": captured["entry_eax"], "entry_edi": f"0x{entry['edi']:X}",
                           "return_runtime": captured["entry_return_runtime"],
                           "return_link_va": captured["entry_return_link_va"],
                           "main_code_rebase": f"0x{main_rebase:X}",
                           "return_matches_static_callsite": relation,
                           "request_link_va": captured["request_link_va"],
                           "request_ax": captured["request_ax"], "request_bx": captured["request_bx"],
                           "request_correlated_entry_ordinal": dynamic["ah4400_requests"][0]["correlated_entry_ordinal"],
                           "return_ax": captured["return_ax"], "return_dx": captured["return_dx"],
                           "return_cf": captured["return_cf"],
                           "memory_field_ds_edx_plus_10": captured["ds_edx_plus_0x10"]},
        "argument_corroboration": argument,
        "chktty_comparison": {"static_callsite": "0x000BA4E4", "caller": "__chktty_",
                              "dynamic_w3_239_is_chktty": False,
                              "reason": "W3-239's first entry return link 0xAFCF4 matches sopen_'s call return, not __chktty_'s return link 0xBA4E9."},
        "later_bx1_status": {"w3_236_request_sequence": old["chktty_and_bx1"]["bx1_callsites"][0]["sequence"],
                              "w3_236_dynamic_caller": "UNKNOWN",
                              "same_invocation_as_w3_239_first_call": False,
                              "proof": "W3-239's active token correlates its entry ordinal 1 only with BX=5. W3-236 is a separate run without a token connecting its sequence-104 BX=1 to that call.",
                              "remaining_question": "The natural original caller of the later BX=1 event remains unresolved."},
        "native_comparison": {"w1_task": "W1-085", "caller": "__chktty_ 0xBA4D6 -> callsite 0xBA4E4",
                              "entry_eax": "0x1", "request_bx": "0x1",
                              "same_run_or_same_dynamic_call": False},
        "conclusion": "The first captured original isatty invocation is dynamically correlated to sopen_ at 0xAFCEF and carries EAX=EDI=5, which is the opened DOS handle according to hash-bound static local dataflow. Its request is BX=5. This does not resolve W3-236's later BX=1 caller.",
    }


def main() -> None:
    result = analyze()
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-241 — Static caller for the first captured original isatty call\n\n"
        f"The exact target hash `{result['target']['sha256']}` is verified. Existing hash-bound static evidence maps `sopen_` entry `0xAFC8D`, callsite `0xAFCEF`, to `isatty_` entry `0xC896A`. The call returns at `0xAFCF4`.\n\n"
        f"W3-239 measured the matching runtime return at `0x29ACF4`; with the same-run MAIN code rebase `0x1EB000`, the link return is `0xAFCF4`. This pairs the **first captured dynamic entry** to `sopen_`. At entry EAX and EDI were both `5`. W1-047's static dataflow says `sopen_` passes the successful DOS handle carried in EDI; the runtime values corroborate that path. Its AX=4400 request was BX=5 and returned AX=2/DX=2/CF=0.\n\n"
        "This is distinct from the static `__chktty_` callsite `0xBA4E4`. It does not pair W3-236's later BX=1 event at sequence 104 to `sopen_`; W3-236 has no invocation token for that event. The original BX=1 caller remains UNKNOWN. Native W1-085 is also a separate run.\n\n"
        "Evidence: `evidence/w3_241_isatty_static_caller.json`.\n", encoding="utf-8")
    print(json.dumps({"result": str(OUT), "report": str(REPORT),
                      "caller": result["static_source"]["caller"],
                      "callsite": result["static_source"]["callsite"],
                      "dynamic_return_match": result["dynamic_source"]["return_matches_static_callsite"],
                      "later_bx1_resolved": False}, indent=2))


if __name__ == "__main__":
    main()
