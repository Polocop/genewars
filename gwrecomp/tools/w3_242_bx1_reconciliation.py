"""Read-only reconciliation of original BX=1 captures W3-091 and W3-236."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(relpath: str) -> tuple[dict, str]:
    data = (ROOT / relpath).read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def analyze() -> dict:
    w3091, hash091 = _load("evidence/w3_091_ah4400_bx1_caller.json")
    w3236, hash236 = _load("evidence/w3_236_chktty_original_capture.json")
    w3241, hash241 = _load("evidence/w3_241_isatty_static_caller.json")

    contract = w3091["verified_contract"]
    caller = contract["caller"]
    request = contract["request"]
    event = w3236["chktty_and_bx1"]["bx1_callsites"][0]
    static = w3241["static_source"]
    trace_path = ROOT / "build/dosboxx_oracle/C/W3_236_CHKTTY_AX4400.jsonl"
    trace_bytes = trace_path.read_bytes()
    trace_hash = hashlib.sha256(trace_bytes).hexdigest()
    if trace_hash != w3236["trace"]["sha256"]:
        raise ValueError("W3-236 raw trace hash does not match its structured evidence")
    raw_callback = None
    for line in trace_bytes.splitlines():
        item = json.loads(line)
        if item.get("sequence") == 107 and item.get("event") == "setup_dos_api":
            raw_callback = item
            break
    if raw_callback is None:
        raise ValueError("W3-236 callback sequence 107 is absent")
    if raw_callback.get("ordinal") != event["setup_dos_api_callback_ordinal"]:
        raise ValueError("W3-236 callback ordinal does not match pre-dispatch record")
    if raw_callback.get("process_psp") != event["process_psp"]:
        raise ValueError("W3-236 callback PSP does not match pre-dispatch record")

    mappings = {
        "process_psp": (event["process_psp"], caller["process_psp"]),
        "cs_selector": (event["cs_selector"], int(caller["cs_selector"], 16)),
        "code_rebase": (event["main_code_rebase"], int(caller["main_code_rebase"], 16)),
        "int_instruction_link_va": (event["int_instruction_link_va"], int(caller["link_va_of_int_instruction"], 16)),
        "return_link_va": (event["return_link_va"], int(caller["return_link_va"], 16)),
        "eax": (event["eax"], int(request["ax"], 16)),
        "ebx": (event["ebx"], int(request["bx"], 16)),
        "ecx": (event["ecx"], int(request["cx"], 16)),
        "edx": (event["edx"], int(caller["registers_in"]["edx"], 16)),
        "esi": (event["esi"], int(caller["registers_in"]["esi"], 16)),
        "eflags": (event["eflags"], int(caller["registers_in"]["eflags"], 16)),
        "ds": (event["ds"], int(caller["registers_in"]["ds"], 16)),
        "es": (event["es"], int(caller["registers_in"]["es"], 16)),
        "ss": (event["ss"], int(caller["registers_in"]["ss"], 16)),
    }
    comparisons = {
        name: {"w3_236": left, "w3_091": right, "equal": left == right}
        for name, (left, right) in mappings.items()
    }
    response = contract["response"]
    callback_correlation = contract["callback_correlation"]
    return {
        "schema": "gwrecomp-w3-242-bx1-cross-run-reconciliation/v1",
        "task": "W3-242",
        "classification": "CROSS_RUN_STATE_CORROBORATION",
        "sources": {
            "W3-091": {"path": "evidence/w3_091_ah4400_bx1_caller.json", "sha256": hash091},
            "W3-236": {"path": "evidence/w3_236_chktty_original_capture.json", "sha256": hash236},
            "W3-241": {"path": "evidence/w3_241_isatty_static_caller.json", "sha256": hash241},
            "W3-236 raw trace": {"path": "build/dosboxx_oracle/C/W3_236_CHKTTY_AX4400.jsonl", "sha256": trace_hash},
        },
        "comparison": {
            "fields": comparisons,
            "all_compared_fields_equal": all(value["equal"] for value in comparisons.values()),
            "w3_236_sequence": event["sequence"],
            "w3_091_run_id": w3091["run_id"],
            "same_run": False,
            "shared_invocation_identity": False,
        },
        "same_run_response_contracts": [
            {
                "source": "W3-091",
                "pre_dispatch_sequence": contract["callback_correlation"]["sequence_order"][0],
                "callback_sequence": contract["callback_correlation"]["sequence_order"][1],
                "setup_dos_api_ordinal": contract["callback_correlation"]["setup_dos_api_ordinal"],
                "request": request,
                "response": response,
                "dos_context": contract["dos_context"],
            },
            {
                "source": "W3-236",
                "pre_dispatch_sequence": event["sequence"],
                "callback_sequence": raw_callback["sequence"],
                "setup_dos_api_ordinal": raw_callback["ordinal"],
                "request": {"ax": hex(raw_callback["in_ax"]), "bx": hex(raw_callback["in_bx"])},
                "response": {
                    "ax": hex(raw_callback["out_ax"]), "dx": hex(raw_callback["out_dx"]),
                    "cf": raw_callback["cf"], "success": raw_callback["result"],
                },
                "dos_context": {
                    "handle": raw_callback["entry"], "resolved_path": raw_callback["resolved_path"],
                    "default_drive": raw_callback["default_drive"], "cwd": raw_callback["cwd"],
                },
            },
        ],
        "site_and_caller": {
            "int_instruction_link_va": "0x000C8973",
            "containing_helper": "isatty_",
            "helper_entry_link_va": "0x000C896A",
            "w3_241_first_eax5_helper_caller": static.get("caller"),
            "bx1_helper_caller": "UNKNOWN",
            "reason": "W3-236 captures the INT instruction state but has no paired helper-entry/return token for this event; the W3-241 sopen_ result belongs to a separate EAX=5 invocation.",
        },
        "limitations": [
            "Matching request fields and link VA across different runs corroborate a repeated state; they do not establish the same dynamic invocation.",
            "Each DOS response is causally paired only to its own run's pre-dispatch event and callback ordinal 24; matching across runs is corroboration, not shared invocation identity.",
            "No whole-run equivalence, menu, or framebuffer claim is made.",
        ],
        "evidence_level": "ORIGINAL_OBSERVED",
    }
