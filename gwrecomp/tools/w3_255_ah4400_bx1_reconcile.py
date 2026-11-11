"""Extract the already-captured same-run original BX=1 DOS return from W3-236."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "build/dosboxx_oracle/C/W3_236_CHKTTY_AX4400.jsonl"
MANIFEST = ROOT / "evidence/w3_236_chktty_original_capture.json"
OUTPUT = ROOT / "evidence/w3_255_ah4400_bx1_reconcile.json"
TARGET_HASH = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def pair_bx1(events: list[dict]) -> dict:
    entries = [e for e in events if e.get("event") == "original_cpu_int21_ah44_bx1_entry"
               and e.get("mapping_valid") is True and e.get("w3_093_sample_target") is True]
    results = [e for e in events if e.get("event") == "setup_dos_api"
               and e.get("operation") == "INT21_AH44"]
    tails = [e for e in events if e.get("event") == "w3_095_original_psp_tail"]
    pairs = []
    for entry in entries:
        result = next((e for e in results
                       if e.get("process_psp") == entry.get("process_psp")
                       and e.get("ordinal") == entry.get("setup_dos_api_callback_ordinal")
                       and e.get("in_ax", 0) & 0xffff == 0x4400
                       and e.get("in_bx", 0) & 0xffff == 1), None)
        tail = next((e for e in tails if e.get("process_psp") == entry.get("process_psp")
                     and e.get("callsite_link_va", "").lower() == "0xc8973"), None)
        pairs.append({"entry": entry, "dos_result": result, "psp_tail": tail,
                      "result_cf": bool(result and (result.get("out_eflags", 0) & 1)),
                      "complete": bool(result and tail)})
    return {"valid_protected_entries": len(entries), "pairs": pairs,
            "unmapped_entries": [e for e in events
                if e.get("event") == "original_cpu_int21_ah44_bx1_entry"
                and e.get("mapping_valid") is not True]}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    events = [json.loads(line) for line in TRACE.read_text(encoding="utf-8").splitlines() if line]
    pairing = pair_bx1(events)
    if len(pairing["pairs"]) != 1 or not pairing["pairs"][0]["complete"]:
        raise RuntimeError("expected exactly one complete valid original BX=1 entry/result/tail tuple")
    pair = pairing["pairs"][0]
    entry, result, tail = pair["entry"], pair["dos_result"], pair["psp_tail"]
    if manifest.get("preflight", {}).get("target_sha256") != TARGET_HASH:
        raise RuntimeError("W3-236 target hash mismatch")
    if entry.get("int_instruction_link_va") != 0xC8973 or entry.get("return_link_va") != 0xC8975:
        raise RuntimeError("original MAIN mapping/callsite does not match expected site")
    out_flags = result["out_eflags"]
    out = {
        "schema": "gwrecomp-w3-255-ah4400-bx1-reconcile/v1", "task": "W3-255",
        "classification": "ORIGINAL_SAME_RUN_BX1_RESPONSE_PAIRED",
        "evidence_level": "ORIGINAL_OBSERVED",
        "provenance": {"source_manifest": str(MANIFEST), "source_trace": str(TRACE),
            "trace_sha256": manifest["trace"]["sha256"], "trace_bytes": manifest["trace"]["bytes"],
            "target_sha256": manifest["preflight"]["target_sha256"],
            "runtime_sha256": manifest["preflight"]["runtime_sha256"],
            "cue_sha256": manifest["preflight"].get("cue_sha256"),
            "config_sha256": manifest["preflight"].get("config_sha256")},
        "same_run_contract": {
            "process_psp": entry["process_psp"], "entry_sequence": entry["sequence"],
            "entry_ordinal": entry["cpu_entry_ordinal"],
            "main_code_rebase": entry["main_code_rebase"],
            "cs_selector": entry["cs_selector"], "cs_base": entry["cs_base"],
            "int_instruction_link_va": "0x000C8973", "return_link_va": "0x000C8975",
            "mapping_valid": entry["mapping_valid"], "int21_bytes_verified": entry["int21_bytes_verified"],
            "input": {"AX": "0x4400", "BX": "0x0001", "ECX": entry["ecx"],
                      "EDX": entry["edx"], "DS": entry["ds"], "EFLAGS": entry["eflags"]},
            "dos_callback_sequence": result["sequence"],
            "dos_callback_ordinal": result["ordinal"],
            "output": {"AX": f"0x{result['out_ax'] & 0xffff:04X}",
                       "DX": f"0x{result['out_dx'] & 0xffff:04X}",
                       "EFLAGS": f"0x{out_flags:08X}", "CF": bool(out_flags & 1)},
            "handle": result["entry"], "resolved_path": result["resolved_path"],
            "default_drive": result["default_drive"], "cwd": result["cwd"],
            "result_boolean": result["result"], "dos_error_field": result.get("dos_error"),
            "psp_tail_sequence": tail["sequence"], "psp_tail_length": tail["tail_length"],
            "psp_tail_hex": tail["tail_bytes_hex"], "psp_tail_text": " -k 38928",
            "caller": "UNKNOWN", "full_startup_seed_equivalence": False,
        },
        "other_same_run_entry": [{"sequence": e["sequence"], "mapping_valid": e.get("mapping_valid"),
             "cs_selector": e.get("cs_selector"), "old_eip": e.get("old_eip"),
             "note": "real-mode/non-MAIN INT entry; excluded from the protected request pairing"}
             for e in pairing["unmapped_entries"]],
        "cross_run_corroboration": {"source": "evidence/w3_206_ah44_tail_reconciliation.json",
            "relationship": "consistent reported BX=1/CON response, separate earlier run; not used to pair this result"},
        "limits": ["The response is tied to the protected request by process PSP and DOS callback ordinal, but Staging's service record does not capture the protected caller function; caller remains UNKNOWN.",
            "This confirms the same-run original behavior for this invocation only; it does not establish complete equivalence with the native W1 replay or authorize unblocking W2-086.",
            "The CPU hook emits a second unmapped real-mode entry for the same register values; it is not treated as another MAIN call."],
    }
    OUTPUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "request_sequence": entry["sequence"],
                      "response_sequence": result["sequence"], "AX": out["same_run_contract"]["output"]["AX"],
                      "DX": out["same_run_contract"]["output"]["DX"],
                      "CF": out["same_run_contract"]["output"]["CF"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
