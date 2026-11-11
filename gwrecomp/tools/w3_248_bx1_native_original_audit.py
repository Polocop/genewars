"""Offline comparison of the W1-085 native frontier with measured originals."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "native": ROOT / "evidence/native_setup_replay_w1_085.json",
    "original_run": ROOT / "evidence/w3_236_chktty_original_capture.json",
    "reconciliation": ROOT / "evidence/w3_242_bx1_reconciliation.json",
    "original_contract": ROOT / "evidence/w3_091_ah4400_bx1_caller.json",
    "raw_trace": ROOT / "build/dosboxx_oracle/C/W3_236_CHKTTY_AX4400.jsonl",
}
OUTPUT = ROOT / "evidence/w3_248_bx1_native_original_audit.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_tail(argv: list[dict]) -> str:
    args = [str(x.get("string", "")) for x in argv]
    return " " + " ".join(args[1:]) if len(args) > 1 else ""


def same_hex(left, right) -> bool:
    try:
        return int(str(left), 16) == int(str(right).removeprefix("0x"), 16)
    except (TypeError, ValueError):
        return str(left).lower() == str(right).lower()


def reconcile(native: dict, original: dict, original_contract: dict,
              old_reconciliation: dict, source_hashes: dict) -> dict:
    nf = native["frontier"]
    nr = nf["request_registers"]
    bx1 = original["bx1"]
    old = old_reconciliation["same_run_response_contracts"]
    w236 = next(x for x in old if x["source"] == "W3-236")
    w091 = next(x for x in old if x["source"] == "W3-091")
    n_tail = command_tail(native["argv"]["values"] and [
        {"string": value} for value in native["argv"]["values"]])
    o_tail = original["effective_psp_tail"]
    original_calls = original["chktty_callpoints"]
    original_bx1_sequence = bx1["sequence"]
    earlier_original_calls = [x for x in original_calls if x.get("sequence", -1) < original_bx1_sequence]
    matching_eax1 = [x for x in earlier_original_calls if str(x.get("eax")).lower() in ("1", "0x1", "0x00000001")]
    return {
        "schema": "gwrecomp-w3-248-bx1-native-original-audit/v1",
        "task": "W3-248",
        "evidence_level": "ORIGINAL_OBSERVED",
        "source_hashes": source_hashes,
        "native_frontier": {
            "source": "evidence/native_setup_replay_w1_085.json",
            "link_va": nf["guest_eip"],
            "function_entry": nf["request_registers"].get("function"),
            "vector": nf["request_registers"].get("vector"),
            "request_ax": nf["request_ax"],
            "request_registers": nr,
            "response": None,
            "stop_reason": nf["stop_reason"],
            "command_tail": n_tail,
            "argv": native["argv"]["values"],
            "dynamic_caller": native.get("caller_provenance", {}).get("dynamic_caller")
                or "__chktty_ 0x000BA4D6 -> isatty_ 0x000C896A, callsite 0x000BA4E4",
        },
        "original_same_tail_run": {
            "source": "evidence/w3_236_chktty_original_capture.json",
            "command_tail": o_tail,
            "target_sha256": original["preflight"]["target_sha256"],
            "staging_revision": original["preflight"]["staging_revision"],
            "cue_sha256": original["preflight"]["cue_sha256"],
            "config_sha256": original["preflight"]["config_sha256"],
            "psp": original.get("bx1", {}).get("process_psp", original["mapping"].get("process_psp")),
            "code_rebase": hex(original["mapping"]["code_rebase"]),
            "data_rebase": hex(original["mapping"]["data_rebase"]),
        },
        "request_comparison": {
            "same_link_va": nf["guest_eip"].lower() == "0x000c8973",
            "command_tail_equal": n_tail == o_tail,
            "fields": {
                "AX": {"native": nr.get("eax"), "original": bx1["eax_hex"], "equal": same_hex(nr.get("eax"), bx1["eax_hex"])},
                "BX": {"native": nr.get("ebx"), "original": bx1["ebx_hex"], "equal": same_hex(nr.get("ebx"), bx1["ebx_hex"])},
                "CX": {"native": nr.get("ecx"), "original": bx1["ecx_hex"], "equal": same_hex(nr.get("ecx"), bx1["ecx_hex"])},
                "DX_EDX_address_value": {"native": nr.get("edx"), "original": bx1["edx_hex"], "equal": same_hex(nr.get("edx"), bx1["edx_hex"]), "interpretation": "address-valued register; cross-process values are not compared as semantic input"},
                "ESP": {"native": nr.get("esp"), "original": bx1["esp_hex"], "equal": same_hex(nr.get("esp"), bx1["esp_hex"]), "interpretation": "different address spaces/stack state; not an ordinal identity"},
                "EFLAGS_CS_DS_ES_SS": {"native": "not present at native frontier", "original": {k: bx1.get(k) for k in ("eflags_hex", "cs_hex", "ds_hex", "es_hex", "ss_hex")}, "equal": None},
            },
            "same_dynamic_invocation": False,
        },
        "original_call_chain": {
            "observed_chktty_callpoints_before_bx1": earlier_original_calls,
            "matching_eax1_chktty_callpoint_before_bx1": matching_eax1,
            "bx1_event": bx1,
            "dynamic_caller_for_bx1": "UNKNOWN",
            "explanation": "The same-tail original capture has an earlier __chktty_/isatty_ call with EAX=5 at sequence 43; its mapped BX=1 event is sequence 104 and has no paired helper-entry/call token. It does not establish the native EAX=1 caller for the original run.",
        },
        "original_response_contract": {
            "W3_236_same_run": w236,
            "W3_091_same_run": w091,
            "native_response_observed": False,
        },
        "address_txt_provenance": {
            "original_initial": original["address_txt_initial"],
            "native_fixture": native["fixtures"],
            "content_sha256_equal": original["address_txt_initial"]["sha256"] == native["fixtures"]["native"]["address_txt_sha256"],
            "creation_history": "UNKNOWN; byte identity to the known-functional package is verified, but first creation/installation history is not.",
        },
        "another_original_run": {
            "same_tail_capture_exists": True,
            "same_tail_capture_source": "W3-236",
            "unchanged_capture_would_add_new_observation": False,
            "needed_changed_instrumentation": "A same-run caller token spanning __chktty_/direct isatty_ entry, callsite, and the exact BX=1 INT event; retain caller ordinal and return pairing. Existing W3-236 hooks captured EAX=5 call and later BX=1 without that pairing.",
        },
        "classification": ("SAME_SERVICE_AND_TAIL_CROSS_RUN_CORROBORATION_CALLER_UNRESOLVED"
                           if n_tail == o_tail else "CROSS_RUN_SERVICE_CORROBORATION_LAUNCH_TAIL_DIFFERS"),
        "native_differential_established": False,
        "menu_reached": False,
        "framebuffer_reached": False,
        "gameplay_reached": False,
    }


def build_result() -> dict:
    for path in SOURCES.values():
        if not path.is_file():
            raise FileNotFoundError(path)
    loaded = {name: json.loads(path.read_text(encoding="utf-8-sig"))
              for name, path in SOURCES.items() if name != "raw_trace"}
    raw_path = SOURCES["raw_trace"]
    raw_events = [json.loads(line) for line in raw_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    raw_bx1 = [event for event in raw_events if event.get("event") == "original_cpu_int21_ah44_bx1_entry"
               and event.get("int_instruction_link_va") == 0x000C8973]
    if not raw_bx1:
        raise ValueError("hash-bound raw trace has no mapped BX=1 event at link VA 0xC8973")
    w236 = loaded["original_run"]
    checkpoints = w236["chktty_and_bx1"]["chktty_checkpoints"]
    calls = [row for row in checkpoints if row.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL"]
    bx1 = raw_bx1[0]
    native = loaded["native"]
    native["caller_provenance"] = {"dynamic_caller": "__chktty_ 0x000BA4D6 -> isatty_ 0x000C896A, callsite 0x000BA4E4"}
    original = {
        **w236,
        "effective_psp_tail": w236.get("effective_psp_tail"),
        "chktty_callpoints": calls,
        "bx1": {
            "sequence": bx1.get("sequence"),
            "link_va": f"0x{bx1.get('int_instruction_link_va'):08x}",
            "eax_hex": f"0x{bx1['eax']:08x}", "ebx_hex": f"0x{bx1['ebx']:08x}",
            "ecx_hex": f"0x{bx1['ecx']:08x}", "edx_hex": f"0x{bx1['edx']:08x}",
            "esp_hex": f"0x{bx1['esp']:08x}", "eflags_hex": f"0x{bx1['eflags']:08x}",
            "cs_hex": f"0x{bx1['cs_selector']:04x}", "ds_hex": f"0x{bx1['ds']:04x}",
            "es_hex": f"0x{bx1['es']:04x}", "ss_hex": f"0x{bx1['ss']:04x}",
            "process_psp": bx1.get("process_psp"), "paired_callback_sequence": 107,
        },
    }
    hashes = {name: {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256(path)}
              for name, path in SOURCES.items()}
    hashes["raw_trace"]["recorded_sha256_matches"] = hashes["raw_trace"]["sha256"] == w236["trace"]["sha256"]
    if not hashes["raw_trace"]["recorded_sha256_matches"]:
        raise ValueError("W3-236 raw trace hash does not match its recorded evidence")
    return reconcile(native, original, loaded["original_contract"], loaded["reconciliation"], hashes)


if __name__ == "__main__":
    result = build_result()
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "classification": result["classification"],
                      "tail_equal": result["request_comparison"]["command_tail_equal"],
                      "caller": result["original_call_chain"]["dynamic_caller_for_bx1"],
                      "address_sha_equal": result["address_txt_provenance"]["content_sha256_equal"]}, indent=2))
