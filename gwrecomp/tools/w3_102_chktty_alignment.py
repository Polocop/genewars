"""Align the first original __chktty_ call with immutable native evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_MANIFEST = ROOT / "evidence/w3_100_targeted_vesa_capture.json"
ORIGINAL_TRACE = ROOT / "build/dosboxx_oracle/C/W3_100_TARGETED_VESA_20261009_01.jsonl"
W1_CALLSITE = ROOT / "evidence/native_ah44_bx1_callsite_work1.json"
W1_ORIGIN = ROOT / "evidence/native_ah44_bx1_origin_work1.json"
SOURCE = ROOT / "build/entry_path_closure.c"
OUTPUT = ROOT / "evidence/w3_102_chktty_alignment.json"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split() if "=" in token)


def selected(path: Path, prefix: str) -> str:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return next(line for line in doc["stdout"]["selected_lines"] if line.startswith(prefix))


def build() -> dict:
    manifest = json.loads(ORIGINAL_MANIFEST.read_text(encoding="utf-8"))
    trace_bytes = ORIGINAL_TRACE.read_bytes()
    trace = [json.loads(line) for line in trace_bytes.splitlines() if line.strip()]
    original_entry = next(row for row in trace if row.get("checkpoint") == "AH44_CHKTTY_ENTRY")
    original_handle = next(row for row in trace if row.get("checkpoint") == "AH44_CHKTTY_HANDLE_LOAD")
    original_call = next(row for row in trace if row.get("checkpoint") == "AH44_CHKTTY_ISATTY_CALL")
    callbacks = [row for row in trace if row.get("event") == "original_int21_ah44"]
    code_rebase = original_entry["eip"] - original_entry["link_va"]
    return_link = original_entry["return_address"] - code_rebase
    source_text = SOURCE.read_text(encoding="utf-8")
    callsite_text = "RECOMP_CALL(sub_000BA4D6); /* 0x0009864D: call 0xba4d6 */"
    caller_setup = "eax = ecx; /* 0x0009864B: mov eax, ecx */"
    assert callsite_text in source_text and caller_setup in source_text

    native3_call = fields(selected(W1_CALLSITE, "W1_AH44_CALLSITE ordinal=3 "))
    native3_request = fields(selected(W1_ORIGIN, "W1_AH44_REQUEST ordinal=3 "))
    native11_call = fields(selected(W1_CALLSITE, "W1_AH44_CALLSITE ordinal=11 "))
    native11_request = fields(selected(W1_CALLSITE, "W1_AH44_REQUEST ordinal=11 "))
    native_doc = json.loads(W1_CALLSITE.read_text(encoding="utf-8"))
    origin_doc = json.loads(W1_ORIGIN.read_text(encoding="utf-8"))

    return {
        "schema": "w3-102-chktty-alignment/v1",
        "task": "W3-102",
        "provenance": {
            "target_sha256": manifest["preflight"]["fixture_sha256"],
            "staging_revision": manifest["preflight"]["source_revision"],
            "staging_binary_sha256": manifest["preflight"]["staging_sha256"],
            "config_sha256": manifest["preflight"]["config_sha256"],
            "original_manifest_sha256": digest(ORIGINAL_MANIFEST),
            "original_trace_sha256": digest(ORIGINAL_TRACE),
            "original_trace_bytes": len(trace_bytes),
            "w1_callsite_evidence_sha256": digest(W1_CALLSITE),
            "w1_origin_evidence_sha256": digest(W1_ORIGIN),
            "generated_closure_sha256": digest(SOURCE),
            "original_run_guard_cause": manifest["guard"]["cause"],
            "original_run_limit_seconds": manifest["preflight"]["timeout_seconds"],
        },
        "original_first_chktty": {
            "checkpoint_sequence": [original_entry["sequence"], original_handle["sequence"], original_call["sequence"]],
            "process_psp": original_entry["process_psp"],
            "code_rebase": hex(code_rebase),
            "entry_link_va": hex(original_entry["link_va"]),
            "entry_return_runtime": hex(original_entry["return_address"]),
            "entry_return_link_va": hex(return_link),
            "outer_function": "__doopen_ at 0x00098594, resolved from return VA 0x00098652 and corrected-VA call graph",
            "outer_callsite_link_va": "0x0009864D",
            "outer_call_target": "__chktty_ at 0x000BA4D6",
            "pre_call_instruction": caller_setup,
            "stream_pointer": hex(original_handle["edx"]),
            "stream_field_0d": original_call["stream_object_sample"]["field_0d_u8"],
            "stream_field_10": original_call["stream_object_sample"]["field_10_u32"],
            "value_loaded_into_eax_at_isatty_call": original_call["eax"],
            "original_bx1_persisted_callback_count": sum(row.get("in_bx") == 1 for row in callbacks),
            "persisted_callback_bx_values": sorted({row.get("in_bx") for row in callbacks}),
            "nearby_bx5_callbacks": [
                {key: row.get(key) for key in ("sequence", "ordinal", "in_ax", "in_bx", "in_dx", "out_ax", "out_dx", "cf", "cwd")}
                for row in callbacks if row.get("sequence", 0) > original_call["sequence"] and row.get("in_bx") == 5
            ],
            "callback_caller_link": "not included in DOS callback record; candidates remain sequence/register correlations",
        },
        "native_chktty_ordinals": {
            "ordinal_3": {"callsite": native3_call, "request": native3_request, "stream_field_10_loaded": int(native3_call["eax"], 16), "interpreted_bx": int(native3_request["ebx"], 16)},
            "ordinal_11": {"callsite": native11_call, "request": native11_request, "stream_field_10_loaded": int(native11_call["eax"], 16), "interpreted_bx": int(native11_request["ebx"], 16)},
            "native_target_sha256": native_doc["target_sha256"],
            "native_ordinal_11_target_sha256": origin_doc["target_sha256"],
            "callsite_instruction_fact": "The exact target code at 0xBA4E1 loads EAX=[EDX+0x10]; the checkpoint at 0xBA4E4 observes that loaded value before calling isatty_.",
        },
        "alignment": {
            "original_first_vs_native_ordinal_3": "ALIGNS by outer __doopen_ return/callsite and loaded stream-field value 5; dynamic invocation identity across runs is not proven.",
            "original_first_vs_native_ordinal_11": "DOES NOT ALIGN by stream object/value: native ordinal 11 loads 1 from a different stream pointer and is a later native invocation.",
            "original_bx1_observed": False,
            "causal_first_divergence": "UNKNOWN",
            "limits": [
                "Original W3-100 has no persisted BX=1 callback among the eight recorded AX=4400 callbacks; absence is bounded to this run/trace.",
                "Original callback records omit guest caller CS:EIP, and two adjacent BX=5 rows follow the callsite, so the exact callback-to-callsite pairing is not unique.",
                "The native command tail matches, but launcher, CPU state, memory seed, and dynamic invocation identity are not proven equivalent."
            ],
            "w2_086_unblocked": False
        },
        "scope": {"oracle_replay_performed": False, "source_modified": False, "runtime_or_core_modified": False, "guest_modified": False}
    }


def main() -> None:
    result = build()
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "original_outer_return": result["original_first_chktty"]["entry_return_link_va"], "original_field10": result["original_first_chktty"]["stream_field_10"], "native_ordinals": {str(n): result["native_chktty_ordinals"][f"ordinal_{n}"]["interpreted_bx"] for n in (3, 11)}, "original_bx1": result["alignment"]["original_bx1_observed"]}, indent=2))


if __name__ == "__main__":
    main()
