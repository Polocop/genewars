"""Read-only reconciliation of existing original and native AH=44 captures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "evidence/native_ah44_bx1_callsite_work1.json"
TAIL_EVIDENCE = ROOT / "evidence/w3_095_original_psp_tail.json"
ORIGINAL_MANIFEST = ROOT / "evidence/w3_100_targeted_vesa_capture.json"
ORIGINAL_TRACE = ROOT / "build/dosboxx_oracle/C/W3_100_TARGETED_VESA_20261009_01.jsonl"
OUTPUT = ROOT / "evidence/w3_101_original_ah44_reconciliation.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def keyed_fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split() if "=" in token)


def build() -> dict:
    native_doc = json.loads(NATIVE.read_text(encoding="utf-8"))
    tail_doc = json.loads(TAIL_EVIDENCE.read_text(encoding="utf-8"))
    original_doc = json.loads(ORIGINAL_MANIFEST.read_text(encoding="utf-8"))
    trace_bytes = ORIGINAL_TRACE.read_bytes()
    trace = [json.loads(line) for line in trace_bytes.splitlines() if line.strip()]

    native_lines = native_doc["stdout"]["selected_lines"]
    native_call_line = next(
        line for line in native_lines
        if line.startswith("W1_AH44_CALLSITE ordinal=11 ")
    )
    native_request_line = next(
        line for line in native_lines
        if line.startswith("W1_AH44_REQUEST ordinal=11 ")
    )
    original_checkpoints = [
        row for row in trace
        if row.get("event") == "target_runtime_checkpoint"
        and row.get("checkpoint") in {
            "AH44_CHKTTY_ENTRY",
            "AH44_CHKTTY_HANDLE_LOAD",
            "AH44_CHKTTY_ISATTY_CALL",
        }
    ]
    callbacks = [row for row in trace if row.get("event") == "original_int21_ah44"]
    exec_rows = [row for row in trace if row.get("event") == "dos_execute"]
    gw_exec = next(row for row in exec_rows if row.get("executable", "").lower() == "gw.exe")
    dos4gw_exec = next(row for row in exec_rows if row.get("executable", "").lower() == "dos4gw.exe")
    callback_after_callsite = next(
        row for row in callbacks
        if row["sequence"] > original_checkpoints[-1]["sequence"]
    )
    bx1_callbacks = [row for row in callbacks if row.get("in_bx") == 1]
    chktty_call = next(row for row in original_checkpoints if row["checkpoint"] == "AH44_CHKTTY_ISATTY_CALL")
    sample = chktty_call["stream_object_sample"]
    manifest_sha = sha256(ORIGINAL_MANIFEST)
    trace_sha = hashlib.sha256(trace_bytes).hexdigest()
    native_sha = sha256(NATIVE)
    tail_sha = sha256(TAIL_EVIDENCE)
    source_hashes = tail_doc.get("source_hashes", {})

    return {
        "schema": "w3-101-original-ah44-reconciliation/v1",
        "task": "W3-101",
        "evidence_kind": "read-only cross-run reconciliation",
        "provenance": {
            "native_evidence": {"path": str(NATIVE.relative_to(ROOT)), "sha256": native_sha},
            "native_sha_matches_w3_095_record": source_hashes.get("evidence/native_ah44_bx1_callsite_work1.json") == native_sha,
            "psp_tail_evidence": {"path": str(TAIL_EVIDENCE.relative_to(ROOT)), "sha256": tail_sha},
            "original_capture_manifest": {"path": str(ORIGINAL_MANIFEST.relative_to(ROOT)), "sha256": manifest_sha},
            "original_trace": {"path": str(ORIGINAL_TRACE.relative_to(ROOT)), "sha256": trace_sha, "bytes": len(trace_bytes), "events": len(trace)},
            "target_sha256": original_doc["preflight"]["fixture_sha256"],
            "original_staging_revision": original_doc["preflight"]["source_revision"],
            "original_staging_binary_sha256": original_doc["preflight"]["staging_sha256"],
            "original_config_sha256": original_doc["preflight"]["config_sha256"],
            "original_code_rebase": hex(chktty_call["eip"] - chktty_call["link_va"]),
            "original_data_rebase": hex(chktty_call["data_rebase"]),
            "original_psp": chktty_call["process_psp"],
            "original_guard_cause": original_doc["guard"]["cause"],
            "original_guard_exit": original_doc["guard"]["exit_reason"],
        },
        "launch": {
            "original_gw_tail_in_trace": gw_exec["command_tail"],
            "original_dos4gw_tail_in_trace": dos4gw_exec["command_tail"],
            "separate_original_psp_tail_evidence": tail_doc["comparison"]["original_psp_tail"],
            "native_command_tail": native_doc["command_tail"],
            "psp_tail_match_across_runs": tail_doc["comparison"]["exact_tail_match"],
            "launcher_equivalence": False,
            "limitation": "The PSP-tail evidence and W3-100 trace are separate original runs; W1 native is another run with a different launcher/argv[0]. Exact tail equality does not prove CPU or memory seed equality.",
        },
        "original": {
            "dynamic_chktty_checkpoints": original_checkpoints,
            "stream_field_0d": sample.get("field_0d_u8"),
            "stream_field_10": sample.get("field_10_u32"),
            "callsite_registers": {key: chktty_call.get(key) for key in ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "eflags", "cs", "ds", "ss", "return_address", "stack_words_u32")},
            "all_persisted_ah44_callbacks": callbacks,
            "callback_nearest_after_chktty_callsite": callback_after_callsite,
            "original_bx1_callback_count": len(bx1_callbacks),
            "original_bx1_callback_observed": bool(bx1_callbacks),
            "callback_caller_address": "not present in DOS callback record; sequence/register alignment is recorded but no callback-side caller CS:EIP is claimed",
            "bounded_trace_limit": "No BX=1 among persisted callbacks in this bounded W3-100 run is not proof the original never issues BX=1 later or in another run.",
        },
        "native": {
            "chktty_callsite": keyed_fields(native_call_line),
            "ah44_request": keyed_fields(native_request_line),
            "semantic_stream_field_10": 1,
            "stream_pointer": "0x0010A822",
            "caller_and_callsite": {"caller": "0x000BA4D6", "callsite": "0x000BA4E4", "helper_entry": "0x000C896A", "int21": "0x000C8973"},
        },
        "comparison": {
            "same_dynamic_ordinal_proven": False,
            "original_and_native_caller_link_va": "0x000BA4D6 / 0x000BA4E4 observed in corresponding callsite checkpoints, but invocation identity across runs is not established",
            "original_field_10": 5,
            "native_field_10": 1,
            "original_nearby_callback_request": {key: callback_after_callsite.get(key) for key in ("in_ax", "in_bx", "in_dx", "in_eflags", "out_ax", "out_dx", "cf", "cwd", "ordinal", "sequence")},
            "causal_first_divergence": "UNKNOWN; measured values differ at the stream/call frontier, but distinct launches and unaligned invocation ordinal prevent causal attribution",
            "service_contract_for_bx1": "NOT OBSERVED in the bounded original trace; the measured original BX=5 response must not be reused for BX=1",
            "w2_086_unblocked": False,
        },
        "scope": {"oracle_replay_performed": False, "source_or_fixture_modified": False, "native_or_original_response_fabricated": False},
    }


def main() -> None:
    result = build()
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "original_stream_field_10": result["original"]["stream_field_10"], "original_bx1_count": result["original"]["original_bx1_callback_count"], "native_bx1": result["native"]["ah44_request"].get("ebx"), "tail_match": result["launch"]["psp_tail_match_across_runs"]}, indent=2))


if __name__ == "__main__":
    main()
