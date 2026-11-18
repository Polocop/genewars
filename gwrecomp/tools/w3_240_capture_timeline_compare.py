#!/usr/bin/env python3
"""Read-only comparison of the W3-236 and W3-239 original traces."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W236_JSON = ROOT / "evidence/w3_236_chktty_original_capture.json"
W236_TRACE = ROOT / "build/dosboxx_oracle/C/W3_236_CHKTTY_AX4400.jsonl"
W239_JSON = ROOT / "evidence/w3_239_bx1_dynamic_pairing.json"
W239_TRACE = ROOT / "build/dosboxx_oracle/C/W3_239_BX1_PAIRING.jsonl"
OUT = ROOT / "evidence/w3_240_capture_timeline_compare.json"
REPORT = ROOT / "reports/coordination/w3_240_capture_timeline_compare.md"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_trace(path: Path, max_bytes: int = 1_048_576) -> tuple[list[dict], dict]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"trace exceeds recorded 1 MiB bound: {path}")
    events = [json.loads(line) for line in raw.decode("utf-8", "strict").splitlines() if line.strip()]
    return events, {"path": str(path.relative_to(ROOT)).replace("\\", "/"),
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "event_count": len(events)}


def checkpoint_list(events: list[dict]) -> list[dict]:
    out = []
    for event in events:
        if event.get("event") == "target_runtime_checkpoint":
            out.append({"sequence": event.get("sequence"),
                        "checkpoint": event.get("checkpoint"),
                        "link_va": event.get("link_va"),
                        "eax": event.get("eax"), "ebx": event.get("ebx"),
                        "edx": event.get("edx"), "eflags": event.get("eflags"),
                        "return_address": event.get("return_address"),
                        "w3_237_event_ordinal": event.get("w3_237_event_ordinal"),
                        "w3_237_correlated_entry_ordinal": event.get("w3_237_correlated_isatty_entry_ordinal"),
                        "correlation_valid": event.get("w3_237_correlation_valid"),
                        "elapsed_ms": event.get("elapsed_ms")})
    return out


def callback_list(events: list[dict]) -> list[dict]:
    return [{"sequence": e.get("sequence"), "ordinal": e.get("ordinal"),
             "ax": e.get("in_ax"), "bx": e.get("in_bx"), "cf": e.get("cf"),
             "main_code_rebase": e.get("main_code_rebase"), "cwd": e.get("cwd")}
            for e in events if e.get("event") == "original_int21_ah44"]


def summarize() -> dict:
    old = read_json(W236_JSON)
    new = read_json(W239_JSON)
    old_events, old_trace = read_trace(W236_TRACE)
    new_events, new_trace = read_trace(W239_TRACE)
    for evidence, trace in ((old, old_trace), (new, new_trace)):
        recorded = evidence.get("trace", {})
        if recorded.get("sha256") != trace["sha256"] or recorded.get("bytes") != trace["bytes"]:
            raise ValueError(f"raw trace does not match capture evidence: {trace['path']}")
    old_calls = [e for e in old_events if e.get("event") == "original_cpu_int21_ah44_bx1_entry"]
    old_calls.extend(e for e in old_events if e.get("event") == "target_runtime_checkpoint"
                     and e.get("checkpoint") == "DOS_AH44_BX1_CALLSITE")
    new_calls = [x for x in new.get("bx1_requests", [])]
    new_entry = (new.get("isatty_entries") or [None])[0]
    new_req = (new.get("ah4400_requests") or [None])[0]
    new_ret = (new.get("ah4400_returns") or [None])[0]
    mapping_old = old.get("mapping") or {}
    mapping_new = new.get("main_mapping") or {}
    callback_old, callback_new = callback_list(old_events), callback_list(new_events)
    shared = {
        "target_sha256_equal": old.get("preflight", {}).get("target_sha256") == new.get("preflight", {}).get("target_sha256"),
        "cue_sha256_equal": old.get("preflight", {}).get("cue_sha256") == new.get("preflight", {}).get("original_cue_sha256"),
        "config_sha256_equal": old.get("preflight", {}).get("config_sha256") == new.get("preflight", {}).get("dosbox_config_sha256"),
        "main_code_rebase_equal": mapping_old.get("code_rebase") == mapping_new.get("code_rebase"),
        "fixture_sha256_equal": old.get("preflight", {}).get("target_sha256") == new.get("preflight", {}).get("target_sha256"),
        "address_txt_sha256_equal": (old.get("address_txt_initial", {}).get("sha256") ==
                                      new.get("address_txt_initial", {}).get("sha256")),
    }
    code = old.get("preflight", {}).get("runtime_sha256")
    code_new = new.get("preflight", {}).get("runtime_sha256")
    old_bx1 = []
    for event in old_calls:
        old_bx1.append({"sequence": event.get("sequence"),
                        "link_va": event.get("int_instruction_link_va", event.get("link_va")),
                        "ax": event.get("eax", event.get("eax")),
                        "bx": event.get("ebx", event.get("ebx")),
                        "esp": event.get("esp"), "return_link_va": event.get("return_link_va"),
                        "main_rebase": event.get("main_code_rebase", event.get("main_code_rebase"))})
    result = {
        "schema": "gwrecomp-w3-240-capture-timeline-comparison/v1",
        "task": "W3-240",
        "evidence_level": "ORIGINAL_OBSERVED_WITH_CROSS_RUN_LIMITATIONS",
        "captures": {
            "W3-236": {"evidence_path": "evidence/w3_236_chktty_original_capture.json",
                       "evidence_sha256": sha256(W236_JSON), "trace": old_trace,
                       "runtime_sha256": code, "staging_revision": old.get("preflight", {}).get("staging_revision"),
                       "guard_exit": old.get("guard", {}).get("exit_reason"),
                       "duration_s": old.get("guard", {}).get("duration_s"),
                       "last_checkpoint": old.get("last_checkpoint"),
                       "mapping": mapping_old,
                       "effective_psp_tail": old.get("effective_psp_tail"),
                       "target_bx1_events": old_bx1,
                       "isatty_checkpoints": [e for e in checkpoint_list(old_events)
                                               if e.get("checkpoint") == "AH44_ISATTY_ENTRY"],
                       "dos_ax4400_callbacks": callback_old,
                       "checkpoint_count": len(checkpoint_list(old_events))},
            "W3-239": {"evidence_path": "evidence/w3_239_bx1_dynamic_pairing.json",
                       "evidence_sha256": sha256(W239_JSON), "trace": new_trace,
                       "runtime_sha256": code_new, "staging_revision": new.get("preflight", {}).get("staging_revision"),
                       "guard_exit": new.get("guard", {}).get("exit_reason"),
                       "duration_s": new.get("guard", {}).get("duration_s"),
                       "last_event": (new_events[-1].get("event") if new_events else None),
                       "mapping": mapping_new,
                       "effective_psp_tail": new.get("effective_psp_tail_in_capture"),
                       "isatty_entry": new_entry,
                       "ax4400_request": new_req,
                       "ax4400_return": new_ret,
                       "target_bx1_events": new_calls,
                       "dos_ax4400_callbacks": callback_new,
                       "checkpoint_count": len(checkpoint_list(new_events))},
        },
        "shared_measured_facts": shared,
        "differences": {
            "instrumented_runtime_binary_sha256_equal": code == code_new,
            "trace_event_count_ratio_is_not_execution_progress": {
                "W3_236": old_trace["event_count"], "W3_239": new_trace["event_count"],
                "reason": "The instrumentation/checkpoint filters and binary hashes differ; event counts cannot be compared as guest progress."},
            "guard_timeouts_both_30s": True,
            "W3_236_filter": "broad selected checkpoint set; no per-invocation token at C896A->C8973",
            "W3_239_filter": "opt-in C896A-C8975 instruction window; per-invocation token at entry/request/return",
        },
        "alignment_conclusion": {
            "same_static_mapping": bool(shared["main_code_rebase_equal"] and mapping_old.get("code_rebase")),
            "first_dynamic_call_in_W3_239": "isatty entry ordinal 1 EAX=5/EBX=2 -> AX=4400/BX=5 -> AX=2/DX=2/CF=0",
            "W3_236_BX1_pairing": "unpaired; its captured entry and later BX=1 have no same-run invocation token",
            "same_dynamic_invocation_proven": False,
            "earliest_runtime_divergence": "UNKNOWN: run observations are separate and their trace filters/binaries differ; only the W3-239 first invocation is token-correlated.",
            "first actionable evidence difference": "W3-239 proves the first captured EAX=5 invocation returns through link 0xAFCF4 and requests BX=5. It does not establish the caller or ordinal of W3-236's BX=1 at sequence 104.",
        },
        "next_action": "Keep the original BX=1 caller unresolved. Use the recorded run timelines and differing binaries to derive a new capture hypothesis only if it can target the later natural invocation without changing guest state; no unchanged replay is justified.",
    }
    return result


def main() -> None:
    result = summarize()
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-240 — W3-236 / W3-239 original trace comparison\n\n"
        f"- W3-236 trace: {result['captures']['W3-236']['trace']['event_count']} events, {result['captures']['W3-236']['trace']['bytes']} bytes; DOSBox SHA-256 `{result['captures']['W3-236']['runtime_sha256']}`.\n"
        f"- W3-239 trace: {result['captures']['W3-239']['trace']['event_count']} events, {result['captures']['W3-239']['trace']['bytes']} bytes; DOSBox SHA-256 `{result['captures']['W3-239']['runtime_sha256']}`.\n"
        f"- Same target/CUE/config hashes: {result['shared_measured_facts']['target_sha256_equal']}/{result['shared_measured_facts']['cue_sha256_equal']}/{result['shared_measured_facts']['config_sha256_equal']}.\n"
        f"- Same recorded MAIN code rebase: `{result['captures']['W3-236']['mapping'].get('code_rebase')}` and `{result['captures']['W3-239']['mapping'].get('code_rebase')}`.\n"
        f"- W3-239 dynamically pairs its first EAX=5 entry to BX=5 and return; W3-236's BX=1 remains unpaired.\n\n"
        "Trace counts cannot be read as progress because the instrumented binaries and capture filters differ. Both runs ended at the 30-second guard. The earliest runtime divergence is therefore unknown. The W3-239 first invocation cannot be equated to W3-236's later BX=1 solely from the shared static address.\n\n"
        f"Next action: {result['next_action']}\n\n"
        "Evidence JSON: `evidence/w3_240_capture_timeline_compare.json`.\n", encoding="utf-8")
    print(json.dumps({"result": str(OUT), "report": str(REPORT),
                      "shared_facts": result["shared_measured_facts"],
                      "same_runtime_binary": result["differences"]["instrumented_runtime_binary_sha256_equal"],
                      "bx1_unpaired": not result["alignment_conclusion"]["same_dynamic_invocation_proven"]}, indent=2))


if __name__ == "__main__":
    main()
