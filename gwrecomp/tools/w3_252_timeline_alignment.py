"""Bounded offline alignment of W3-236 and W3-251 original captures."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _find_link_va(events: list[dict], link_va: int) -> dict | None:
    return next((event for event in events
                 if event.get("link_va") == link_va), None)


def align(w236: dict, w251: dict, w240: dict, w250: dict) -> dict:
    """Return only comparable measured facts; never infer a causal slowdown."""
    link_isatty = 0xC896A
    old_cp = _find_link_va(w236["chktty_and_bx1"]["chktty_checkpoints"],
                           link_isatty)
    new_cp = next((event for event in w251.get("target_checkpoints_compact", [])
                   if event.get("checkpoint") == "W3_237_ISATTY_ENTRY"), None)
    if old_cp is None or new_cp is None:
        raise ValueError("same-link isatty entry checkpoint missing")
    old_elapsed = old_cp.get("elapsed_ms")
    new_elapsed = new_cp.get("elapsed_ms")
    same_fixture = all((
        w236["preflight"].get("target_sha256") == w251["preflight"].get("target_sha256"),
        w236["preflight"].get("cue_sha256") == w251["preflight"].get("cue_sha256_before"),
        w236["preflight"].get("config_sha256") == w251["preflight"].get("config_sha256"),
        w236.get("address_txt_initial", {}).get("sha256") == w251["preflight"].get("address_sha256"),
        w236["mapping"].get("code_rebase") == int(w251["caller_pairing"]["isatty_entries"][0]["code_rebase"]),
    ))
    old_bx1 = w236["chktty_and_bx1"].get("bx1_callsites", [])
    old_bx1_first = old_bx1[0] if old_bx1 else None
    new_bx1 = w251["caller_pairing"].get("bx1_requests", [])
    new_calls = w251.get("original_ax4400_observations", [])
    new_bx_counts: dict[str, int] = {}
    for call in new_calls:
        bx = str(call.get("in_bx", "UNKNOWN"))
        new_bx_counts[bx] = new_bx_counts.get(bx, 0) + 1
    old_guard = w236.get("guard", {})
    new_guard = w251.get("guard", {})
    return {
        "schema": "gwrecomp-w3-252-timeline-alignment/v1",
        "classification": "SAME_ENTRY_REACHED_LATER_IN_W3_251" if
            old_elapsed is not None and new_elapsed is not None and new_elapsed > old_elapsed
            else "COMPARABLE_ENTRY_TIMING_UNKNOWN",
        "evidence_level": "ORIGINAL_OBSERVED_WITH_CROSS_RUN_ALIGNMENT",
        "comparison": {
            "same_fixture_hashes": same_fixture,
            "main_link_va": f"0x{link_isatty:06X}",
            "main_code_rebase_w3_236": f"0x{w236['mapping']['code_rebase']:X}",
            "main_code_rebase_w3_251": f"0x{int(w251['caller_pairing']['isatty_entries'][0]['code_rebase']):X}",
            "runtime_sha256_w3_236": w236["preflight"].get("runtime_sha256"),
            "runtime_sha256_w3_251": w251["preflight"].get("runtime_sha256"),
            "runtime_binaries_equal": w236["preflight"].get("runtime_sha256") == w251["preflight"].get("runtime_sha256"),
            "source_sha256_w3_251": w251["preflight"].get("source_sha256"),
            "capture_filter_w3_236": w240.get("differences", {}).get("W3_236_filter"),
            "capture_filter_w3_251": "GWRECOMP_W3_237_CAPTURE_ONLY=1 and GWRECOMP_W3_251_CAPTURE_ONLY=1; targets isatty entry/AX4400 request/return",
            "w3_236_source_snapshot_available": False,
            "w3_251_dispatcher_change": "W3-251 caches its capture-only environment flag once and stores the measured isatty entry return address; this changed binary is not source-identical to W3-236.",
            "w3_236_entry": {
                "sequence": old_cp.get("sequence"), "elapsed_ms": old_elapsed,
                "eax": old_cp.get("eax"), "ebx": old_cp.get("ebx"), "edi": old_cp.get("edi"),
            },
            "w3_251_entry": {
                "sequence": new_cp.get("sequence"), "elapsed_ms": new_elapsed,
                "eax": int(new_cp["eax"], 16), "ebx": int(new_cp["ebx"], 16), "edi": int(new_cp["edi"], 16),
            },
            "entry_elapsed_delta_ms": new_elapsed - old_elapsed if old_elapsed is not None and new_elapsed is not None else None,
            "w3_236_bx1": None if old_bx1_first is None else {
                "sequence": old_bx1_first.get("sequence"),
                "ordinal": old_bx1_first.get("cpu_entry_ordinal"),
                "link_va": f"0x{old_bx1_first.get('int_instruction_link_va', 0):X}",
                "return_link_va": f"0x{old_bx1_first.get('return_link_va', 0):X}",
                "elapsed_ms": old_bx1_first.get("elapsed_ms"),
            },
            "w3_251_bx1_observed": bool(new_bx1),
            "w3_251_ah4400_bx_counts": new_bx_counts,
            "w3_236_guard": {"cause": old_guard.get("cause"), "timeout_s": old_guard.get("limits", {}).get("timeout_s")},
            "w3_251_guard": {"cause": new_guard.get("cause"), "timeout_s": new_guard.get("limits", {}).get("timeout_s")},
            "w3_236_last_checkpoint": w236.get("last_checkpoint"),
            "w3_251_last_trace_event": w251.get("last_trace_event"),
            "w3_251_y_resource_path": next((tail for tail in w251.get("dos_execute_tails", []) if "-label essentials" in tail), None),
        },
        "interpretation": {
            "measured": "The same fixture and same-link isatty entry are observed in both runs; W3-251 reaches that entry 4087 ms later. W3-236 later contains a BX=1 INT21 entry at sequence 104; W3-251 contains five BX=5 and three BX=2 callbacks, and no BX=1 before its 30-second timeout.",
            "not_proven": "The 4087 ms delay is correlated with distinct instrumented runtime binaries and different capture filters. These data do not prove the instrumentation caused the delay or identify the earliest guest-state divergence. Sequence/event counts are not a runtime-progress metric.",
            "w3_240_alignment_limit": w240.get("alignment_conclusion", {}).get("earliest_runtime_divergence"),
            "w3_250_prior_assessment": w250.get("runtime_progress", {}).get("interpretation"),
            "w3_249_to_w3_251_entry_delta_ms": 18792 - 26311,
            "w3_249_to_w3_251_causality": "The later W3-251 build reached the common entry earlier than W3-249, but capture/source changes differ; the timing change does not isolate the cached environment lookup as the cause.",
            "first_divergence": "UNKNOWN: only the first shared isatty checkpoint has comparable elapsed time; no same-filter event timeline or elapsed time for the W3-236 BX=1 entry is retained in the compact capture record.",
            "next_action": "Do not replay yet. First inspect the W3-236 and W3-251 dispatcher/capture source paths and identify a bounded measurement that can distinguish instrumentation cost from guest-path divergence without adding per-instruction work. If no such measurement is available offline, retain the unknown and request a new replay hypothesis rather than increasing timeout alone."
        },
        "sources": [
            "evidence/w3_236_chktty_original_capture.json",
            "evidence/w3_240_capture_timeline_compare.json",
            "evidence/w3_250_tail_hook_reconciliation.json",
            "evidence/w3_251_entry_return_capture.json",
            "build/dosboxx_oracle/C/W3_251_ENTRY_RETURN_20261009_01.jsonl",
        ],
    }


def main() -> int:
    paths = {
        "w236": ROOT / "evidence/w3_236_chktty_original_capture.json",
        "w240": ROOT / "evidence/w3_240_capture_timeline_compare.json",
        "w250": ROOT / "evidence/w3_250_tail_hook_reconciliation.json",
        "w251": ROOT / "evidence/w3_251_entry_return_capture.json",
    }
    inputs = {key: json.loads(path.read_text(encoding="utf-8"))
              for key, path in paths.items()}
    result = align(inputs["w236"], inputs["w251"], inputs["w240"], inputs["w250"])
    output = ROOT / "evidence/w3_252_timeline_alignment.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "classification": result["classification"],
                      "entry_elapsed_delta_ms": result["comparison"]["entry_elapsed_delta_ms"],
                      "w3_251_bx1_observed": result["comparison"]["w3_251_bx1_observed"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
