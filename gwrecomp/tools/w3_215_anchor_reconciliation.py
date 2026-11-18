"""Validate and summarize the already captured W3-213 heap anchor."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
W3_213 = ROOT / "evidence/w3_213_adjustamount_original.json"
W3_068 = ROOT / "evidence/w3_068_heap_alignment_original_20261008.json"
W1 = ROOT / "evidence/w1_heap_init_alignment_20261008.json"
OUT = ROOT / "evidence/w3_215_anchor_reconciliation.json"
REPORT = ROOT / "reports/coordination/w3_215_anchor_reconciliation.md"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reconcile() -> dict:
    a = json.loads(W3_213.read_text(encoding="utf-8"))
    b = json.loads(W3_068.read_text(encoding="utf-8"))
    c = json.loads(W1.read_text(encoding="utf-8"))
    capture = a["capture"]["main_mapping"]["anchor"]
    samples = {int(s["link_offset"]): s for s in capture["selected_global_samples"]}
    required = {0x10B78E, 0x10B78F, 0x10B790, 0x10C824, 0x10C828}
    if not required.issubset(samples):
        raise ValueError("required original anchor samples are missing")
    if capture["anchor"] != "CREATE_NEW_NHEAP_ENTRY" or not capture["measured_address_matches"]:
        raise ValueError("CreateNewNHeap anchor was not measured at its expected runtime address")
    if capture["link_va"] != 0xC3D7A or capture["candidate_rebase"] != 0x1EB000:
        raise ValueError("unexpected anchor link VA or code rebase")
    if capture["data_rebase"] != 0x1DA000:
        raise ValueError("unexpected measured data rebase")
    if capture["process_psp"] != 7811 or capture["invocation_ordinal"] != 1:
        raise ValueError("unexpected process or invocation ordinal")

    modes = {f"0x{off:06X}": samples[off]["value_u32"] & 0xFF
             for off in (0x10B78E, 0x10B78F, 0x10B790)}
    threshold = samples[0x10C828]["value_u32"]
    if modes != {"0x10B78E": 1, "0x10B78F": 0, "0x10B790": 0} or threshold != 0x10:
        raise ValueError("W3-213 sample values differ from the captured evidence")

    original = b["original_adjustamount"]
    native = c["native"]["adjustamount"]
    if not original["input_value"].startswith("0x40,") or original["return_observation"]["argument_slot_after_return"] != "0x00001000":
        raise ValueError("W3-068 comparison values do not match source evidence")
    if native["threshold_global"]["0x10C828"] != "0x8000":
        raise ValueError("W1 native threshold does not match source evidence")

    source_paths = [W3_213, W3_068, W1]
    return {
        "schema": "w3-215-anchor-reconciliation/v1",
        "task": "W3-215",
        "classification": "MEASURED_ANCHOR_WITH_UNRESOLVED_ADJUSTMENT_CAUSALITY",
        "sources": {str(p.relative_to(ROOT)).replace("\\", "/"): {"sha256": sha256(p)} for p in source_paths},
        "original_w3_213": {
            "run_id": a["run_id"],
            "target_sha256": a["source"]["fixture_sha256"],
            "staging_revision": a["source"]["source_revision"],
            "instrumented_runtime_sha256": a["source"]["runtime_sha256"],
            "process_psp": capture["process_psp"],
            "invocation_ordinal": capture["invocation_ordinal"],
            "anchor": "__CreateNewNHeap_ entry",
            "link_va": "0x000C3D7A",
            "runtime_linear": f"0x{capture['linear']:08X}",
            "code_rebase": "0x001EB000",
            "data_rebase": "0x001DA000",
            "measured_address_matches": True,
            "registers": {k: f"0x{capture[k]:08X}" for k in ("eax", "ebx", "esi", "edi", "eflags")},
            "sampled_mode_bytes": modes,
            "sampled_global_10c824": f"0x{samples[0x10C824]['value_u32']:08X}",
            "sampled_global_10c828": f"0x{threshold:08X}",
            "sampling_point": "CreateNewNHeap entry anchor only",
        },
        "separate_run_comparisons": {
            "w3_068_original": {
                "run_id": "w3-068-heap-alignment-original-20261008-01",
                "adjustamount_link_entry": original["link_va"],
                "adjustamount_input": "0x40",
                "input_source_note": original["input_value"],
                "post_call_argument_slot": original["return_observation"]["argument_slot_after_return"],
                "threshold_10c828": "NOT_CAPTURED_IN_THIS_RUN",
            },
            "w1_native": {
                "adjustamount_input": native["input_value"],
                "threshold_10c828": native["threshold_global"]["0x10C828"],
                "result": native["result"],
            },
            "same_invocation_or_seed_equivalence": "NOT_ESTABLISHED",
        },
        "missing": [
            "W3-213 did not record the C3D98 AdjustAmount callsite, C3F76 entry, or C3D9D return.",
            "The sampled W3-213 threshold at CreateNewNHeap entry is not proven to be read by the absent AdjustAmount invocation.",
            "The W3-068 AdjustAmount input/output and W3-213 global sample are from separate original runs.",
        ],
        "causal_conclusion": "No causal conclusion: W3-213 measures [0x10C828]=0x10 at CreateNewNHeap entry; W3-068 separately measures AdjustAmount input 0x40 and post-call slot 0x1000 while its threshold is absent. W1 native separately measures threshold 0x8000. These observations motivate a future matched entry/return capture but do not establish why outputs differ.",
    }


def write_outputs(data: dict) -> None:
    OUT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        "# W3-215 — Original heap anchor reconciliation\n\n"
        "## Result\n\n"
        "W3-213's existing original replay measured `[0x10C828] = 0x10` at the verified `__CreateNewNHeap_` entry anchor (ordinal 1, PSP 7811). It also sampled mode bytes `01 00 00`. This is a real same-run anchor measurement, not an AdjustAmount entry/return capture.\n\n"
        "W3-068 is a separate original run: it measured AdjustAmount input `0x40` and the post-call stack slot `0x1000`; the threshold was not captured there. W1's native evidence separately reports threshold `0x8000`. Same invocation/seed equivalence and causal use of the W3-213 sampled global are not established.\n\n"
        "W3-213 still lacks checkpoints C3D98, C3F76, and C3D9D. No replay was run for this reconciliation.\n\n"
        "## Evidence\n\n"
        "Machine-readable source hashes and observations: `evidence/w3_215_anchor_reconciliation.json`.\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    result = reconcile()
    write_outputs(result)
    print(json.dumps({"task": "W3-215", "classification": result["classification"], "evidence": str(OUT)}, indent=2))
