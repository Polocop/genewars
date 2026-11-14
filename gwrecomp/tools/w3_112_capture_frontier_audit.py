"""Read-only reconciliation of W3-111's PlayIntro trace frontier."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.w3_111_playintro_return_capture import source_coverage

CAPTURE = ROOT / "evidence/w3_111_playintro_return_capture.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_111_PLAYINTRO_RETURN_20261009_01.jsonl"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
STATIC = ROOT / "evidence/w3_108_playintro_continuation.json"
DISASM = ROOT / "evidence/genewars-1_1-le_disasm.s"
W3_107 = ROOT / "evidence/w3_107_main_transition.json"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
CHECKPOINTS = (0x94342, 0x92930, 0x9FDCC, 0xA3A00, 0x9FDF9)
FIRST_TARGET = 0x92983


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def build_evidence() -> dict[str, Any]:
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    static = json.loads(STATIC.read_text(encoding="utf-8"))
    w3_107 = json.loads(W3_107.read_text(encoding="utf-8"))
    source = CORE.read_text(encoding="utf-8")
    disasm = DISASM.read_text(encoding="utf-8")
    rows = read_rows(TRACE)

    if capture["preflight"]["fixture_sha256"] != TARGET_SHA:
        raise ValueError("W3-111 fixture hash mismatch")
    if capture["trace"]["sha256"] != file_sha(TRACE):
        raise ValueError("W3-111 trace hash mismatch")
    if capture["preflight"]["core_source_sha256"] != file_sha(CORE):
        raise ValueError("W3-111 source hash mismatch")
    if capture["preflight"]["staging_revision"] != "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f":
        raise ValueError("pinned Staging revision mismatch")

    coverage = source_coverage(source)
    row_by_link: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        link = row.get("link_va")
        if isinstance(link, int):
            row_by_link.setdefault(link, []).append(row)

    observed = []
    for link in CHECKPOINTS:
        matches = row_by_link.get(link, [])
        observed.append({
            "link_va": f"0x{link:08X}",
            "observed": bool(matches),
            "records": [{
                "sequence": row.get("sequence"),
                "checkpoint": row.get("checkpoint"),
                "runtime_eip": f"0x{row['eip']:08X}" if isinstance(row.get("eip"), int) else None,
                "code_rebase": f"0x{row['eip'] - link:08X}" if isinstance(row.get("eip"), int) else None,
                "data_rebase": f"0x{row['data_rebase']:08X}" if isinstance(row.get("data_rebase"), int) else None,
                "elapsed_ms": row.get("elapsed_ms"),
                "w3_107_targeted": row.get("w3_107_targeted_main_transition"),
                "w3_109_targeted": row.get("w3_109_targeted_playintro_return"),
            } for row in matches],
        })

    prior = row_by_link.get(0x94342, [])
    prior_armed = any(row.get("w3_107_targeted_main_transition") is True for row in prior)
    target_rows = row_by_link.get(FIRST_TARGET, [])
    target_cover = coverage[FIRST_TARGET]
    has_order_gate = "link_va == 0x00092983 && (w3_107_seen_mask & (1u << 6))" in source
    has_prior_bit = "case 0x00094342: w3_107_target_bit = 1u << 6; break;" in source
    static_first_call = "call   PlaySmacker" in disasm[disasm.index("PlayIntro:\t/* 0x92930 */"):disasm.index("PlaySmacker:\t/* 0x929d0 */")]
    dynamic_code_rebases = sorted({
        row["eip"] - row["link_va"] for row in rows
        if isinstance(row.get("eip"), int) and isinstance(row.get("link_va"), int)
        and row.get("link_va") in CHECKPOINTS
    })
    dynamic_data_rebases = sorted({
        row["data_rebase"] for row in rows
        if row.get("link_va") in CHECKPOINTS and isinstance(row.get("data_rebase"), int)
    })
    expected = capture["preflight"]["target_coverage"].get(f"0x{FIRST_TARGET:08X}", {})
    target_visibility = all(target_cover[key] and expected.get(key) for key in ("selected", "one_cycle"))
    predicate_ready = prior_armed and has_order_gate and has_prior_bit

    return {
        "schema": "w3-112-capture-frontier-audit/v1",
        "task": "W3-112",
        "target_sha256": TARGET_SHA,
        "inputs": {
            "capture": {"path": str(CAPTURE.relative_to(ROOT)), "sha256": file_sha(CAPTURE)},
            "trace": {"path": str(TRACE.relative_to(ROOT)), "sha256": file_sha(TRACE), "bytes": TRACE.stat().st_size},
            "instrumenter": {"path": str(CORE.relative_to(ROOT)), "sha256": file_sha(CORE)},
            "static_map": {"path": str(STATIC.relative_to(ROOT)), "sha256": file_sha(STATIC)},
            "disassembly": {"path": str(DISASM.relative_to(ROOT)), "sha256": file_sha(DISASM)},
            "w3_107": {"path": str(W3_107.relative_to(ROOT)), "sha256": file_sha(W3_107)},
        },
        "mapping": {
            "code_rebases": [f"0x{x:08X}" for x in dynamic_code_rebases],
            "data_rebases": [f"0x{x:08X}" for x in dynamic_data_rebases],
            "consistent": len(dynamic_code_rebases) == 1 and len(dynamic_data_rebases) == 1,
        },
        "checkpoints": observed,
        "first_target_audit": {
            "link_va": f"0x{FIRST_TARGET:08X}",
            "present_in_trace": bool(target_rows),
            "selected_site_and_one_cycle_coverage": target_visibility,
            "w3_107_94342_predecessor_event": prior_armed,
            "source_maps_94342_to_w3_107_bit6": has_prior_bit,
            "w3_109_order_predicate_requires_bit6": has_order_gate,
            "ordering_predicate_satisfied_before_target": predicate_ready,
            "static_playintro_contains_playSmacker_call": static_first_call,
            "interpretation": (
                "The 0x92983 W3-109 order predicate was not suppressed by its 0x94342 predecessor condition: "
                "the same run recorded 0x94342 as a W3-107 target, and source maps that checkpoint to bit 6. "
                "The 0x92983 callback is selected and inside the one-cycle probe range, but no 0x92983 record exists. "
                "Thus the instruction was not observed by this capture; the timeout has no last-EIP sample and does not "
                "prove it could not execute after the final recorded callback."
            ),
        },
        "static_dynamic_separation": {
            "static_chain": static["static_chain"],
            "w3_107_links_observed": w3_107["trace"]["target_order"],
            "observed_same_run_links": [f"0x{x:08X}" for x in sorted(row_by_link)],
            "menu_or_presented_frame_claimed": False,
        },
        "guard": capture["guard"],
        "classification": "INCONCLUSIVE_FIRST_TARGET_NOT_OBSERVED_BEFORE_TIMEOUT",
        "next_action": "Inspect W3-111's actual trace/event coverage around 0x92930 and the VESA callbacks; any new experiment should add an unconditional bounded diagnostic specifically at 0x92983 rather than infer target absence from timeout.",
    }


def main() -> None:
    out = ROOT / "evidence/w3_112_capture_frontier_audit.json"
    out.write_text(json.dumps(build_evidence(), indent=2) + "\n", encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
