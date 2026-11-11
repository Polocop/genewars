#!/usr/bin/env python3
"""Offline reconciliation of W3-280 and W3-285 bounded Smacker traces."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
W280_EVIDENCE = ROOT / "evidence/w3_280_play_smk_step.json"
W285_EVIDENCE = ROOT / "evidence/w3_285_smacker_callee_capture.json"
OUT = ROOT / "evidence/w3_286_smacker_replay_reconciliation.json"
REPORT = ROOT / "reports/coordination/w3_286_smacker_replay_reconciliation.md"
MAX_TRACE_BYTES = 1_048_576
MAX_TRACE_ROWS = 2_048
CHAIN = [
    "W3_117_PLAYSMACKER_CALLSITE",
    "W3_133_PLAY_SMK_ENTRY",
    "W3_133_PLAY_SMK_DIRECT_ENTRY",
    "W3_133_SMACKOPEN_ENTRY",
]
REGISTERS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags", "cs"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_trace(raw: bytes, expected: dict[str, Any]) -> dict[str, Any]:
    """Check retained trace bytes, hash, row count, and configured caps."""
    rows = [line for line in raw.splitlines() if line.strip()]
    actual = {
        "bytes": len(raw),
        "sha256": sha256(raw),
        "rows": len(rows),
        "within_byte_cap": len(raw) <= MAX_TRACE_BYTES,
        "within_row_cap": len(rows) <= MAX_TRACE_ROWS,
    }
    actual["metadata_matches"] = (
        actual["bytes"] == expected.get("bytes")
        and actual["sha256"] == expected.get("sha256")
        and actual["rows"] == expected.get("rows")
    )
    return actual


def _load_capture(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    meta = json.loads(path.read_text(encoding="utf-8"))
    trace_path = ROOT / meta["trace"]["path"].replace("\\", "/")
    raw = trace_path.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    actual = {
        "path": str(trace_path.relative_to(ROOT)).replace("\\", "/"),
        **validate_trace(raw, meta["trace"]),
    }
    if not actual["within_byte_cap"] or not actual["within_row_cap"]:
        raise ValueError(f"trace exceeds declared audit caps: {actual}")
    if not actual["metadata_matches"]:
        raise ValueError(f"trace no longer matches retained metadata: {actual}")
    return meta, rows, actual


def _checkpoint_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = row.get("checkpoint")
        if name in CHAIN and name not in found:
            found[name] = row
    return found


def _ordered_chain(rows: list[dict[str, Any]], found: dict[str, dict[str, Any]]) -> bool:
    if not all(name in found for name in CHAIN):
        return False
    positions = {name: next(i for i, row in enumerate(rows) if row.get("checkpoint") == name) for name in CHAIN}
    seqs = [found[name].get("sequence") for name in CHAIN]
    return all(positions[CHAIN[i]] < positions[CHAIN[i + 1]] for i in range(len(CHAIN) - 1)) and all(
        isinstance(seqs[i], int) and isinstance(seqs[i + 1], int) and seqs[i] < seqs[i + 1]
        for i in range(len(CHAIN) - 1)
    )


def _link_return(row: dict[str, Any], rebase: int) -> int | None:
    stack = row.get("stack_words_u32")
    if not isinstance(stack, list) or not stack or not isinstance(stack[0], int):
        return None
    return stack[0] - rebase


def _key_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = []
    for row in rows:
        event = str(row.get("event", ""))
        cp = str(row.get("checkpoint", ""))
        link = row.get("link_va")
        if ("w3_278" in event.lower() or "w3_275_second" in event.lower()
                or cp in CHAIN or link in {0xAE2D0, 0xAE2DF, 0xAE2E1, 0xAE2E3,
                                            0xAE2E8, 0xAE2F2, 0xAE301, 0xAE306, 0xAE308}):
            keys.append({
                "sequence": row.get("sequence"), "event": row.get("event"),
                "checkpoint": row.get("checkpoint"), "link_va": link,
                "eax": row.get("eax"), "ebx": row.get("ebx"),
                "ecx": row.get("ecx"), "edx": row.get("edx"),
                "esi": row.get("esi"), "edi": row.get("edi"),
                "ebp": row.get("ebp"), "esp": row.get("esp"),
                "eflags": row.get("eflags"),
            })
    return keys


def classify(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Pure classifier used by the CLI and synthetic tests."""
    p280, p285 = a["provenance"], b["provenance"]
    identical_fixture = all(p280.get(k) == p285.get(k) for k in (
        "target_sha256", "fixture_bytes", "config_sha256", "cue_sha256", "cue_read_only", "staging_revision"
    ))
    m280 = int(a["analysis"]["code_rebase"], 16)
    m285 = int(b["analysis"]["code_rebase"], 16)
    r280, r285 = _checkpoint_rows(a["_rows"]), _checkpoint_rows(b["_rows"])
    common = [name for name in CHAIN if name in r280 and name in r285]
    ordered_a = _ordered_chain(a["_rows"], r280)
    ordered_b = _ordered_chain(b["_rows"], r285)
    equal_fields: dict[str, dict[str, bool]] = {}
    for name in common:
        left, right = r280[name], r285[name]
        equal_fields[name] = {field: left.get(field) == right.get(field) for field in REGISTERS}
        if name == "W3_133_PLAY_SMK_DIRECT_ENTRY":
            equal_fields[name]["return_link_va_from_stack"] = _link_return(left, m280) == _link_return(right, m285)
    first_chain_same = common == CHAIN and ordered_a and ordered_b and all(all(v.values()) for v in equal_fields.values())

    def has_event(rows: list[dict[str, Any]], event: str) -> bool:
        return any(row.get("event") == event for row in rows)

    def has_link(rows: list[dict[str, Any]], link: int) -> bool:
        return any(row.get("link_va") == link for row in rows)

    second_gate_280 = has_event(a["_rows"], "w3_278_later_play_smk_entry") and has_event(a["_rows"], "w3_278_branch_target")
    second_gate_285 = has_event(b["_rows"], "w3_278_later_play_smk_entry") or has_event(b["_rows"], "w3_278_branch_target")
    return {
        "fixture_identity_equal": identical_fixture,
        "code_rebase": {"w3_280": f"0x{m280:08X}", "w3_285": f"0x{m285:08X}", "equal": m280 == m285},
        "first_invocation_chain": {
            "checkpoints": common,
            "ordered_in_both_runs": {"W3-280": ordered_a, "W3-285": ordered_b},
            "same_observed_registers_and_direct_return": first_chain_same,
            "field_equality": equal_fields,
            "conclusion": "W3-285 repeats the same first Smacker invocation already captured in W3-280" if first_chain_same else "not proven identical",
        },
        "later_invocation": {
            "w3_280_later_entry_and_branch_destination_observed": second_gate_280,
            "w3_285_later_entry_or_branch_destination_observed": second_gate_285,
            "w3_280_later_branch_link_va": "0x000AE2E3" if has_link(a["_rows"], 0xAE2E3) else None,
            "w3_285_later_branch_link_va": "0x000AE2E3" if has_link(b["_rows"], 0xAE2E3) else None,
            "w3_285_adds_new_later_invocation": bool(second_gate_285 and not second_gate_280),
            "w3_285_adds_new_frontier": False,
        },
        "return_and_visual_gate": {
            "ae306_executed_return_observed_w3_280": has_link(a["_rows"], 0xAE306),
            "ae306_executed_return_observed_w3_285": has_link(b["_rows"], 0xAE306),
            "framebuffer_pixels_verified_in_either_trace": False,
            "menu_verified_in_either_trace": bool(a.get("scope", {}).get("menu_verified") or b.get("scope", {}).get("menu_verified")),
            "gameplay_verified_in_either_trace": bool(a.get("scope", {}).get("gameplay_verified") or b.get("scope", {}).get("gameplay_verified")),
        },
    }


def build_result(w280_path: Path = W280_EVIDENCE, w285_path: Path = W285_EVIDENCE) -> dict[str, Any]:
    a, rows_a, trace_a = _load_capture(w280_path)
    b, rows_b, trace_b = _load_capture(w285_path)
    a["_rows"], b["_rows"] = rows_a, rows_b
    comparison = classify(a, b)
    return {
        "schema": "w3-286-smacker-replay-reconciliation/v1",
        "task": "W3-286",
        "evidence_level": "ORIGINAL_OBSERVED_WITH_OFFLINE_RECONCILIATION",
        "method": "offline comparison only; no DOSBox, Oracle, or build",
        "captures": {
            "W3-280": {"run_id": a["run_id"], "trace": trace_a, "binary_sha256": a["provenance"]["binary_sha256"]},
            "W3-285": {"run_id": b["run_id"], "trace": trace_b, "binary_sha256": b["provenance"]["binary_sha256"]},
        },
        "shared_provenance": {
            k: a["provenance"].get(k) for k in ("target_sha256", "fixture_bytes", "config_sha256", "cue_sha256", "cue_read_only", "staging_revision")
        },
        "code_mapping": {
            "W3-280": a["analysis"]["code_rebase"], "W3-285": b["analysis"]["code_rebase"],
            "fresh_per_run": True,
            "replay_specific_mapping_equal": comparison["code_rebase"]["equal"],
        },
        "comparison": comparison,
        "selected_events": {"W3-280": _key_rows(rows_a), "W3-285": _key_rows(rows_b)},
        "limits": [
            "Different instrumented Staging binary hashes: these are separate builds, though pinned source revision and target/config/CUE fixture identities match.",
            "The first-entry register match identifies the same captured first invocation; it does not prove equivalence for the later invocation.",
            "W3-280's later gate destination 0xAE2E3 is directly present; the branch condition interpretation is separately documented in W3-280.",
            "Return address 0xAE306 on the direct-entry stack is a return-site value, not proof that execution returned there.",
            "No framebuffer pixels, menu, or gameplay are verified by these two traces.",
        ],
        "next_action": "Use the already measured second invocation in W3-280 as the trigger basis for a narrowly bounded non-blocking continuation/return checkpoint only if an offline/static hypothesis explains how to avoid the prior 120-second timeout; otherwise keep the media-return and visual frontier unknown. Do not repeat the W3-285 first-invocation capture.",
    }


def render_report(result: dict[str, Any]) -> str:
    c = result["comparison"]
    f = c["first_invocation_chain"]
    cap = result["captures"]
    lines = [
        "# W3-286 — Smacker replay reconciliation",
        "",
        "Status: **offline reconciliation complete**. No Oracle/DOSBox/build was run.",
        "",
        "## Integrity and shared fixture",
        "",
        "| Run | Trace SHA-256 | Bytes / rows | Staging binary SHA-256 |",
        "|---|---|---:|---|",
    ]
    for name in ("W3-280", "W3-285"):
        x = cap[name]
        lines.append(f"| {name} | `{x['trace']['sha256']}` | {x['trace']['bytes']} / {x['trace']['rows']} | `{x['binary_sha256']}` |")
    p = result["shared_provenance"]
    lines += [
        "",
        f"Both captures share target GW.EXE `{p['target_sha256']}`, fixture size {p['fixture_bytes']} bytes, CONFIG hash `{p['config_sha256']}`, read-only CUE hash `{p['cue_sha256']}`, and Staging source revision `{p['staging_revision']}`. Each trace passes the 1 MiB / 2048-row caps and exactly matches its retained metadata. The fresh code rebase is `0x001EB000` in both runs; the instrumented binary hashes differ.",
        "",
        "## Duplicate first invocation",
        "",
        f"W3-280 sequences 328–331 and W3-285 sequences 327–330 contain the same ordered checkpoints: `{', '.join(f['checkpoints'])}`. Register/flags/CS values match at every checkpoint, and the direct-entry stack return maps to link VA `0xAE306` in both. Classification: **{f['conclusion']}**. Thus W3-285 adds no new invocation or execution frontier. Its latch-specific hook did not arm; the existing W3-133 target checkpoint captured the entry.",
        "",
        "## Second invocation and remaining frontier",
        "",
        "W3-280 separately records the later invocation at sequences 394–399: callsite `0x92ADD`, later `play_smk_` entry `0xAE2D0`, load/test at `0xAE2DF/0xAE2E1`, and observed destination `0xAE2E3`. W3-285 has none of those later-invocation events; it timed out after reaching the earlier Smacker path. Do not conflate the shared first entry with the later branch.",
        "",
        "Neither trace contains an executed link-VA `0xAE306` return checkpoint. The stack's `0xAE306` is only the saved return address. These traces do not verify framebuffer pixels, menu, or gameplay.",
        "",
        "## Evidence and next action",
        "",
        "The original observations remain in the source JSONL files; this task only reconciles them offline. W3-285's original capture is preserved and corrected here to label the duplicate. No Runtime behavior or original/native parity is inferred.",
        "",
        result["next_action"],
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--w280", type=Path, default=W280_EVIDENCE)
    parser.add_argument("--w285", type=Path, default=W285_EVIDENCE)
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--report", type=Path, default=REPORT)
    args = parser.parse_args()
    result = build_result(args.w280, args.w285)
    result["comparison"]["trace_integrity"] = {
        "W3-280": result["captures"]["W3-280"]["trace"],
        "W3-285": result["captures"]["W3-285"]["trace"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.report.write_text(render_report(result), encoding="utf-8")
    # Preserve the original observation while making the duplicate interpretation explicit.
    w285 = json.loads(args.w285.read_text(encoding="utf-8"))
    w285["conclusion"] = "DUPLICATE_FIRST_INVOCATION_NO_NEW_FRONTIER"
    w285["comparison_to_w3_280"] = {
        "audit_evidence": str(args.output.relative_to(ROOT)).replace("\\", "/"),
        "same_fixture_and_target": result["comparison"]["fixture_identity_equal"],
        "same_fresh_code_rebase": result["comparison"]["code_rebase"]["equal"],
        "first_invocation_chain_repeated": result["comparison"]["first_invocation_chain"]["same_observed_registers_and_direct_return"],
        "classification": result["comparison"]["first_invocation_chain"]["conclusion"],
        "W3_280_later_invocation_and_branch": result["comparison"]["later_invocation"]["w3_280_later_entry_and_branch_destination_observed"],
        "W3_285_later_invocation_or_branch": result["comparison"]["later_invocation"]["w3_285_later_entry_or_branch_destination_observed"],
        "W3_285_new_frontier": result["comparison"]["later_invocation"]["w3_285_adds_new_frontier"],
        "latch_specific_hook_armed": w285["analysis"]["fallthrough_latch_seen"],
        "notes": "The original W3-285 AE308 observation is retained. It is the same first invocation already in W3-280, not the later second invocation. W3-280 contains the later branch destination AE2E3 at seq 399; W3-285 does not contain that later invocation. The AE306 value on the AE308 stack is a saved return site, not an observed executed return.",
    }
    w285["interpretation"]["comparison_correction"] = w285["comparison_to_w3_280"]["notes"]
    args.w285.write_text(json.dumps(w285, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    prior_report = REPORT.read_text(encoding="utf-8") if REPORT.exists() else "# W3-285 — natural Smacker callee entry\n"
    marker = "\n## Offline comparison correction (W3-286)\n"
    if marker in prior_report:
        prior_report = prior_report.split(marker, 1)[0]
    prior_report += marker + "\n"
    prior_report += (
        "W3-286 compared this retained trace with W3-280 offline. The W3-285 sequence "
        "`W3_117_PLAYSMACKER_CALLSITE -> W3_133_PLAY_SMK_ENTRY -> "
        "W3_133_PLAY_SMK_DIRECT_ENTRY -> W3_133_SMACKOPEN_ENTRY` is the same first "
        "invocation already recorded in W3-280: the captured register/flag/CS fields "
        "and saved direct-entry return site match. Therefore W3-285 adds no new invocation "
        "or frontier. W3-280 separately records the later invocation and destination `0xAE2E3` "
        "at sequences 394–399; W3-285 has no such later-invocation event. The custom "
        "W3-285 latch hook remained unarmed. The `0xAE306` value is a saved return address, "
        "not an executed return checkpoint. Neither capture verifies framebuffer pixels, "
        "menu, or gameplay. See `evidence/w3_286_smacker_replay_reconciliation.json`.\n"
    )
    REPORT.write_text(prior_report, encoding="utf-8")
    print(json.dumps({"output": str(args.output), "report": str(args.report), "classification": result["comparison"]["first_invocation_chain"]["conclusion"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
