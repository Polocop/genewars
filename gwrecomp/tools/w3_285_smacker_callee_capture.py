from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_BYTES = 1024 * 1024
MAX_ROWS = 2048
TARGET_LINK = 0xAE308
EVENT = "w3_285_smacker_direct_entry"


def parse(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_BYTES:
        raise ValueError("trace byte cap exceeded")
    rows = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON row {number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"non-object JSON row {number}")
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise ValueError("trace row cap exceeded")
    return rows


def analyze(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mappings = [row for row in rows if row.get("event") == "main_mapping"]
    if len(mappings) != 1 or mappings[0].get("mapping_matches") is not True:
        raise ValueError("fresh unique MAIN mapping missing")
    base = int(mappings[0]["code_rebase"])
    latch = [row for row in rows if row.get("event") == "w3_278_branch_target" and
             int(row.get("link_va", -1)) == 0xAE2E3]
    custom_hits = [row for row in rows if row.get("event") == EVENT and
                   int(row.get("link_va", -1)) == TARGET_LINK]
    existing_hits = [row for row in rows if row.get("event") == "target_runtime_checkpoint" and
                     row.get("checkpoint") == "W3_133_PLAY_SMK_DIRECT_ENTRY" and
                     int(row.get("link_va", -1)) == TARGET_LINK]
    hits = custom_hits or existing_hits
    if len(hits) > 1:
        raise ValueError("one-shot callee event duplicated")
    for row in latch:
        if int(row["code_rebase"]) != base or int(row["runtime_linear"]) - base != int(row["link_va"]):
            raise ValueError("runtime/link mapping mismatch")
    for row in hits:
        runtime = int(row.get("runtime_linear", row.get("linear", -1)))
        row_base = int(row.get("code_rebase", runtime - int(row["link_va"])))
        if row_base != base or runtime - base != int(row["link_va"]):
            raise ValueError("runtime/link mapping mismatch")
    hit = hits[0] if hits else None
    wrapper = [row for row in rows if row.get("event") == "target_runtime_checkpoint" and
               row.get("checkpoint") == "W3_133_PLAY_SMK_ENTRY" and int(row.get("link_va", -1)) == 0xAE2D0]
    next_smackopen = [row for row in rows if row.get("event") == "target_runtime_checkpoint" and
                      row.get("checkpoint") == "W3_133_SMACKOPEN_ENTRY"]
    ordered = bool(hit and wrapper and int(wrapper[0]["sequence"]) < int(hit["sequence"]) and
                   (not next_smackopen or int(hit["sequence"]) < int(next_smackopen[0]["sequence"])))
    stack_words = hit.get("stack_words_u32", []) if hit else []
    return_runtime = int(stack_words[0]) if stack_words else None
    return_link = return_runtime - base if return_runtime is not None else None
    last = hit or (latch[-1] if latch else None)
    normalized_entry = None
    if hit:
        normalized_entry = {k: hit.get(k) for k in (
            "sequence", "event", "checkpoint", "phase", "process_psp", "cs", "eip",
            "link_va", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags") if k in hit}
        normalized_entry["runtime_linear"] = hit.get("runtime_linear", hit.get("linear"))
        normalized_entry["code_rebase"] = base
        normalized_entry["return_address_runtime_from_stack"] = return_runtime
        normalized_entry["return_address_link_va_from_stack"] = return_link
    return {
        "code_rebase": f"0x{base:08X}",
        "fallthrough_latch_seen": bool(latch),
        "fallthrough_sequence": int(latch[0]["sequence"]) if latch else None,
        "instrumented_one_shot_hook_seen": bool(custom_hits),
        "callee_entry_seen": hit is not None,
        "callee_entry_sequence": int(hit["sequence"]) if hit else None,
        "ordered": ordered,
        "entry_source": "W3_285_ONE_SHOT_HOOK" if custom_hits else "EXISTING_W3_133_TARGET_CHECKPOINT" if existing_hits else None,
        "entry": normalized_entry,
        "same_run_wrapper_entry_sequence": int(wrapper[0]["sequence"]) if wrapper else None,
        "same_run_smackopen_entry_sequence": int(next_smackopen[0]["sequence"]) if next_smackopen else None,
        "return_address_matches_static_0xAE306": return_link == 0xAE306 if return_link is not None else None,
        "last_target_event": ({k: last.get(k) for k in (
            "sequence", "event", "checkpoint", "link_va", "runtime_linear", "linear", "code_rebase") if k in last} if last else None),
        "menu_verified": False,
        "gameplay_verified": False,
    }


def verify_instrumentation(source: str) -> bool:
    required = (
        'GWRECOMP_W3_285_CAPTURE', 'w3_280_first_fallthrough_seen',
        'candidate_link_va == 0x000ae308', 'w3_285_smacker_direct_entry',
        'candidate_link_va >= 0x000ae2e3 && candidate_link_va <= 0x000ae308',
        'w3_285_step_instruction_count < 16', 'w3_285_entry_probe_window',
    )
    return all(token in source for token in required)


def report(result: dict[str, Any]) -> str:
    analysis = result["analysis"]
    lines = [
        "# W3-285 — natural Smacker callee entry",
        "",
        f"Status: **{result['conclusion']}**. Evidence level: **{result['evidence_level']}**.",
        "",
        f"- Fixture GW.EXE SHA-256: `{result['provenance']['target_sha256']}`.",
        f"- Staging revision: `{result['provenance']['staging_revision']}`; instrumented binary SHA-256: `{result['provenance']['binary_sha256']}`.",
        f"- Fresh MAIN rebase: `{analysis['code_rebase']}`.",
        f"- Same-run branch fall-through latch `0xAE2E3`: `{analysis['fallthrough_latch_seen']}` at sequence `{analysis['fallthrough_sequence']}`.",
        f"- Natural callee entry `0xAE308`: `{analysis['callee_entry_seen']}`; event source: `{analysis['entry_source']}`.",
        f"- Same-run `play_smk_` entry sequence: `{analysis['same_run_wrapper_entry_sequence']}`; ordering through callee: `{analysis['ordered']}`.",
        f"- Stack return address maps to static post-CALL `0xAE306`: `{analysis['return_address_matches_static_0xAE306']}`.",
        f"- New latch-specific one-shot hook emitted: `{analysis['instrumented_one_shot_hook_seen']}`.",
        "",
        "The original reached `0xAE308` through the existing W3-133 target checkpoint; the new W3-285 latch-specific hook did not emit because its prerequisite branch-latch event was absent. This run does not dynamically resolve the second branch itself.",
        "",
        "```json",
        json.dumps(analysis["entry"] or analysis["last_target_event"], indent=2),
        "```",
        "",
        f"Guard cause: `{result['guard'].get('cause')}` after {result['guard'].get('duration_s')} seconds; timeout or an absent hook does not prove the callee was not executed.",
        "",
        "Media return, first framebuffer pixels, menu, gameplay, and native parity remain unverified.",
        "",
        "No global trace or bulk memory dump was enabled. The replay used the authentic W3-067 fixture and read-only CUE through `oracle_guard`.",
        "",
    ]
    return "\n".join(lines)

