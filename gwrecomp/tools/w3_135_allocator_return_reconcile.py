"""Reconcile W3-134 allocator entry against its enclosing return checkpoint."""
from __future__ import annotations

import json
from typing import Any

CAP_BYTES = 1_048_576
CODE_REBASE = 0x1EB000


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > CAP_BYTES:
        raise ValueError("trace byte cap exceeded")
    rows = []
    for line in raw.splitlines():
        if line.strip():
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _valid_row(row: dict[str, Any] | None) -> bool:
    return bool(row and isinstance(row.get("eip"), int) and
                isinstance(row.get("link_va"), int) and
                row["eip"] - row["link_va"] == CODE_REBASE and
                isinstance(row.get("process_psp"), int) and
                isinstance(row.get("cs"), int))


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    checkpoints = [row for row in rows if row.get("event") == "target_runtime_checkpoint"]
    callsites = [row for row in checkpoints if row.get("link_va") == 0x92ADD]
    entries = [row for row in checkpoints if row.get("checkpoint") ==
               "W3_134_LBMEMORYALLOC_4AC_ENTRY" and row.get("eax") == 0x4AC]
    returns = [row for row in checkpoints if row.get("link_va") == 0x92AE2]
    pairs = []
    for callsite in callsites:
        for entry in entries:
            for ret in returns:
                order = [callsite.get("sequence", 0), entry.get("sequence", 0),
                         ret.get("sequence", 0)]
                if (order[0] < order[1] < order[2] and _valid_row(callsite) and
                        _valid_row(entry) and _valid_row(ret) and
                        callsite["process_psp"] == entry["process_psp"] == ret["process_psp"] and
                        callsite["cs"] == entry["cs"] == ret["cs"]):
                    play_entries = [row for row in checkpoints
                                    if row.get("link_va") == 0xAE2D0 and
                                    order[0] < row.get("sequence", 0) < order[1] and
                                    _valid_row(row) and
                                    row["process_psp"] == callsite["process_psp"] and
                                    row["cs"] == callsite["cs"]]
                    if not play_entries:
                        continue
                    play_entry = play_entries[0]
                    expected_play_return = play_entry.get("return_address")
                    if (not isinstance(expected_play_return, int) or
                            expected_play_return != ret["eip"] or
                            entry.get("return_address", 0) != CODE_REBASE + 0xAE64F):
                        continue
                    pairs.append((callsite, play_entry, entry, ret))
    matched = pairs[0] if pairs else None
    if matched:
        callsite, play_entry, entry, ret = matched
        direct_returns = [row for row in checkpoints if row.get("checkpoint") ==
                          "W3_134_LBMEMORYALLOC_RETURN" and
                          row.get("link_va") == 0xAE64F and
                          row.get("process_psp") == entry.get("process_psp") and
                          row.get("sequence", 0) > entry.get("sequence", 0)]
    else:
        callsite = play_entry = entry = ret = None
        direct_returns = []
    return {
        "classification": "ENCLOSING_PLAY_SMK_RETURN_OBSERVED_ALLOCATOR_COMPLETION_INFERRED"
        if matched else "UNMATCHED_OR_INCOMPLETE",
        "same_invocation_join_valid": bool(matched),
        "code_rebase": f"0x{CODE_REBASE:08X}",
        "callsite_92add": callsite,
        "play_smk_entry": play_entry,
        "allocator_entry": entry,
        "enclosing_return_92ae2": ret,
        "direct_allocator_return_checkpoint_observed": bool(direct_returns),
        "nested_allocator_call_completion_inferred": bool(matched),
        "inference_basis": ("The play_smk_ entry stack points to 0x92AE2; that exact continuation is observed later in the same PSP/CS/rebase after the allocator entry whose stack return points inside RADMALLOC. Normal synchronous call/return flow implies the nested allocation call completed." if matched else None),
        "allocator_return_eax": None,
        "allocator_ownership_free_lifetime": "UNKNOWN",
        "play_smk_return_eax": ret.get("eax") if ret else None,
        "caller_function": "RADMALLOC" if matched else None,
        "event_sequences": ([callsite.get("sequence"), play_entry.get("sequence"),
                             entry.get("sequence"), ret.get("sequence")] if matched else []),
    }
