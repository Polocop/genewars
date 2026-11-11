"""Bounded same-invocation parser for W3-134 allocator caller evidence."""
from __future__ import annotations

import json
from typing import Any

CAP_BYTES = 1_048_576
CAP_TARGETS = 6


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


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    callsite = next((row for row in rows
                     if row.get("event") == "target_runtime_checkpoint" and
                     row.get("link_va") == 0x92ADD), None)
    play_entry = next((row for row in rows
                       if row.get("event") == "target_runtime_checkpoint" and
                       row.get("link_va") == 0xAE2D0 and
                       (not callsite or row.get("checkpoint_ordinal", 0) >=
                        callsite.get("checkpoint_ordinal", 0))), None)
    entries = [row for row in rows if row.get("event") == "target_runtime_checkpoint" and
               row.get("checkpoint") == "W3_134_LBMEMORYALLOC_4AC_ENTRY"][:1]
    returns = [row for row in rows if row.get("event") == "target_runtime_checkpoint" and
               row.get("checkpoint") == "W3_134_LBMEMORYALLOC_RETURN"][:1]
    entry = entries[0] if entries else None
    ret = returns[0] if returns else None
    rebase = (entry.get("eip") - entry.get("link_va") if entry and
              isinstance(entry.get("eip"), int) and isinstance(entry.get("link_va"), int)
              else None)
    stack = entry.get("stack_words_u32") if entry else None
    stack_return = (stack[0] if isinstance(stack, list) and stack and
                    isinstance(stack[0], int) and stack[0] != 0 else None)
    derived_return = (stack_return - rebase if stack_return is not None and rebase is not None
                      and stack_return >= rebase else None)
    caller_function = ("RADMALLOC" if derived_return is not None and
                       0xAE63C <= derived_return < 0xAE658 else None)
    same_return = bool(ret and derived_return is not None and
                       ret.get("link_va") == derived_return and
                       ret.get("eip", 0) - ret.get("link_va", 0) == rebase)
    callsite_and_entry_ordered = bool(callsite and entry and
                                      callsite.get("sequence", 0) < entry.get("sequence", 0))
    return {
        "classification": ("ALLOCATOR_ENTRY_AND_MATCHED_RETURN" if same_return else
                           "ALLOCATOR_CALLER_RESOLVED" if entry and caller_function else
                           "ALLOCATOR_ENTRY_CALLER_CANDIDATE" if entry and stack_return is not None else
                           "CALLSITE_ONLY" if callsite else "NO_TARGET"),
        "target_event_count": min(CAP_TARGETS, int(bool(callsite)) + int(bool(play_entry)) +
                                  len(entries) + len(returns)),
        "code_rebase": f"0x{rebase:08X}" if rebase is not None else None,
        "callsite_92add": callsite,
        "play_smk_entry_after_callsite": play_entry,
        "callsite_precedes_allocator_entry": callsite_and_entry_ordered,
        "allocator_entry": entry,
        "stack_return_runtime": f"0x{stack_return:08X}" if stack_return is not None else None,
        "stack_return_link_va": f"0x{derived_return:08X}" if derived_return is not None else None,
        "stack_return_function": caller_function,
        "allocator_return": ret,
        "same_invocation_return_observed": same_return,
        "caller_identity": "RADMALLOC_STACK_RETURN_TARGET" if caller_function else
                           "DYNAMIC_RETURN_TARGET" if same_return else
                           "STACK_RETURN_ADDRESS_ONLY" if derived_return is not None else "UNKNOWN",
        "last_relevant_checkpoint": (ret or entry or play_entry or callsite or {}).get("checkpoint"),
    }


def source_coverage(source: str) -> dict[str, bool]:
    return {
        "one_shot_arming": "w3_134_capture_armed" in source and
                           "link_va == 0x00092add && !w3_134_allocator_captured" in source,
        "exact_allocator_filter": "link_va == 0x00091e00 && reg_eax == 0x000004ac" in source and
                                  "W3_134_LBMEMORYALLOC_4AC_ENTRY" in source,
        "stack_return_capture": "w3_134_alloc_return_link_va" in source and
                                "W3_134_LBMEMORYALLOC_RETURN" in source,
        "bounded_event_gate": "w3_134_entry_target || w3_134_return_target" in source,
    }
