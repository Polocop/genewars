"""Parse the bounded pre-dispatch INT 21h caller and DOS callback trace."""
from __future__ import annotations

import json
from pathlib import Path


def validated_return_link(event: dict, expected_rebase: int | None = None) -> int | None:
    required = ("cs_base", "old_eip", "linear", "main_code_rebase", "caller_link_va")
    if not all(key in event for key in required) or not event.get("mapping_valid"):
        return None
    linear = int(event["cs_base"]) + int(event["old_eip"])
    rebase = int(event["main_code_rebase"])
    if linear != int(event["linear"]) or rebase <= 0 or linear < rebase:
        return None
    if expected_rebase is not None and rebase != expected_rebase:
        return None
    link = linear - rebase
    if int(event["caller_link_va"]) != link:
        return None
    return link


def main_rebase_from_trace(events: list[dict]) -> int | None:
    anchor = next((e for e in events
                   if e.get("event") == "target_code_anchor"
                   and e.get("anchor") == "MAIN_ENTRY"
                   and e.get("byte_signature_matches") is True
                   and e.get("cs_descriptor_valid") is True
                   and e.get("cs_base") == 0), None)
    checkpoint = next((e for e in events
                       if e.get("event") == "target_runtime_checkpoint"
                       and e.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"
                       and e.get("link_va") == 0x93F30
                       and e.get("linear") == e.get("eip")), None)
    if not anchor or not checkpoint:
        return None
    code_rebase = int(checkpoint["eip"]) - int(checkpoint["link_va"])
    if code_rebase != int(anchor["candidate_rebase"]):
        return None
    return code_rebase


def correlate_ah43_events(events: list[dict], expected_rebase: int | None = None,
                          w1_frontier_link: int | None = None) -> list[dict]:
    correlated = []
    pending = []
    for event in sorted(events, key=lambda e: e.get("sequence", 0)):
        if event.get("event") == "original_cpu_int21_ah43_entry":
            pending.append(event)
            continue
        if event.get("event") != "original_int21_ah43":
            continue
        candidates = [candidate for candidate in pending
                      if candidate.get("psp") == event.get("process_psp")
                      and candidate.get("sequence", -1) < event.get("sequence", -1)]
        mapped = [(candidate, validated_return_link(candidate, expected_rebase))
                  for candidate in candidates]
        mapped = [(candidate, link) for candidate, link in mapped if link is not None]
        selected = mapped[0] if mapped else (candidates[0], None) if candidates else (None, None)
        caller, ret_link = selected
        callsite = ret_link - 2 if ret_link is not None and ret_link >= 2 else None
        correlated.append({
            "pre_dispatch": caller,
            "pre_dispatch_group": candidates,
            "callback": event,
            "requested_path": event.get("requested_path"),
            "return_link_va": hex(ret_link) if ret_link is not None else None,
            "int_instruction_link_va_candidate": hex(callsite) if callsite is not None else None,
            "w1_frontier_link_va": hex(w1_frontier_link) if w1_frontier_link is not None else None,
            "matches_w1_frontier": callsite == w1_frontier_link if callsite is not None and w1_frontier_link is not None else None,
            "mapping_valid": ret_link is not None,
        })
        pending = []
    return correlated


def read_trace(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]
