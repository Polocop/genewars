#!/usr/bin/env python3
"""Validate bounded native allocator-chain evidence for W1-062."""
from __future__ import annotations

import json
import pathlib
import sys


ENTRY_VAS = {"000c3e2a", "000c3d7a", "000c3ca9"}
CALL_SITES = {"000c3e54", "000c3db0"}


def validate(data: dict) -> list[str]:
    errors: list[str] = []
    chain = data.get("w1_062_allocator_chain")
    if not isinstance(chain, dict):
        return ["missing w1_062_allocator_chain"]
    events = chain.get("events")
    if not isinstance(events, list):
        return ["allocator events must be a list"]
    entries = {str(event.get("va", "")).lower() for event in events
               if event.get("kind") == "NATIVE_ALLOC_ENTRY"}
    sites = {str(event.get("site", "")).lower() for event in events
             if event.get("kind") == "NATIVE_ALLOC_CALLSITE"}
    if not ENTRY_VAS.issubset(entries):
        errors.append(f"missing allocator entries: {sorted(ENTRY_VAS - entries)}")
    if not CALL_SITES.issubset(sites):
        errors.append(f"missing allocator callsites: {sorted(CALL_SITES - sites)}")
    expected_callers = {"000c3e54": ("000c3e2a", "000c3d7a"),
                        "000c3db0": ("000c3d7a", "000c3ca9")}
    for site, (caller, target) in expected_callers.items():
        rows = [event for event in events if event.get("kind") == "NATIVE_ALLOC_CALLSITE" and
                str(event.get("site", "")).lower() == site]
        if not any(str(event.get("caller", "")).lower() == caller and
                   str(event.get("target", "")).lower() == target for event in rows):
            errors.append(f"callsite {site} lacks the expected dynamic caller/target pair")
    for event in events:
        if not isinstance(event.get("ordinal"), str) or not event.get("ordinal", "").isdigit():
            errors.append("each allocator event needs a dynamic ordinal")
            break
        for field in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                      "flags_k", "flags_a", "flags_b", "cf", "cs", "ds", "es", "ss", "valid"):
            if field not in event:
                errors.append(f"allocator event missing {field}")
                break
        if not event.get("valid") == "1":
            errors.append("allocator stack sample is not valid")
            break
        if any(f"stack{i}" not in event for i in range(8)):
            errors.append("allocator event missing bounded stack words")
            break
    if chain.get("dynamic_caller_chain_observed") is not True:
        errors.append("dynamic caller chain is not marked observed")
    original = chain.get("original_w3_070", {})
    if original.get("same_dynamic_invocation_claimed") is not False:
        errors.append("separate-run original/native evidence must not claim invocation identity")
    frontier = chain.get("native_ax0501_frontier", {})
    if frontier.get("eip", "").lower() != "000c3cc1" or frontier.get("eax", "").lower() != "00000501":
        errors.append("native replay did not stop at natural AX=0501 C3CC1")
    try:
        frontier_size = ((int(frontier.get("ebx", "0"), 16) & 0xffff) << 16) | (int(frontier.get("ecx", "0"), 16) & 0xffff)
        measured_size = int(str(chain.get("native_request_size_bytes", "0")), 16)
        terminal_callsites = [event for event in events if event.get("kind") == "NATIVE_ALLOC_CALLSITE" and
                              str(event.get("site", "")).lower() == "000c3db0"]
        if not terminal_callsites or not any(int(str(event.get("stack0", "0")), 16) == frontier_size == measured_size
                                             for event in terminal_callsites):
            errors.append("natural AX=0501 size is not linked to a captured C3DB0 stack request")
    except ValueError:
        errors.append("invalid hexadecimal allocator request size")
    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("usage: verify_native_alloc_chain_w1_062.py evidence.json", file=sys.stderr)
        return 2
    path = pathlib.Path(args[0])
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot read evidence: {exc}", file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        print("FAIL: " + "; ".join(errors), file=sys.stderr)
        return 1
    print("PASS: bounded native allocator chain captured without original invocation equivalence claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
