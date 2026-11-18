"""Validate and summarize the bounded W3-237 original capture."""
from __future__ import annotations

from collections.abc import Iterable

ENTRY = "W3_237_ISATTY_ENTRY"
REQUEST = "W3_237_AH4400_REQUEST"
RETURN = "W3_237_AH4400_RETURN"
PROBE_START = 0x000C896A
PROBE_END = 0x000C8975


def probe_window_contains(link_va: int, *, capture_only: bool, main_rebase: int) -> bool:
    """The opt-in dispatcher window is valid only after MAIN mapping is measured."""
    return bool(capture_only and main_rebase and PROBE_START <= link_va <= PROBE_END)


def correlate(events: Iterable[dict]) -> dict:
    entries: dict[int, dict] = {}
    requests = []
    last_entry = 0
    event_count = 0
    for event in events:
        if event.get("event") != "target_runtime_checkpoint":
            continue
        name = event.get("checkpoint")
        if name == ENTRY:
            ordinal = int(event["w3_237_event_ordinal"])
            if ordinal in entries or ordinal <= 0:
                raise ValueError("duplicate or invalid isatty invocation ordinal")
            if int(event.get("link_va", 0)) != PROBE_START:
                raise ValueError("isatty entry uses an unexpected link VA")
            entries[ordinal] = event
            last_entry = ordinal
            event_count += 1
        elif name == REQUEST:
            ordinal = int(event["w3_237_event_ordinal"])
            if ordinal <= 0:
                raise ValueError("invalid AX=4400 request ordinal")
            correlated = int(event.get("w3_237_correlated_isatty_entry_ordinal", 0))
            if correlated and correlated not in entries:
                raise ValueError("request references an unseen isatty invocation")
            if correlated and correlated != last_entry:
                raise ValueError("request does not reference the active invocation")
            if int(event.get("link_va", 0)) != 0x000C8973:
                raise ValueError("AX=4400 request uses an unexpected link VA")
            if correlated and event.get("process_psp") != entries[correlated].get("process_psp"):
                raise ValueError("request is not from the same guest process as its entry token")
            if event.get("w3_237_correlation_valid") and not correlated:
                raise ValueError("correlation marked valid without an entry ordinal")
            requests.append({"ordinal": ordinal, "event": event,
                             "entry": entries.get(correlated),
                             "correlated_entry_ordinal": correlated})
            event_count += 1
        elif name == RETURN:
            event_count += 1
    if event_count > 192:
        raise ValueError("instrumentation event cap exceeded")
    bx1 = [r for r in requests if (int(r["event"].get("eax", 0)) & 0xffff) == 0x4400
           and (int(r["event"].get("ebx", 0)) & 0xffff) == 1]
    for request in requests:
        event = request["event"]
        if (int(event.get("eax", 0)) & 0xffff) == 0x4400:
            if not all(key in event for key in ("eax", "ebx", "ecx", "edx", "esi", "edi",
                                                "ebp", "esp", "eflags", "cs", "ds", "ss",
                                                "stack_words_u32", "return_address", "linear",
                                                "link_va")):
                raise ValueError("AX=4400 event lacks required CPU context")
    return {"entries": list(entries.values()), "requests": requests,
            "bx1_requests": bx1,
            "classification": "ORIGINAL_OBSERVED" if bx1 else "INCONCLUSIVE_NO_BX1"}


def source_instrumentation_valid(source: str) -> bool:
    required = ("GWRECOMP_W3_237_CAPTURE_ONLY", ENTRY, REQUEST, RETURN,
                "w3_237_correlated_isatty_entry_ordinal", "w3_237_isatty_entry_ordinal < 64",
                "w3_237_ah44_request_ordinal < 64", "w3_237_probe_window",
                "candidate_link_va <= 0x000c8975")
    return all(token in source for token in required)
