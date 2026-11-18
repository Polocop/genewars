"""Join bounded caller, helper-entry, and natural BX=1 trace events."""
from __future__ import annotations

import struct

CALLERS = {
    "W3_249_ISATTY_CALL_SOPEN_PRIMARY": "sopen_ primary",
    "W3_249_ISATTY_CALL_SOPEN_SECONDARY": "sopen_ secondary",
    "W3_249_ISATTY_CALL_IOMODE": "__IOMode_",
    "W3_249_ISATTY_CALL_CHKTTY": "__chktty_",
    "W3_249_ISATTY_CALL_AIL_STARTUP": "_AIL_startup",
}
ISATTY_ENTRY_NAMES = {"W3_237_ISATTY_ENTRY", "AH44_ISATTY_ENTRY"}
BX1_NAMES = {"W3_237_AH4400_REQUEST", "DOS_AH44_BX1_CALLSITE"}
BX1_RETURN_NAMES = {"W3_237_AH4400_RETURN", "DOS_AH44_BX1_RETURN"}


def _int(value, default=0):
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return default


def _direct_call_target(event):
    raw = event.get("bytes", "")
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(data) < 5 or data[0] != 0xE8:
        return None
    site = _int(event.get("link_va"))
    displacement = struct.unpack("<i", data[1:5])[0]
    target = (site + 5 + displacement) & 0xFFFFFFFF
    if _int(event.get("w3_249_static_callee_link_va")) != 0xC896A:
        return None
    if _int(event.get("w3_249_expected_return_link_va")) != site + 5:
        return None
    return target if target == 0xC896A else None


def pair_events(events):
    """Return only same-trace callsite/entry/request pairings that validate addresses."""
    callers = []
    entries = []
    requests = []
    ah4400_returns = []
    for index, event in enumerate(events):
        name = event.get("checkpoint", "")
        if name in CALLERS and _direct_call_target(event) == 0xC896A:
            callers.append({"index": index, "sequence": event.get("sequence"),
                            "callsite": event.get("link_va"), "caller": CALLERS[name],
                            "eax": event.get("eax"),
                            "return_link_va": event.get("w3_249_expected_return_link_va")})
        elif name in ISATTY_ENTRY_NAMES:
            entries.append({"index": index, "sequence": event.get("sequence"),
                            "ordinal": event.get("w3_237_event_ordinal", event.get("checkpoint_ordinal")),
                            "eax": event.get("eax"),
                            "return_link_va": event.get("w3_237_isatty_return_address", event.get("return_address"))})
        elif name in BX1_NAMES and _int(event.get("eax")) & 0xFFFF == 0x4400 and _int(event.get("ebx")) & 0xFFFF == 1:
            requests.append({"index": index, "sequence": event.get("sequence"),
                             "ordinal": event.get("w3_237_event_ordinal", event.get("checkpoint_ordinal")),
                             "correlated_entry_ordinal": event.get("w3_237_correlated_isatty_entry_ordinal"),
                             "return_link_va": event.get("w3_237_isatty_return_address"),
                             "eax": event.get("eax"), "ebx": event.get("ebx"),
                             "response": event.get("registers_after")})
        elif name in BX1_RETURN_NAMES:
            ah4400_returns.append({"index": index, "sequence": event.get("sequence"),
                                   "ordinal": event.get("w3_237_event_ordinal", event.get("checkpoint_ordinal")),
                                   "correlated_entry_ordinal": event.get("w3_237_correlated_isatty_entry_ordinal"),
                                   "eax": event.get("eax"), "edx": event.get("edx"),
                                   "eflags": event.get("eflags"), "carry": bool(_int(event.get("eflags")) & 1)})

    pairs = []
    for request in requests:
        has_entry_token = bool(_int(request["correlated_entry_ordinal"]) or
                               _int(request["return_link_va"]))
        entry = next((x for x in reversed(entries[:])
                      if has_entry_token and x["index"] < request["index"] and
                      (not _int(request["correlated_entry_ordinal"]) or
                       str(x["ordinal"]) == str(request["correlated_entry_ordinal"])) and
                      (not _int(request["return_link_va"]) or
                       _int(x["return_link_va"]) == _int(request["return_link_va"]))), None)
        caller = None
        if entry:
            caller = next((x for x in reversed(callers)
                           if x["index"] < entry["index"] and
                           _int(x["return_link_va"]) == _int(entry["return_link_va"])), None)
        result = next((x for x in ah4400_returns if x["index"] > request["index"] and
                       bool(_int(request["correlated_entry_ordinal"]) or
                            _int(request["return_link_va"])) and
                       (not _int(request["correlated_entry_ordinal"]) or
                        str(x["correlated_entry_ordinal"]) == str(request["correlated_entry_ordinal"]))), None)
        pairs.append({"request": request, "entry": entry, "caller": caller, "result": result,
                      "caller_status": "PAIRED" if caller else "UNKNOWN"})
    bx1_returns = [pair["result"] for pair in pairs if pair["result"]]
    return {"candidate_callsites": callers, "isatty_entries": entries,
            "bx1_requests": requests, "bx1_returns": bx1_returns,
            "ah4400_returns": ah4400_returns, "pairs": pairs,
            "dynamic_caller": pairs[-1]["caller"]["caller"] if pairs and pairs[-1]["caller"] else "UNKNOWN"}
