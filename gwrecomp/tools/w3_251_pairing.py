"""Pair an original BX=1 DOS request to its same-run isatty entry token."""
from __future__ import annotations


CALLER_BY_RETURN_LINK = {
    0x000AFCF4: "sopen_ primary",
    0x000AFE0E: "sopen_ secondary",
    0x000C89CC: "__IOMode_",
    0x000BA4E9: "__chktty_",
    0x000B0186: "_AIL_startup",
}


def _integer(event: dict, key: str) -> int:
    value = event.get(key, 0)
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return 0


def pair_events(events: list[dict]) -> dict:
    entries = []
    requests = []
    returns = []
    for index, event in enumerate(events):
        name = event.get("checkpoint", "")
        if name == "W3_237_ISATTY_ENTRY":
            entries.append({
                "index": index,
                "sequence": event.get("sequence"),
                "ordinal": event.get("w3_237_event_ordinal"),
                "eax": event.get("eax"),
                "edi": event.get("edi"),
                "return_runtime": event.get("w3_251_entry_return_runtime"),
                "code_rebase": event.get("w3_251_main_code_rebase"),
                "return_link_va": event.get("w3_251_entry_return_link_va"),
                "token_valid": event.get("w3_251_token_valid") is True,
            })
        elif name == "W3_237_AH4400_REQUEST" and _integer(event, "eax") & 0xFFFF == 0x4400 and _integer(event, "ebx") & 0xFFFF == 1:
            requests.append({
                "index": index,
                "sequence": event.get("sequence"),
                "entry_ordinal": event.get("w3_237_correlated_isatty_entry_ordinal"),
                "return_link_va": event.get("w3_251_entry_return_link_va"),
                "token_valid": event.get("w3_251_token_valid") is True,
                "eax": event.get("eax"),
                "ebx": event.get("ebx"),
                "edx": event.get("edx"),
                "eflags": event.get("eflags"),
            })
        elif name == "W3_237_AH4400_RETURN":
            returns.append({
                "index": index,
                "sequence": event.get("sequence"),
                "entry_ordinal": event.get("w3_237_correlated_isatty_entry_ordinal"),
                "eax": event.get("eax"),
                "edx": event.get("edx"),
                "eflags": event.get("eflags"),
                "carry": bool(_integer(event, "eflags") & 1),
            })

    pairs = []
    for request in requests:
        entry = next((candidate for candidate in reversed(entries)
                      if candidate["index"] < request["index"] and
                      str(candidate["ordinal"]) == str(request["entry_ordinal"]) and
                      candidate["token_valid"] and request["token_valid"] and
                      _integer(candidate, "return_link_va") == _integer(request, "return_link_va")), None)
        result = next((candidate for candidate in returns
                       if candidate["index"] > request["index"] and
                       str(candidate["entry_ordinal"]) == str(request["entry_ordinal"])), None)
        ret_link = _integer(entry or {}, "return_link_va")
        pairs.append({
            "entry": entry,
            "request": request,
            "return": result,
            "caller": CALLER_BY_RETURN_LINK.get(ret_link, "UNKNOWN") if entry else "UNKNOWN",
            "status": "PAIRED" if entry and result else "REQUEST_WITHOUT_COMPLETE_TOKEN_PAIR",
        })
    return {"isatty_entries": entries, "bx1_requests": requests,
            "bx1_returns": [pair["return"] for pair in pairs if pair["return"]],
            "pairs": pairs,
            "dynamic_caller": pairs[-1]["caller"] if pairs and pairs[-1]["status"] == "PAIRED" else "UNKNOWN"}
