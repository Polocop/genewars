"""Small pure helpers for correlating original AH=4400/BX=1 checkpoints."""
from __future__ import annotations


def _as_int(value):
    if isinstance(value, str):
        return int(value, 0)
    return value


def correlate_bx1_checkpoints(events: list[dict]) -> dict:
    calls = [e for e in events if e.get("checkpoint") == "DOS_AH44_BX1_CALLSITE"]
    returns = [e for e in events if e.get("checkpoint") == "DOS_AH44_BX1_RETURN"]
    valid_calls = [e for e in calls
                   if _as_int(e.get("link_va", -1)) == 0xC8973
                   and _as_int(e.get("eax", 0)) & 0xffff == 0x4400
                   and _as_int(e.get("ebx", 0)) & 0xffff == 1]
    pairs = []
    for call in valid_calls:
        call_seq = _as_int(call.get("sequence", -1))
        match = next((ret for ret in returns
                      if _as_int(ret.get("sequence", -1)) > call_seq
                      and ret.get("process_psp") == call.get("process_psp")
                      and _as_int(ret.get("link_va", -1)) == 0xC8975), None)
        if match:
            pairs.append({"callsite": call, "return": match,
                          "same_process_ordered_pair": True,
                          "return_ax": _as_int(match.get("eax", 0)) & 0xffff,
                          "return_dx": _as_int(match.get("edx", 0)) & 0xffff,
                          "return_cf": bool(_as_int(match.get("eflags", 0)) & 1)})
    return {"classification": "ORIGINAL_OBSERVED" if pairs else "INCONCLUSIVE",
            "original_call_count": len(valid_calls), "paired_return_count": len(pairs),
            "pairs": pairs,
            "unpaired_calls": [e for e in valid_calls
                               if not any(p["callsite"] is e for p in pairs)]}
