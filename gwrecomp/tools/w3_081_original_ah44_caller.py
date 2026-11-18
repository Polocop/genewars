"""Bounded correlator for original __chktty_/isatty_/AH=4400 checkpoints."""
from __future__ import annotations


def as_int(value):
    if isinstance(value, str):
        return int(value, 0)
    return value


def summarize(events: list[dict]) -> dict:
    mapped = [e for e in events if e.get("event") == "target_runtime_checkpoint"]
    main = next((e for e in mapped if e.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    setup = next((e for e in mapped if e.get("checkpoint") == "SETUP_GAME_ENTRY"), None)
    target = [e for e in mapped if str(e.get("checkpoint", "")).startswith("AH44_") or
              e.get("checkpoint") in {"DOS_AH44_BX1_CALLSITE", "DOS_AH44_BX1_RETURN"}]
    calls = [e for e in target if e.get("checkpoint") == "DOS_AH44_BX1_CALLSITE" and
             as_int(e.get("link_va", -1)) == 0xC8973 and
             as_int(e.get("eax", 0)) & 0xffff == 0x4400 and
             as_int(e.get("ebx", 0)) & 0xffff == 1]
    returns = [e for e in target if e.get("checkpoint") == "DOS_AH44_BX1_RETURN" and
               as_int(e.get("link_va", -1)) == 0xC8975]
    pairs = []
    for call in calls:
        call_seq = as_int(call.get("sequence", -1))
        ret = next((r for r in returns if as_int(r.get("sequence", -1)) > call_seq and
                    r.get("process_psp") == call.get("process_psp")), None)
        if ret:
            pairs.append({
                "call": call,
                "return": ret,
                "return_ax": as_int(ret.get("eax", 0)) & 0xffff,
                "return_dx": as_int(ret.get("edx", 0)) & 0xffff,
                "return_cf": bool(as_int(ret.get("eflags", 0)) & 1),
            })
    matching_callbacks = [e for e in events if e.get("event") == "original_int21_ah44" and
                          as_int(e.get("in_ax", 0)) & 0xffff == 0x4400 and
                          as_int(e.get("in_bx", 0)) & 0xffff == 1]
    ah44_callbacks = [e for e in events if e.get("event") == "original_int21_ah44" and
                      as_int(e.get("in_ax", 0)) & 0xffff == 0x4400]
    return {
        "classification": "ORIGINAL_OBSERVED" if pairs else "INCONCLUSIVE",
        "main_mapping": ({"link_va": as_int(main.get("link_va")),
                          "runtime_eip": as_int(main.get("eip")),
                          "code_rebase": as_int(main.get("eip")) - as_int(main.get("link_va")),
                          "cs": as_int(main.get("cs")),
                          "data_rebase": as_int(main.get("data_rebase"))} if main else None),
        "main_entry": main,
        "setup_game_entry": setup,
        "target_checkpoints": target,
        "ah44_bx1_calls": calls,
        "ah44_bx1_returns": returns,
        "paired_calls": pairs,
        "ah44_callbacks": ah44_callbacks,
        "callback_bx1_events": matching_callbacks,
        "last_target_checkpoint": mapped[-1] if mapped else None,
        "effective_child_argv": main.get("main_argv_capture") if main else None,
        "psp_command_tail": main.get("psp_tail_text") if main else None,
    }
