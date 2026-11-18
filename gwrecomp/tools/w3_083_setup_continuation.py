"""Summarize bounded original setup_game continuation checkpoints."""
from __future__ import annotations


TARGETS = {
    "SETUP_GAME_ENTRY", "SETUP_FIRST_CALLEE", "SETUP_GAME_CONTINUATION_94AE9",
    "PLAYINTRO_CALLSITE", "PLAYINTRO_ENTRY", "GAME_CALLSITE",
    "VIDEO_VESA_MODE_CALLSITE", "VIDEO_FRAMEBUFFER_ASSIGN_AFTER",
}


def summarize(events: list[dict]) -> dict:
    checkpoints = [e for e in events if e.get("event") == "target_runtime_checkpoint"]
    selected = [e for e in checkpoints if e.get("checkpoint") in TARGETS]
    main = next((e for e in checkpoints if e.get("checkpoint") == "MAIN_ENTRY_CHECKPOINT"), None)
    setup = next((e for e in selected if e.get("checkpoint") == "SETUP_GAME_ENTRY"), None)
    first_callee = next((e for e in selected if e.get("checkpoint") == "SETUP_FIRST_CALLEE"), None)
    continuation = next((e for e in selected if e.get("checkpoint") == "SETUP_GAME_CONTINUATION_94AE9"), None)
    playintro_call = next((e for e in selected if e.get("checkpoint") == "PLAYINTRO_CALLSITE"), None)
    playintro_entry = next((e for e in selected if e.get("checkpoint") == "PLAYINTRO_ENTRY"), None)
    game_call = next((e for e in selected if e.get("checkpoint") == "GAME_CALLSITE"), None)
    mapping = None
    if main:
        mapping = {"link_va": main.get("link_va"), "runtime_eip": main.get("eip"),
                   "code_rebase": main.get("eip", 0) - main.get("link_va", 0),
                   "data_rebase": main.get("data_rebase"), "cs": main.get("cs"),
                   "ds": main.get("ds")}
    route = []
    for event in (setup, first_callee, continuation, playintro_call, playintro_entry, game_call):
        if event:
            route.append({"sequence": event.get("sequence"),
                          "checkpoint": event.get("checkpoint"),
                          "link_va": event.get("link_va"),
                          "runtime_eip": event.get("eip"),
                          "return_address": event.get("return_address"),
                          "branch_taken": event.get("branch_taken"),
                          "branch_destination_link": event.get("branch_destination_link"),
                          "eax": event.get("eax"), "ebx": event.get("ebx"),
                          "ecx": event.get("ecx"), "edx": event.get("edx"),
                          "esp": event.get("esp"), "eflags": event.get("eflags"),
                          "stack_words_u32": event.get("stack_words_u32"),
                          "bytes": event.get("bytes")})
    return {"classification": "CONTINUATION_CAPTURED" if continuation else "INCONCLUSIVE",
            "main_mapping": mapping,
            "main_entry": main,
            "setup_game_entry": setup,
            "first_setup_callee": first_callee,
            "setup_game_continuation_94ae9": continuation,
            "playintro_callsite": playintro_call,
            "playintro_entry": playintro_entry,
            "game_callsite": game_call,
            "route": route,
            "all_target_checkpoints": selected,
            "last_checkpoint": checkpoints[-1] if checkpoints else None,
            "continuation_order_valid": bool(
                setup and continuation and
                setup.get("sequence", -1) < continuation.get("sequence", -1)),
            "playintro_reached": playintro_entry is not None,
            "game_callsite_reached": game_call is not None}
