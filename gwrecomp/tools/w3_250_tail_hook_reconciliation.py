"""Offline, evidence-bound reconciliation of W3-249's launch and hook results."""
from __future__ import annotations

import json
from pathlib import Path


EXPECTED_TAILS = ("/c gw  -k 38928", " -k 38928",
                 "/c DOS4GW C:\\GENEWARS\\GW.EXE -k 38928 ",
                 " C:\\GENEWARS\\GW.EXE -k 38928")


def dos_execute_tails(events: list[dict]) -> list[str]:
    return [str(event.get("command_tail", "")) for event in events
            if event.get("event") == "dos_execute"]


def launch_tail_status(events: list[dict], expected=EXPECTED_TAILS) -> str:
    tails = dos_execute_tails(events)
    positions = []
    start = 0
    for value in expected:
        try:
            start = tails.index(value, start) + 1
            positions.append(start)
        except ValueError:
            return "NOT_OBSERVED"
    return "OBSERVED_IN_ORDER" if positions == sorted(positions) else "ORDER_MISMATCH"


def callsite_hook_status(return_runtime: int | None, code_rebase: int | None,
                         static_return_link: int, hook_emitted: bool) -> dict:
    if return_runtime is None or code_rebase is None:
        return {"status": "UNKNOWN", "mapped_return_link": None, "mapped_callsite": None}
    return_link = return_runtime - code_rebase
    callsite = return_link - 5
    if return_link == static_return_link and not hook_emitted:
        status = "RETURN_LINK_MATCH_HOOK_NOT_EMITTED_CAUSE_UNKNOWN"
    elif return_link == static_return_link and hook_emitted:
        status = "RETURN_LINK_AND_HOOK_MATCH"
    else:
        status = "RETURN_LINK_DOES_NOT_MATCH_STATIC_CALL"
    return {"status": status, "mapped_return_link": f"0x{return_link:08X}",
            "mapped_callsite": f"0x{callsite:08X}"}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_record(root: Path) -> dict:
    ev = root / "evidence"
    raw_dir = root / "build/dosboxx_oracle/C"
    paths = {
        "w3_081": raw_dir / "W3_081_AH44_CALLER_20261008_01.jsonl",
        "w3_236": raw_dir / "W3_236_CHKTTY_AX4400.jsonl",
        "w3_249": raw_dir / "W3_249_ISATTY_CALLERS_20261009_01.jsonl",
    }
    raw = {name: [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                  if line.strip()] for name, path in paths.items()}
    summaries = {name: load_json(ev / filename) for name, filename in {
        "w3_081": "w3_081_original_ah44_caller.json",
        "w3_236": "w3_236_chktty_original_capture.json",
        "w3_241": "w3_241_isatty_static_caller.json",
        "w3_249": "w3_249_original_bx1_caller_capture.json",
    }.items()}
    static = summaries["w3_241"]["static_source"]
    entry = next((event for event in raw["w3_249"]
                  if event.get("event") == "target_runtime_checkpoint" and
                  event.get("checkpoint") == "W3_237_ISATTY_ENTRY"), None)
    dos_callback = next((event for event in raw["w3_249"]
                         if event.get("event") == "original_int21_ah44" and
                         event.get("in_ax") == 0x4400), None)
    return_runtime = entry.get("return_address") if entry else None
    code_rebase = dos_callback.get("main_code_rebase") if dos_callback else None
    hook_emitted = any(event.get("event") == "target_runtime_checkpoint" and
                       str(event.get("checkpoint", "")).startswith("W3_249_ISATTY_CALL_")
                       for event in raw["w3_249"])
    first_elapsed = entry.get("elapsed_ms") if entry else None
    prev_entry = next((event for event in raw["w3_236"]
                       if event.get("event") == "target_runtime_checkpoint" and
                       event.get("checkpoint") == "AH44_ISATTY_ENTRY"), None)
    prev_setup = next((event for event in raw["w3_236"]
                       if event.get("event") == "target_runtime_checkpoint" and
                       event.get("checkpoint") == "SETUP_GAME_ENTRY"), None)
    target_hooks = [event.get("checkpoint") for event in raw["w3_249"]
                    if event.get("event") == "target_runtime_checkpoint"]
    w3_249 = summaries["w3_249"]
    w3_236 = summaries["w3_236"]
    w3_081 = summaries["w3_081"]
    tail_status = {name: launch_tail_status(events) for name, events in raw.items()}
    same_chain = len(set(tail_status.values())) == 1 and next(iter(tail_status.values())) == "OBSERVED_IN_ORDER"
    return {
        "schema": "gwrecomp-w3-250-tail-hook-reconciliation/v1",
        "task": "W3-250",
        "classification": "ORIGINAL_LAUNCH_CHAIN_MATCH_HOOK_AND_PROGRESS_DIVERGENCE",
        "evidence_level": "ORIGINAL_OBSERVED_WITH_STATIC_CORROBORATION",
        "source_tasks": ["W3-081", "W3-236", "W3-241", "W3-248", "W3-249"],
        "source_hashes": {
            name: {"target_sha256": summary.get("preflight", {}).get("target_sha256",
                        summary.get("preflight", {}).get("fixture_sha256",
                        summary.get("preflight", {}).get("fixture_sha256"))),
                  "runtime_sha256": summary.get("preflight", {}).get("runtime_sha256",
                        summary.get("preflight", {}).get("instrumented_executable_sha256",
                        summary.get("preflight", {}).get("dosbox_sha256"))),
                  "config_sha256": summary.get("preflight", {}).get("config_sha256"),
                  "cue_sha256": summary.get("preflight", {}).get("cue_sha256",
                        summary.get("preflight", {}).get("cue_sha256_before"))}
            for name, summary in (("w3_081", w3_081), ("w3_236", w3_236), ("w3_249", w3_249))},
        "launch_chain": {
            "dos_execute_tail_status": tail_status,
            "same_measured_gw_and_dos4gw_tail_chain": same_chain,
            "expected_ordered_tails": list(EXPECTED_TAILS),
            "w3_081_effective_child_argv": w3_081.get("effective_child_argv"),
            "w3_081_psp_tail": w3_081.get("psp_command_tail"),
            "w3_236_effective_child_argv": w3_236.get("effective_child_argv"),
            "w3_236_psp_tail": w3_236.get("effective_psp_tail"),
            "w3_249_dos_execute_tails": dos_execute_tails(raw["w3_249"]),
            "w3_249_checkpoint_psp_tail_field": entry.get("psp_tail_text") if entry else None,
            "interpretation": "W3-249's dos_execute records independently show the full -k 38928 chain; its empty checkpoint psp_tail_text field is not the child EXEC-tail measurement and does not contradict those records.",
            "measured_non_game_environment_difference": "W3-249's auto-mounted Y resource path is under build/staging-w3-249-exec; W3-081/W3-236 use build/staging-w3-059-exec. C: fixture and D: CUE commands are the same.",
        },
        "runtime_progress": {
            "w3_236_runtime_sha256": w3_236.get("preflight", {}).get("runtime_sha256"),
            "w3_249_runtime_sha256": w3_249.get("preflight", {}).get("instrumented_executable_sha256"),
            "w3_236_first_isatty_elapsed_ms": prev_entry.get("elapsed_ms") if prev_entry else None,
            "w3_236_setup_game_elapsed_ms": prev_setup.get("elapsed_ms") if prev_setup else None,
            "w3_249_first_isatty_elapsed_ms": first_elapsed,
            "w3_249_checkpoints": target_hooks,
            "w3_249_guard_exit": w3_249.get("guard", {}).get("exit_reason"),
            "w3_249_guard_cause": w3_249.get("guard", {}).get("cause"),
            "w3_249_instruction_target_bx1_observed": bool(w3_249.get("checkpoints", {}).get("bx1_requests")),
            "interpretation": "W3-236 reached isatty_ at 14.705 s and setup_game at 14.730 s; W3-249 reached its first isatty_ checkpoint at 26.311 s and timed out at 30 s before BX=1. Runtime hashes differ; this measured slowdown is correlated with the new build, not proven to be caused by the added hooks.",
        },
        "caller_hook": {
            "target_sha256": static.get("target_sha256"),
            "static_caller": static.get("caller"),
            "static_callsite": static.get("callsite"),
            "static_return_link_va": static.get("callsite_return_link_va"),
            "runtime_return_address": f"0x{return_runtime:08X}" if return_runtime is not None else None,
            "measured_code_rebase": f"0x{code_rebase:08X}" if code_rebase is not None else None,
            "mapping": callsite_hook_status(return_runtime, code_rebase,
                         int(static["callsite_return_link_va"], 16), hook_emitted),
            "hook_checkpoint_emitted": hook_emitted,
            "dispatcher_contains_site_test": "link_va == 0x000afcef" in (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8"),
            "dispatcher_contains_bounded_emission_exception": "w3_249_callsite_checkpoint && w3_249_isatty_callsite_count < 16" in (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8"),
            "root_cause": "UNKNOWN: return-link/static-site mapping agrees, the runner set the capture flag and the source contains the site and bounded-emission branches, but the trace has no site event; the current capture does not identify which runtime dispatcher condition prevented emission.",
            "scope": "This return link belongs to the observed EAX=5/BX=5 sopen_ call only. It does not identify the later BX=1 caller, which was not reached in W3-249.",
        },
        "first_proven_divergence": "W3-249 emits no static caller checkpoint and progresses to the first isatty event substantially later under a different instrumented binary; the game command-tail chain itself matches.",
        "next_action": "For a future task, use the already measured isatty entry return_address plus the same-run code rebase as the caller token, record the DOS EXEC chain in the structured summary, and gate the W3-249 environment lookup outside the per-instruction dispatcher before considering another bounded replay.",
        "menu_reached": False,
        "framebuffer_reached": False,
        "gameplay_reached": False,
    }


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    output = root / "evidence/w3_250_tail_hook_reconciliation.json"
    output.write_text(json.dumps(build_record(root), indent=2) + "\n", encoding="utf-8")
    print(output)
