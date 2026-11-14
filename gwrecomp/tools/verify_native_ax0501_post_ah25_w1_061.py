"""Validate the post-AH25 native AX=0501 caller-context capture."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"


def validate_capture(data: dict, root: pathlib.Path = ROOT) -> list[str]:
    errors: list[str] = []

    def require(ok: bool, message: str) -> None:
        if not ok:
            errors.append(message)

    require(data.get("execution_mode") == "native_recompiled_guest", "capture is not native execution")
    require(data.get("native_returncode") == 0, "bounded native replay did not complete")
    require(data.get("target_sha256", "").lower() == TARGET_SHA, "authenticated target hash mismatch")
    require(data.get("build_id") == data.get("build_artifact", {}).get("sha256"), "build fingerprint mismatch")
    try:
        stamp = datetime.fromisoformat(str(data.get("captured_at", "")).replace("Z", "+00:00"))
        require(stamp.tzinfo is not None and stamp <= datetime.now(timezone.utc), "capture timestamp invalid")
    except ValueError:
        require(False, "capture timestamp missing or invalid")
    options = set(data.get("replay_options", []))
    required = {"--continue-dos-ah25", "--continue-dos-ah35", "--continue-dpmi-ax0200",
                "--capture-ax0501-stack", "--capture-crt-startup", "--serve-w3-functional-config",
                "--serve-w3-address-seed", "--serve-w3-sound-ini", "--reuse-compiled-closure"}
    require(required <= options, "replay omitted an authenticated prerequisite or bounded stack capture")
    require(data.get("crt", {}).get("callback_count") == 19, "CRT callback count changed")
    require(data.get("argv", {}).get("argc") == 3, "argc is not 3")
    require(data.get("gate", {}).get("local_64") == "01" and data.get("gate", {}).get("local_68") == "01", "game gate is not 1/1")
    require(data.get("roots", {}).get("setup_game", {}).get("observed") is True, "setup_game was not reached")
    require(data.get("roots", {}).get("first_callee_14bf0", {}).get("observed") is True, "callee 0x14BF0 was not reached")
    require(data.get("config_ini", {}).get("opened") is True and data.get("config_ini", {}).get("bytes_read") == 130 and
            data.get("config_ini", {}).get("eof_observed") is True, "CONFIG.INI fixture lifecycle regressed")
    require(data.get("fixtures", {}).get("comparable") is True, "authentic fixture identity is not comparable")

    require(data.get("w1_060_dos_ah25", {}).get("provider_response_event", {}).get("handled") == "1",
            "AH=25h predecessor was not handled")
    replay = data.get("w1_061_ax0501_context", {})
    frontier = replay.get("natural_frontier", {})
    require(frontier.get("eip", "").lower() == "000c3cc1" and frontier.get("eax", "").lower() == "00000501",
            "natural AX=0501 frontier missing or moved")
    require(frontier.get("function", "").lower() == "000c3ca9", "AX=0501 function context mismatch")
    size = ((int(frontier.get("ebx", "0"), 16) & 0xffff) << 16) | (int(frontier.get("ecx", "0"), 16) & 0xffff)
    require(replay.get("request_size_bytes", "").lower() == f"0x{size:08x}", "request size does not derive from live BX:CX")
    prior = replay.get("w1_036_prior_request", {})
    prior_size = ((int(prior.get("ebx", "0"), 16) & 0xffff) << 16) | (int(prior.get("ecx", "0"), 16) & 0xffff)
    require(replay.get("w1_036_request_size_bytes", "").lower() == f"0x{prior_size:08x}", "W1-036 request size mismatch")
    require(size != prior_size and replay.get("same_request_registers") is False,
            "post-AH25 request was treated as the W1-036 request despite different live state")
    require(replay.get("same_dynamic_invocation") is False, "same dynamic invocation is not established")
    stack = replay.get("stack_snapshot", {})
    require(stack.get("valid") == "1" and stack.get("trap_va", "").lower() == "000c3cc1" and
            stack.get("function", "").lower() == "000c3ca9", "bounded stack snapshot missing or invalid")
    require(all(f"word{i}" in stack for i in range(12)), "stack snapshot does not contain 12 bounded words")
    fault = replay.get("segment_fault_state", {})
    require(fault.get("pending") == "1" and fault.get("eip", "").lower() == "000d2247" and
            fault.get("selector", "").lower() == "8674", "concurrent segment-fault state changed or is absent")
    caller = replay.get("caller_analysis", {})
    require(replay.get("dynamic_caller_identified") is False and caller.get("dynamic_callsite_observed_this_run") is False,
            "capture overstates dynamic caller observation")
    require("unknown" in str(caller.get("upstream_writer", "")).lower(), "unobserved upstream writer was not preserved as unknown")
    require(len(caller.get("static_candidate_chain", [])) == 3, "static candidate call chain is incomplete")
    require(replay.get("original_equivalence_claimed") is False, "evidence overstates original equivalence")
    require(replay.get("original_contract_path") == "evidence/w3_068_dpmi0501_success_contract.json",
            "original request evidence provenance missing")
    recovery = data.get("recovery", {})
    require("W1-061" in str(recovery.get("manifest", "")) and bool(recovery.get("verification_sha256")),
            "verified recovery directory missing")
    harness_sha = data.get("build_fingerprints", {}).get("native_harness_source_sha256", "")
    require(bool(harness_sha), "native harness source fingerprint missing")
    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    path = pathlib.Path(args[0]) if args else ROOT / "evidence" / "native_ax0501_post_ah25_w1_061.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(data, ROOT)
    if errors:
        for error in errors:
            print("FAIL:", error)
        return 1
    print("PASS W1-061: post-AH25 AX=0501 context differs from W1-036 and includes bounded stack")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
