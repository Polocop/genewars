"""Validate W1-060's native DOS AH=25h vector-8 continuation."""
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

    require(data.get("schema") == "gwrecomp.native-setup-replay/v1", "unexpected capture schema")
    require(data.get("execution_mode") == "native_recompiled_guest", "capture is not native execution")
    require(data.get("native_returncode") == 0, "bounded native replay did not complete")
    require(data.get("target_sha256", "").lower() == TARGET_SHA, "target hash differs from authenticated executable")
    require(data.get("build_id") == data.get("build_artifact", {}).get("sha256"), "build fingerprint mismatch")
    try:
        timestamp = datetime.fromisoformat(str(data.get("captured_at", "")).replace("Z", "+00:00"))
        require(timestamp.tzinfo is not None and timestamp <= datetime.now(timezone.utc), "capture timestamp invalid")
    except ValueError:
        require(False, "capture timestamp missing or invalid")
    options = set(data.get("replay_options", []))
    required = {"--continue-dpmi-ax0200", "--continue-dos-ah35", "--continue-dos-ah25",
                "--capture-crt-startup", "--serve-w3-functional-config", "--serve-w3-address-seed",
                "--serve-w3-sound-ini", "--reuse-compiled-closure"}
    require(required <= options, "replay omitted an authenticated prerequisite or AH=25h continuation")
    require(data.get("crt", {}).get("callback_count") == 19, "CRT callback count changed")
    require(data.get("argv", {}).get("argc") == 3, "argc is not 3")
    require(data.get("gate", {}).get("local_64") == "01" and data.get("gate", {}).get("local_68") == "01", "game gate is not 1/1")
    require(data.get("roots", {}).get("setup_game", {}).get("observed") is True, "setup_game was not reached")
    require(data.get("roots", {}).get("first_callee_14bf0", {}).get("observed") is True, "callee 0x14BF0 was not reached")
    require(data.get("config_ini", {}).get("opened") is True and data.get("config_ini", {}).get("bytes_read") == 130 and
            data.get("config_ini", {}).get("eof_observed") is True, "CONFIG.INI lifecycle regressed")
    require(data.get("fixtures", {}).get("comparable") is True, "fixture fingerprint is not comparable")

    prev = data.get("w1_059_dos_ah35", {})
    require(prev.get("native_contract_checks", {}).get("response_bx_low_word_zero") is True,
            "AH=35h predecessor response missing")
    replay = data.get("w1_060_dos_ah25", {})
    event = replay.get("provider_response_event", {})
    require(event.get("eip", "").lower() == "000c8d0c", "native AH=25h is not at link VA 0xC8D0C")
    require(event.get("vector", "").lower() == "21" and event.get("request_eax", "").lower() == "00002508",
            "request is not INT 21h AX=2508")
    require((int(event.get("request_eax", "0"), 16) & 0xff) == 8, "request AL is not vector 8")
    require(event.get("provider") == "gw_dos_services_callback" and event.get("handled") == "1",
            "request did not use the native Runtime callback")
    checks = replay.get("runtime_contract_checks", {})
    require(checks.get("unrelated_registers_preserved") is True, "AH=25h changed an unrelated general register")
    require(checks.get("segments_preserved") is True, "AH=25h changed a segment register")
    require(checks.get("non_carry_flags_preserved") is True, "AH=25h changed non-carry flags")
    require(checks.get("carry_clear") is True and event.get("cf_out") == "0", "AH=25h did not return CF clear")
    original = replay.get("original_observation", {})
    require(original.get("link_va", "").lower() == "0x001c8d0c" and
            original.get("request_ds", "").lower() == "0x000c" and
            original.get("request_edx", "").lower() == "0x001c8a5e", "original AH=25h request evidence mismatch")
    require(original.get("native_dx_is_not_compared_as_same_address") is True,
            "original and native DX values were incorrectly treated as the same address")
    require(replay.get("original_equivalence_claimed") is False, "evidence overstates original/native equivalence")

    runtime = replay.get("runtime_source_hashes", {}).get("gw_dos_services_c_sha256", "")
    source_path = root / "runtime" / "gw_dos_services.c"
    require(bool(runtime) and hashlib.sha256(source_path.read_bytes()).hexdigest() == runtime,
            "captured C Runtime fingerprint is missing or stale")
    source = source_path.read_text(encoding="utf-8")
    require("if (function == 0x25u)" in source, "current Runtime lacks the AH=25h handler")
    frontier = replay.get("next_frontier", {})
    require(bool(frontier) and frontier.get("eip", "").lower() not in {"", "000c8d0c"},
            "post-AH=25h native frontier is missing or repeats the request")
    recovery = data.get("recovery", {})
    require("W1-060" in str(recovery.get("manifest", "")) and bool(recovery.get("verification_sha256")),
            "W1-060 recovery verification is not recorded")
    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    path = pathlib.Path(args[0]) if args else ROOT / "evidence" / "native_dos_ah25_replay_w1_060.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(data, ROOT)
    if errors:
        for error in errors:
            print("FAIL:", error)
        return 1
    print("PASS W1-060: native AH=25h used the Runtime callback and continued to a fresh frontier")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
