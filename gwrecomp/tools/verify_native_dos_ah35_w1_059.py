"""Validate W1-059's fresh native DOS AH=35h/vector-8 continuation."""
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
    require(data.get("evidence_level") == "DIFF_VERIFIED", "capture evidence level changed")
    require(data.get("native_returncode") == 0, "bounded native replay did not complete")
    require(data.get("target_sha256", "").lower() == TARGET_SHA, "target hash differs from authenticated game executable")
    require(data.get("build_id") == data.get("build_artifact", {}).get("sha256"), "build fingerprint mismatch")
    try:
        stamp = datetime.fromisoformat(str(data.get("captured_at", "")).replace("Z", "+00:00"))
        require(stamp.tzinfo is not None and stamp <= datetime.now(timezone.utc), "capture timestamp invalid")
    except ValueError:
        require(False, "capture timestamp missing or invalid")

    options = set(data.get("replay_options", []))
    required = {"--continue-dpmi-ax0200", "--continue-dos-ah35", "--capture-crt-startup",
                "--serve-w3-functional-config", "--serve-w3-address-seed", "--serve-w3-sound-ini",
                "--reuse-compiled-closure"}
    require(required <= options, "replay omitted the previous authenticated continuation or fixtures")
    require(data.get("crt", {}).get("callback_count") == 19, "CRT callbacks no longer total 19")
    require(data.get("argv", {}).get("argc") == 3, "argc is not 3")
    require(data.get("gate", {}).get("local_64") == "01" and data.get("gate", {}).get("local_68") == "01", "game gate is not 1/1")
    require(data.get("roots", {}).get("setup_game", {}).get("observed") is True, "setup_game was not reached")
    require(data.get("roots", {}).get("first_callee_14bf0", {}).get("observed") is True, "callee 0x14BF0 was not reached")
    require(data.get("config_ini", {}).get("opened") is True and data.get("config_ini", {}).get("bytes_read") == 130 and
            data.get("config_ini", {}).get("eof_observed") is True, "authenticated CONFIG.INI lifecycle regressed")
    require(data.get("fixtures", {}).get("comparable") is True, "authentic fixture identity is not comparable")

    prior = data.get("w1_058_dpmi_ax0200", {})
    require(prior.get("provider_response_events", [{}])[0].get("handled") == "1", "AX=0200 predecessor continuation missing")
    replay = data.get("w1_059_dos_ah35", {})
    events = replay.get("provider_response_event", {})
    require(events.get("eip", "").lower() == "000c8cdf", "native AH=35h event is not at link VA 0xC8CDF")
    require(events.get("vector", "").lower() == "21" and events.get("request_eax", "").lower() == "00003508",
            "native request is not INT 21h AX=3508")
    require((int(events.get("request_ebx", "0"), 16) & 0xffff) == 8, "native request is not DOS vector 8")
    require(events.get("provider") == "gw_dos_services_callback" and events.get("handled") == "1",
            "request did not use the existing Runtime callback")
    checks = replay.get("native_contract_checks", {})
    require(checks.get("response_ax_preserved") is True, "Runtime changed AX for AH=35h")
    require(checks.get("response_bx_low_word_zero") is True, "Runtime did not return vector offset BX=0")
    require(checks.get("response_cf_clear") is True, "Runtime did not clear CF")
    require(checks.get("original_es_comparison") == "not measured in original evidence", "unmeasured original ES was compared")
    original = replay.get("original_observation", {})
    require(original.get("response_ebx", "").lower() == "0x00000000" and original.get("response_cf") is False,
            "original-byte evidence no longer supports BX=0/CF=0")
    require(original.get("response_es_measured") is False, "original returned ES is incorrectly marked measured")
    require(replay.get("original_equivalence_claimed") is False, "evidence claims whole-run equivalence")

    runtime_c = root / "runtime" / "gw_dos_services.c"
    captured_runtime = replay.get("runtime_source_hashes", {}).get("gw_dos_services_c_sha256", "")
    require(bool(captured_runtime) and hashlib.sha256(runtime_c.read_bytes()).hexdigest() == captured_runtime,
            "C Runtime fingerprint is absent or no longer matches this capture")
    source = runtime_c.read_text(encoding="utf-8")
    require("if (function == 0x35u)" in source, "current Runtime no longer contains the AH=35h handler")
    frontier = replay.get("next_frontier", {})
    require(bool(frontier) and frontier.get("eip", "").lower() not in {"", "000c8cdf"},
            "fresh continuation frontier missing or repeats AH=35h")
    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    path = pathlib.Path(args[0]) if args else ROOT / "evidence" / "native_dos_ah35_replay_w1_059.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(data, ROOT)
    if errors:
        for error in errors:
            print("FAIL:", error)
        return 1
    print("PASS W1-059: native AH=35h reached the Runtime and continued to a fresh frontier")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
