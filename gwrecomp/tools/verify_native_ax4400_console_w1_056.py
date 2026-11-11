"""Validate W1-056's fresh, provider-backed native BX=1 replay evidence."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_TARGET = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
EXPECTED_ADDRESS = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"
EXPECTED_SOUND = "339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3"


def _line_fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)


def validate_capture(data: dict, root: pathlib.Path = ROOT) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require(data.get("schema") == "gwrecomp.native-setup-replay/v1", "unexpected native capture schema")
    require(data.get("execution_mode") == "native_recompiled_guest", "capture is not a native recompiled execution")
    require(bool(data.get("capture_id")), "capture_id is missing")
    try:
        captured_at = datetime.fromisoformat(str(data.get("captured_at", "")).replace("Z", "+00:00"))
        require(captured_at.tzinfo is not None and captured_at <= datetime.now(timezone.utc), "capture timestamp is invalid or in the future")
    except ValueError:
        require(False, "capture timestamp is missing or invalid")
    require(data.get("native_returncode") == 0, "native replay did not return successfully")
    require(data.get("command_tail") == "-k 38928", "measured diagnostic command tail was not preserved")
    options = set(data.get("replay_options", []))
    required_options = {
        "--serve-w3-functional-config", "--serve-w3-address-seed", "--serve-w3-sound-ini",
        "--continue-dos-ah3c", "--continue-dos-ax4400", "--continue-dos-ah40",
        "--continue-dos-ax4400-console", "--capture-crt-startup",
    }
    require(required_options <= options, "replay options omit an authenticated fixture or required continuation")

    require(data.get("target_sha256", "").lower() == EXPECTED_TARGET, "target executable fingerprint differs from W3-067")
    require(data.get("build_id") == data.get("build_artifact", {}).get("sha256"), "native build ID does not match its captured artifact")
    require(bool(data.get("build_fingerprints", {}).get("closure_source_sha256")), "closure source fingerprint is missing")
    require(bool(data.get("build_fingerprints", {}).get("routed_closure_object_sha256")), "routed closure object fingerprint is missing")
    require(bool(data.get("build_fingerprints", {}).get("capture_closure_object_sha256")), "capture closure object fingerprint is missing")
    require(bool(data.get("build_fingerprints", {}).get("native_harness_source_sha256")), "native harness fingerprint is missing")
    require(bool(data.get("runtime_fingerprint", {}).get("c_h_sha256")), "Runtime fingerprint is missing")

    crt = data.get("crt", {})
    require(crt.get("callback_count") == 19 and len(crt.get("destinations", [])) == 19, "CRT did not execute all 19 callbacks")
    require(data.get("argv", {}).get("argc") == 3, "native argc is not 3")
    require(data.get("argv", {}).get("values", [None, None, None])[1:] == ["-k", "38928"], "argv does not preserve the diagnostic arguments")
    require(data.get("gate", {}).get("local_64") == "01" and data.get("gate", {}).get("local_68") == "01", "main game gate is not 1/1")
    require(data.get("roots", {}).get("setup_game", {}).get("observed") is True, "setup_game entry was not observed")
    require(data.get("roots", {}).get("setup_game", {}).get("link_va", "").lower() == "0x00094ac0", "setup_game link VA mismatch")
    require(data.get("roots", {}).get("first_callee_14bf0", {}).get("observed") is True, "callee 0x14BF0 was not observed")

    config = data.get("config_ini", {})
    require(config.get("opened") is True and str(config.get("path", "")).casefold() == r"c:\genewars\config.ini", "authentic CONFIG.INI was not opened through its guest path")
    require(config.get("bytes_read") == 130 and config.get("eof_observed") is True, "CONFIG.INI read length or EOF differs from the 130-byte fixture")
    try:
        config_fixture = root / "tests" / "fixtures" / "w3_067_functional_config.ini"
        config_bytes = config_fixture.read_bytes()
        require(len(config_bytes) == 130 and hashlib.sha256(config_bytes).hexdigest() == config.get("sha256_read"), "CONFIG.INI bytes do not match the authenticated fixture")
    except OSError:
        require(False, "authenticated CONFIG.INI fixture is unavailable")

    fixtures = data.get("fixtures", {})
    components = fixtures.get("components", {})
    require(fixtures.get("comparable") is True, "fixture fingerprints are not comparable")
    require(components.get("address_txt_sha256", "").lower() == EXPECTED_ADDRESS, "ADDRESS.TXT hash is not the authenticated 24-byte seed")
    require(components.get("config_ini_sha256", "").lower() == config.get("sha256_read", "").lower(), "CONFIG.INI fixture fingerprint differs from the bytes read")
    native_fixture = fixtures.get("native", {})
    require(native_fixture.get("address_txt_sha256", "").lower() == EXPECTED_ADDRESS, "native provider did not use authenticated ADDRESS.TXT")
    require(native_fixture.get("address_provider_open") is not None, "ADDRESS.TXT provider visibility/open event is missing")
    sound = data.get("sound_ini_continuation", {})
    require(sound.get("sha256", "").lower() == EXPECTED_SOUND and sound.get("size") == 11, "SOUND.INI bytes do not match the authenticated fixture")
    try:
        sound_fixture = root / "tests" / "fixtures" / "w3_069_sound_ini_work1.bin"
        require(hashlib.sha256(sound_fixture.read_bytes()).hexdigest() == EXPECTED_SOUND, "SOUND.INI fixture hash differs from W3-069")
    except OSError:
        require(False, "authenticated SOUND.INI fixture is unavailable")

    w2_path = root / "evidence" / "w2_111_ax4400_stream_metadata.json"
    try:
        w2 = json.loads(w2_path.read_text(encoding="utf-8"))
        original = w2["original_observation"]
        expected_c = w2["fingerprints"]["runtime_c_sha256"].lower()
        require(original["link_va"].lower() == "0xc8973" and original["request"]["ax"].lower() == "0x4400" and original["request"]["bx"].lower() == "0x1", "W2-111 provenance does not describe the measured BX=1 request")
        require(original["response"]["ax"].lower() == "0x80d3" and original["response"]["dx"].lower() == "0x80d3" and original["response"]["cf"] is False, "W2-111 response contract is not AX=DX=0x80D3/CF=0")
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        expected_c = ""
        require(False, "W2-111 provenance evidence is unavailable or malformed")

    replay = data.get("w1_056_ax4400_console", {})
    require(replay.get("runtime_matches_w2_111") is True and replay.get("runtime_c_sha256", "").lower() == expected_c and replay.get("runtime_expected_w2_111_sha256", "").lower() == expected_c, "native Runtime fingerprint does not match W2-111")
    setup_line = replay.get("provider_setup") or ""
    setup = _line_fields(setup_line) if setup_line else {}
    require(setup.get("handle") == "1" and setup.get("device_info") == "80d3" and setup.get("source") == "W3-091:BX=1:CON", "provider was not configured from the measured CON contract")
    events = replay.get("provider_response_events", [])
    require(len(events) == 1, "expected one provider-backed response at the natural BX=1 request")
    if events:
        event = events[0]
        require(event.get("ordinal") == "1" and event.get("eip") == "000c8973", "provider response was not the first request at link 0xC8973")
        require(event.get("request_eax", "").lower() == "00004400" and event.get("request_ebx", "").lower() == "00000001", "natural AX=4400/BX=1 request differs")
        require(event.get("configured_device_info", "").lower() == "80d3", "provider metadata word differs from W3-091")
        response_edx = int(event.get("response_edx", "0"), 16)
        request_edx = int(event.get("request_edx", "0"), 16)
        require(event.get("response_eax", "").lower() == "000080d3" and (response_edx & 0xffff) == 0x80d3 and
                (response_edx & 0xffff0000) == (request_edx & 0xffff0000) and
                event.get("cf_out") == "0" and event.get("handled") == "1",
                "Runtime provider response differs from measured AX=DX=0x80D3/CF=0 with upper EDX preserved")
        for reg in ("ebx", "ecx", "esi", "edi", "ebp", "esp"):
            require(event.get("request_" + reg) == event.get("response_" + reg), f"Runtime changed unrelated {reg.upper()} during AX=4400")
        for seg in ("cs", "ds", "es", "ss"):
            require(event.get("request_" + seg) == event.get("response_" + seg), f"Runtime changed {seg.upper()} during AX=4400")
        for flags in ("flags_k", "flags_a", "flags_b"):
            require(event.get("request_" + flags) == event.get("response_" + flags), f"Runtime changed unrelated flag word {flags}")
    frontier = replay.get("next_frontier", {})
    require(bool(frontier.get("trap_va")) and frontier.get("trap_va", "").lower() != "000c8973", "next natural frontier is missing or repeats the answered service")
    require(replay.get("original_equivalence_claimed") is False, "capture improperly claims original/native invocation equivalence")
    return errors


def main(argv: list[str] | None = None) -> int:
    path = pathlib.Path(argv[1] if argv and len(argv) > 1 else sys.argv[1] if len(sys.argv) > 1 else "evidence/native_ax4400_console_replay_w1_056.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(data, ROOT)
    if errors:
        for error in errors:
            print("FAIL:", error)
        return 1
    print("PASS W1-056: fresh BX=1 replay used W2-111 provider metadata and captured the next frontier")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
