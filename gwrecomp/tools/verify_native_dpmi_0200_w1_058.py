"""Validate W1-058's fresh native DPMI vector-8 callback replay."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
ADDRESS_SHA = "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee"
SOUND_SHA = "339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3"
RUNTIME_SHA = {
    "gw_dos_services_c_sha256": "71993fb0d997fb0430e496ee04ab69f421d7fbe6e5a421f383485ec59a97e078",
    "gw_dos_services_h_sha256": "6e3caafca1e188317dbbadf9bc188cfda5014d6721980f690b42ed5b392a56bd",
    "dos_services_py_sha256": "71d31422a5591c3c1ad36b2dce62b66ac7a218e05a67e0d3ec5ea0cda0fbacab",
}


def _fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.split()[1:] if "=" in token)


def validate_capture(data: dict, root: pathlib.Path = ROOT) -> list[str]:
    errors: list[str] = []

    def require(ok: bool, message: str) -> None:
        if not ok:
            errors.append(message)

    require(data.get("schema") == "gwrecomp.native-setup-replay/v1", "unexpected capture schema")
    require(data.get("execution_mode") == "native_recompiled_guest", "capture is not native execution")
    require(bool(data.get("capture_id")), "fresh capture ID is missing")
    try:
        stamp = datetime.fromisoformat(str(data.get("captured_at", "")).replace("Z", "+00:00"))
        require(stamp.tzinfo is not None and stamp <= datetime.now(timezone.utc), "capture timestamp is invalid or in the future")
    except ValueError:
        require(False, "capture timestamp is missing or invalid")
    require(data.get("native_returncode") == 0, "native process did not complete the bounded replay")
    require(data.get("target_sha256", "").lower() == TARGET_SHA, "target hash differs from the authenticated W3-067 executable")
    require(data.get("build_id") == data.get("build_artifact", {}).get("sha256"), "build ID and executable hash differ")
    options = set(data.get("replay_options", []))
    required_options = {
        "--serve-w3-functional-config", "--serve-w3-address-seed", "--serve-w3-sound-ini",
        "--continue-known-services", "--continue-selector-query", "--continue-time-query",
        "--continue-dpmi-linear-success", "--continue-dos-ah3d", "--continue-dos-ah3c",
        "--continue-dos-ax4400", "--continue-dos-ax4400-console", "--continue-dos-ah40",
        "--continue-dpmi-ax0200", "--capture-crt-startup", "--reuse-compiled-closure",
    }
    require(required_options <= options, "replay omitted a required continuation or authenticated fixture option")
    require(data.get("command_tail") == "-k 38928", "W1-056 measured diagnostic command tail changed")
    require(bool(data.get("build_fingerprints", {}).get("closure_source_sha256")), "closure fingerprint missing")
    require(bool(data.get("build_fingerprints", {}).get("capture_closure_object_sha256")), "capture object fingerprint missing")
    require(bool(data.get("build_fingerprints", {}).get("native_harness_source_sha256")), "native harness fingerprint missing")

    require(data.get("crt", {}).get("callback_count") == 19, "CRT callback count is not 19")
    require(data.get("argv", {}).get("argc") == 3 and data.get("argv", {}).get("values", [None, None, None])[1:] == ["-k", "38928"], "argv lost argc=3 diagnostic startup")
    require(data.get("gate", {}).get("local_64") == "01" and data.get("gate", {}).get("local_68") == "01", "game gate is not 1/1")
    roots = data.get("roots", {})
    require(roots.get("setup_game", {}).get("observed") is True and roots.get("setup_game", {}).get("link_va", "").lower() == "0x00094ac0", "setup_game entry missing")
    require(roots.get("first_callee_14bf0", {}).get("observed") is True, "callee 0x14BF0 entry missing")

    config = data.get("config_ini", {})
    require(config.get("opened") is True and config.get("bytes_read") == 130 and config.get("eof_observed") is True, "CONFIG.INI open/read/EOF contract failed")
    require(str(config.get("path", "")).casefold() == r"c:\genewars\config.ini", "CONFIG.INI guest path mismatch")
    try:
        config_bytes = (root / "tests" / "fixtures" / "w3_067_functional_config.ini").read_bytes()
        require(len(config_bytes) == 130 and hashlib.sha256(config_bytes).hexdigest() == config.get("sha256_read"), "CONFIG.INI bytes differ from the authentic fixture")
    except OSError:
        require(False, "authentic CONFIG.INI fixture unavailable")
    fixtures = data.get("fixtures", {})
    components = fixtures.get("components", {})
    native = fixtures.get("native", {})
    require(fixtures.get("comparable") is True, "fixture fingerprints are not comparable")
    require(components.get("address_txt_sha256", "").lower() == ADDRESS_SHA and native.get("address_txt_sha256", "").lower() == ADDRESS_SHA, "ADDRESS.TXT hash differs from authenticated seed")
    require("bytes=24" in str(native.get("address_provider_open", "")) and native.get("address_provider_initial_visibility") == "present", "virtual ADDRESS.TXT visibility/open is not established")
    sound = data.get("sound_ini_continuation", {})
    require(sound.get("size") == 11 and sound.get("sha256", "").lower() == SOUND_SHA, "SOUND.INI fixture identity mismatch")

    c_evidence_path = root / "evidence" / "native_dpmi_0200_c_work2.json"
    p_evidence_path = root / "evidence" / "python_dpmi_0200_0201_work2.json"
    try:
        c_contract = json.loads(c_evidence_path.read_text(encoding="utf-8"))["original_observation"]
        p_contract = json.loads(p_evidence_path.read_text(encoding="utf-8"))["original_observation"]
        require(c_contract["link_va"].lower() == "0x001c8cd2" and c_contract["input"]["EAX"].lower() == "0x00000200" and c_contract["input"]["EBX"].lower() == "0x00000008", "W2 original AX=0200 input evidence mismatch")
        require(c_contract["response"]["ECX"].lower() == "0x00000000" and c_contract["response"]["EDX"].lower() == "0x00000000" and c_contract["response"]["CF"] == 0, "original vector-8 response is not CX:DX=0:0/CF=0")
        require(p_contract["vector"].lower() == "0x08" and p_contract["response"]["CX_segment"].lower() == "0x0000" and p_contract["response"]["DX_offset"].lower() == "0x0000" and p_contract["response"]["CF"] == 0, "W2-113 corroboration differs from original vector-8 response")
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        c_contract = p_contract = {}
        require(False, "W2-112/113 original contract evidence missing or malformed")

    replay = data.get("w1_058_dpmi_ax0200", {})
    runtime_hashes = replay.get("runtime_source_hashes", {})
    for path, key in (("gw_dos_services.c", "gw_dos_services_c_sha256"),
                      ("gw_dos_services.h", "gw_dos_services_h_sha256"),
                      ("dos_services.py", "dos_services_py_sha256")):
        try:
            actual = hashlib.sha256((root / "runtime" / path).read_bytes()).hexdigest()
        except OSError:
            actual = ""
        require(actual == RUNTIME_SHA[key] and runtime_hashes.get(key, "").lower() == RUNTIME_SHA[key], f"current Runtime source {path} does not match W2-112/113")
    events = replay.get("provider_response_events", [])
    require(len(events) == 1, "expected one natural Runtime callback at 0xC8CD2")
    if events:
        event = events[0]
        require(event.get("ordinal") == "1" and event.get("vector") == "31" and event.get("eip", "").lower() == "000c8cd2", "callback does not identify the first natural INT 31h at 0xC8CD2")
        require(event.get("request_eax", "").lower() == "00000200" and (int(event.get("request_ebx", "0"), 16) & 0xff) == 8, "native request is not AX=0200/BL=8")
        require((int(event.get("response_ecx", "0"), 16) & 0xffff) == 0 and (int(event.get("response_edx", "0"), 16) & 0xffff) == 0, "native Runtime did not return CX:DX=0:0")
        req_ecx, req_edx = int(event.get("request_ecx", "0"), 16), int(event.get("request_edx", "0"), 16)
        res_ecx, res_edx = int(event.get("response_ecx", "0"), 16), int(event.get("response_edx", "0"), 16)
        require((req_ecx & 0xffff0000) == (res_ecx & 0xffff0000) and (req_edx & 0xffff0000) == (res_edx & 0xffff0000), "Runtime did not preserve upper ECX/EDX")
        require(event.get("cf_out") == "0" and event.get("handled") == "1", "Runtime did not handle the request with CF clear")
        for reg in ("eax", "ebx", "esi", "edi", "ebp", "esp"):
            require(event.get("request_" + reg) == event.get("response_" + reg), f"Runtime changed unrelated {reg.upper()}")
        for seg in ("cs", "ds", "es", "fs", "gs", "ss"):
            require(event.get("request_" + seg) == event.get("response_" + seg), f"Runtime changed {seg.upper()}")
        for word in ("flags_a", "flags_b"):
            require(event.get("request_" + word) == event.get("response_" + word), f"Runtime changed unrelated {word}")
    frontier = replay.get("next_frontier", {})
    require(bool(frontier.get("eip")) and frontier.get("eip", "").lower() != "000c8cd2", "next native frontier missing or repeats AX=0200")
    require(replay.get("original_equivalence_claimed") is False, "evidence overstates original/native equivalence")
    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    path = pathlib.Path(args[0]) if args else ROOT / "evidence" / "native_dpmi_0200_replay_w1_058.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_capture(data, ROOT)
    if errors:
        for error in errors:
            print("FAIL:", error)
        return 1
    print("PASS W1-058: native AX=0200 vector-8 response matches the captured CX:DX/CF contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
