"""Replay native entry through measured DOS AH=2Ch and capture the next stop."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dos_time_query_work2.json"


def main():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [sys.executable, str(ROOT / "tests" / "test_native_guest_image.py"),
               "--command-tail=-k", "--continue-known-services",
               "--continue-selector-query", "--continue-time-query",
               "--cd-present-fixture",
               "--evidence-name", EVIDENCE.name]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    progress = evidence["native_generated_c_progress"]
    time_service = progress.get("dos_time_query")
    expected_service = {
        "vector": "0x21", "instruction_va": "0x000D5B24",
        "request_eax": "0x00002C00", "request_ebx": "0x00000000",
        "request_ecx": "0x00000000", "request_edx": "0x00000000",
        "response_eax": "0x00002C00", "response_ebx": "0x00000000",
        "response_ecx": "0x00000000", "response_edx": "0x00000005",
        "hour": 0, "minute": 0, "second": 0, "hundredths": 5,
        "carry": 0, "handled": True,
    }
    if time_service != expected_service:
        raise AssertionError(f"native AH=2Ch contract mismatch: {time_service}")
    next_frontier = progress["next_frontier"]
    expected_frontier = {"vector": "0x31", "instruction_va": "0x000C3CC1",
                         "function_va": "0x000C3CA9", "eax": "0x00000501",
                         "ebx": "0x00000000", "ecx": "0x00008000",
                         "event": "interrupt_trap"}
    if any(next_frontier.get(key) != value for key, value in expected_frontier.items()):
        raise AssertionError(f"unexpected post-time frontier: {next_frontier}")
    if evidence.get("run_exit") != 0 or not evidence.get("passed"):
        raise AssertionError("native guest replay failed")
    fixture = progress.get("cd_fixture_preflight")
    expected_cue = "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5"
    expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if (fixture is None or fixture.get("command_tail") != "-k" or
            fixture.get("config_sha256") != expected_empty or fixture.get("config_size") != 0 or
            fixture.get("cdrom_drives") != ["D"] or
            fixture.get("cue_sha256_before") != expected_cue or
            fixture.get("cue_sha256_after") != expected_cue or
            not fixture.get("cue_read_only_mount") or
            not fixture.get("nested_text_resource_present") or
            fixture.get("flat_data_text_alias_present") or
            fixture.get("native_cd_request_reached") is not False):
        raise AssertionError(f"CD-present fixture parity differs or was overstated: {fixture}")

    # Cross-check against the original-byte W2-018 trace. The oracle has a
    # different incoming volatile register snapshot but returns the same time.
    oracle_path = ROOT / "evidence" / "dpmi_alloc_contract_work3.json"
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    records = [item for item in oracle["interrupts_after_first_success"]
               if item.get("eip_int_opcode_assumption") == "0x001d5b24"]
    if len(records) != 1:
        raise AssertionError(f"expected one original-byte AH=2Ch record, got {len(records)}")
    record = records[0]
    if record["registers_after"]["ecx"] != "0x00000000" or record["registers_after"]["edx"] != "0x00000005":
        raise AssertionError("oracle time response changed; remeasure before accepting")
    evidence["native_generated_c_progress"]["dos_time_query"] = expected_service
    evidence["original_byte_oracle_crosscheck"] = {
        "evidence": "evidence/dpmi_alloc_contract_work3.json",
        "eip": "0x001D5B24", "request": record["registers"],
        "response": record["registers_after"],
        "service": record["service"], "handled": record["handled"],
        "time_fields": {"hour": 0, "minute": 0, "second": 0, "hundredths": 5},
        "comparison": "time fields match; native incoming EAX/EBX/ECX/EDX differ from the original-byte oracle",
    }
    evidence["frontier_interpretation"] = {
        "after_AH_2Ch": "native execution reaches DPMI AX=0501 at 0x000C3CC1",
        "meaning": "first post-time unhandled native interrupt; separate from original-byte AH=2Ch follow-up time polling",
        "menu_reached": False,
    }
    EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("PASS native DOS AH=2Ch exact measured time fields, register preservation, CF, and next DPMI frontier")


if __name__ == "__main__":
    main()
