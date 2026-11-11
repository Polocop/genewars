"""Test measured AH=49 freeing and preserve the current native ES divergence."""
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dos_ah49_frontier_work2.json"


def main():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    command = [sys.executable, str(ROOT / "tests" / "test_native_guest_image.py"),
               "--command-tail=-k", "--continue-known-services",
               "--continue-selector-query", "--continue-time-query",
               "--continue-dpmi-linear-allocation", "--continue-dos-ah48",
               "--continue-dos-ah48-retry", "--test-dos-ah49-contract",
               "--cd-present-fixture", "--evidence-name", EVIDENCE.name]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    progress = data["native_generated_c_progress"]
    contract = progress["dos_ah49_contract_test"]
    if not contract["all_gprs_preserved"] or contract["success_selector"] != "0x004C" or \
            contract["native_selector"] != "0x0014" or contract["wrong_selector_result"] != "trapped":
        raise AssertionError(f"AH=49 selector-gated contract test failed: {contract}")
    frontier = progress["next_frontier"]
    if frontier.get("instruction_va") != "0x000C3D46" or frontier.get("es") != "0x0014":
        raise AssertionError(f"native full replay hid or changed the ES mismatch: {frontier}")

    oracle = json.loads((ROOT / "evidence" / "cd_present_gate_work3.json").read_text(encoding="utf-8"))
    oracle_event = next((item for item in oracle["interrupt_tail"]
                         if item.get("eip_int_opcode_assumption") == "0x001c3d46"), None)
    if oracle_event is None or oracle_event.get("es") != "0x004c":
        raise AssertionError("original-byte AH=49 ES=004C oracle evidence is missing")
    data["original_byte_oracle_ah49"] = {
        "evidence": "evidence/cd_present_gate_work3.json",
        "event": oracle_event,
        "native_oracle_difference": "oracle ES=004C; native ES=0014; native service remains trapped",
    }
    EVIDENCE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("PASS measured DOS AH=49 contract; wrong native ES remains fail-closed")


if __name__ == "__main__":
    main()
