"""Replay the exact measured DOS AH=48 request at the post-DPMI frontier."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dos_ah48_frontier_work2.json"


def main():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [sys.executable, str(ROOT / "tests" / "test_native_guest_image.py"),
               "--command-tail=-k", "--continue-known-services",
               "--continue-selector-query", "--continue-time-query",
               "--continue-dpmi-linear-allocation", "--continue-dos-ah48",
               "--cd-present-fixture", "--evidence-name", EVIDENCE.name]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    progress = data["native_generated_c_progress"]
    response = progress["dos_ah48"]
    if response["response_eax"] != "0x0000004C" or response["carry"] != 0 or response["handled"] != 1:
        raise AssertionError(f"native measured AH=48 response mismatch: {response}")
    for reg in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        if response["request_" + reg] != response["response_" + reg]:
            raise AssertionError(f"AH=48 changed preserved {reg}: {response}")
    frontier = progress["next_frontier"]
    if frontier.get("instruction_va") == "0x000C3D21":
        raise AssertionError(f"native replay did not resume past AH=48: {frontier}")

    oracle = json.loads((ROOT / "evidence" / "cd_present_gate_work3.json").read_text(encoding="utf-8"))
    events = oracle["runtime_service_tail"]
    index = next((i for i, item in enumerate(events)
                  if item.get("eip") == "0x001c3d21" and
                  item.get("registers", {}).get("eax") == "0x00004800" and
                  item.get("registers", {}).get("ebx") == "0x00000001"), None)
    if index is None:
        raise AssertionError("original CUE-present trace lacks the matching DOS AH=48 request")
    measured = events[index]
    if measured["registers_after"]["eax"] != "0x0000004c" or int(measured["registers_after"]["eflags"], 16) & 1:
        raise AssertionError(f"oracle AH=48 contract changed: {measured}")
    data["original_byte_oracle_ah48_crosscheck"] = {
        "evidence": "evidence/cd_present_gate_work3.json", "eip": measured["eip"],
        "request": measured["registers"], "response": measured["registers_after"],
        "service": measured["service"], "handled": measured["handled"],
        "comparison": "AX=004C, CF=0, unrelated registers preserved; snapshots remain oracle/native separated",
    }
    EVIDENCE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("PASS native DOS AH=48 measured response and next guest frontier")


if __name__ == "__main__":
    main()
