"""Replay native entry through the exact DOS AH=48 insufficient-memory retry."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dos_ah48_retry_work2.json"


def main():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [sys.executable, str(ROOT / "tests" / "test_native_guest_image.py"),
               "--command-tail=-k", "--continue-known-services",
               "--continue-selector-query", "--continue-time-query",
               "--continue-dpmi-linear-allocation", "--continue-dos-ah48",
               "--continue-dos-ah48-retry", "--cd-present-fixture",
               "--evidence-name", EVIDENCE.name]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    service = data["native_generated_c_progress"]["dos_ah48_retry"]
    expected = {"instruction_va": "0x000C3D35", "request_eax": "0x0000484C",
                "request_ebx": "0x00000800", "request_ecx": "0x00008000",
                "request_edx": "0x0000004C", "response_eax": "0x00000008",
                "response_ebx": "0x00000034", "response_ecx": "0x00008000",
                "response_edx": "0x0000004C", "carry": 1, "handled": 1}
    if any(service.get(key) != value for key, value in expected.items()):
        raise AssertionError(f"native AH=48 retry differs from measured response: {service}")
    for reg in ("ecx", "edx", "esi", "edi", "ebp", "esp"):
        if service["request_"+reg] != service["response_"+reg]:
            raise AssertionError(f"AH=48 retry changed preserved {reg}: {service}")

    oracle = json.loads((ROOT / "evidence" / "cd_present_gate_work3.json").read_text(encoding="utf-8"))
    match = next((event for event in oracle["runtime_service_tail"]
                  if event.get("eip") == "0x001c3d35" and
                  event.get("registers", {}).get("eax") == "0x0000484c" and
                  event.get("registers", {}).get("ebx") == "0x00000800"), None)
    if not match or match["registers_after"]["eax"] != "0x00000008" or \
            match["registers_after"]["ebx"] != "0x00000034" or \
            int(match["registers_after"]["eflags"], 16) & 1 != 1:
        raise AssertionError(f"original-byte oracle AH=48 response differs: {match}")
    native_next = data["native_generated_c_progress"]["next_frontier"]
    oracle_free = next((event for event in oracle["interrupt_tail"]
                        if event.get("eip_int_opcode_assumption") == "0x001c3d46"), None)
    if oracle_free is None or oracle_free.get("es") != "0x004c" or native_next.get("es") != "0x0014":
        raise AssertionError(f"expected distinct AH=49 segment snapshots: oracle={oracle_free}, native={native_next}")
    data["original_byte_oracle_ah48_retry_crosscheck"] = {
        "evidence": "evidence/cd_present_gate_work3.json", "eip": match["eip"],
        "request": match["registers"], "response": match["registers_after"],
        "service": match["service"], "handled": match["handled"],
        "comparison": "AX=8, BX=0x34, CF=1; remaining register snapshots retained separately",
    }
    data["next_state_divergence"] = {
        "service": "DOS INT 21h AH=49 at link 0x000C3D46 / original 0x001C3D46",
        "original_es": oracle_free["es"], "native_es": native_next["es"],
        "classification": "native guest selector state diverges before AH=49; do not route this to Runtime AH=49 until the first guest-state instruction divergence is owned",
        "oracle_event": oracle_free,
    }
    EVIDENCE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("PASS native DOS AH=48 insufficient-memory response and next event")


if __name__ == "__main__":
    main()
