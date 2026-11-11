"""Continue native entry through the measured DPMI AX=0501 failure contract."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dpmi_linear_alloc_frontier_work2.json"


def main():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [sys.executable, str(ROOT / "tests" / "test_native_guest_image.py"),
               "--command-tail=-k", "--continue-known-services",
               "--continue-selector-query", "--continue-time-query",
               "--continue-dpmi-linear-allocation", "--cd-present-fixture",
               "--evidence-name", EVIDENCE.name]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    progress = data["native_generated_c_progress"]
    service = progress["dpmi_linear_allocation"]
    if service["response_eax"] != "0x00008012" or service["carry"] != 1 or service["handled"] != 1:
        raise AssertionError(f"native measured DPMI unavailable response mismatch: {service}")
    for reg in ("ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        if service.get("response_" + reg) != service.get("request_" + reg):
            raise AssertionError(f"DPMI AX=0501 changed preserved {reg}: {service}")

    oracle = json.loads((ROOT / "evidence" / "cd_present_gate_work3.json").read_text(encoding="utf-8"))
    matches = [event for event in oracle["runtime_service_tail"]
               if event.get("eip") == "0x001c3cc1" and
               event.get("registers", {}).get("eax") == "0x00000501" and
               event.get("registers", {}).get("ebx") == "0x00000000" and
               event.get("registers", {}).get("ecx") == "0x00008000"]
    if not matches:
        raise AssertionError("original CD-present trace lacks the exact AX=0501 unavailable request")
    measured = matches[0]
    if measured["service"] != "dpmi31.allocate_memory.unavailable" or \
            measured["registers_after"]["eax"] != "0x00008012" or \
            int(measured["registers_after"]["eflags"], 16) & 1 != 1:
        raise AssertionError(f"oracle AX=0501 contract changed: {measured}")
    data["original_byte_oracle_crosscheck"] = {
        "evidence": "evidence/cd_present_gate_work3.json",
        "eip": measured["eip"], "request": measured["registers"],
        "response": measured["registers_after"], "service": measured["service"],
        "comparison": "AX=8012, CF=1 and requested size preserved; native event context captured independently",
    }
    data["callback_provenance"] = progress["callback_provenance"]
    EVIDENCE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("PASS native DPMI AX=0501 measured unavailable response and next frontier")


if __name__ == "__main__":
    main()
