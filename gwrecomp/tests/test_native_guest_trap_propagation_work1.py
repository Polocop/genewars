"""Exercise nested trap wrappers and the current native -k interrupt frontier."""
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYTHON = sys.executable
GCC = r"E:\msys64\mingw32\bin\gcc.exe"
EXE = ROOT / "build" / "test_native_guest_trap_wrappers.exe"
EVIDENCE = ROOT / "evidence" / "native_entry_after_trap_propagation_work1.json"


def run(argv, env=None):
    p = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True)
    if p.returncode:
        raise SystemExit(p.stdout + p.stderr or f"command failed ({p.returncode}): {argv}")
    print(p.stdout, end="")
    return p


def main():
    env = {**os.environ, "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    run([GCC, "-std=gnu11", "-m32", "-O0", "-I", str(ROOT / "runtime"),
         "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
         "-o", str(EXE), str(ROOT / "tests" / "test_native_guest_trap_wrappers.c"),
         str(ROOT / "runtime" / "recomp_context.c"), str(ROOT / "runtime" / "gw_interrupts.c"),
         str(ROOT / "runtime" / "gw_segments.c"), str(ROOT / "runtime" / "recomp_bridge.c")], env)
    run([str(EXE)], env)

    # The native runner invokes the normal closure compiler, which refreshes the
    # root and routes INTs before building the linked executable.
    run([PYTHON, str(ROOT / "tests" / "test_native_guest_image.py"),
         "--command-tail=-k", "--continue-known-services", "--continue-selector-query",
         "--continue-time-query",
         "--evidence-name", EVIDENCE.name], env)
    source = (ROOT / "build" / "entry_path_closure.c").read_text(encoding="utf-8")
    if '#include "gw_recomp_stop.h"' not in source:
        raise AssertionError("canonical entry closure is missing nested guest-stop wrappers")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    trap = evidence["native_generated_c_progress"]["next_frontier"]
    expected = {"vector": "0x31", "instruction_va": "0x000C3CC1", "function_va": "0x000C3CA9", "event": "interrupt_trap"}
    if any(trap.get(k) != v for k, v in expected.items()):
        raise AssertionError(f"unexpected native frontier: {trap}")
    if evidence.get("run_exit") != 0 or not evidence.get("passed") or "NATIVE_EXCEPTION" in evidence.get("stdout", ""):
        raise AssertionError("native closure did not return the pending guest INT cleanly")
    print("PASS native -k returns the first structured guest interrupt without a host AV")


if __name__ == "__main__":
    main()
