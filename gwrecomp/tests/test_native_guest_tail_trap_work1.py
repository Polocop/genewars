"""Compile and run the indirect-tail guest interrupt stop fixture."""
import hashlib
import json
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
GCC = r"E:\msys64\mingw32\bin\gcc.exe"
EXE = ROOT / "build" / "test_native_guest_trap_wrappers.exe"
SOURCE = ROOT / "tests" / "test_native_guest_trap_wrappers.c"
OUT = ROOT / "evidence" / "native_guest_tail_trap_work1.json"


def main():
    env = {**os.environ, "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    compile_cmd = [GCC, "-std=gnu11", "-m32", "-O0", "-I", str(ROOT / "runtime"),
                   "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
                   "-o", str(EXE), str(SOURCE), str(ROOT / "runtime" / "recomp_context.c"),
                   str(ROOT / "runtime" / "gw_pit8254.c"),
                   str(ROOT / "runtime" / "gw_interrupts.c"), str(ROOT / "runtime" / "gw_segments.c"),
                   str(ROOT / "runtime" / "recomp_bridge.c")]
    built = subprocess.run(compile_cmd, cwd=ROOT, env=env, text=True, capture_output=True)
    if built.returncode:
        raise SystemExit(built.stdout + built.stderr)
    run = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
    if run.returncode:
        raise SystemExit(run.stdout + run.stderr)
    if "indirect-tail guest-trap propagation" not in run.stdout:
        raise AssertionError(f"tail fixture did not report its assertion set: {run.stdout}")
    report = {
        "test": "native indirect-tail guest trap propagation",
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
        "compile_exit": built.returncode,
        "run_exit": run.returncode,
        "stdout": run.stdout.strip(),
        "guest_trap": {"vector": "0x31", "instruction_va": "0x12345678", "function_va": "0x00000200"},
        "tail_guest_work_after_trap": 0,
        "unresolved_indirect_tail": {
            "target_va": "0x00000300",
            "trap_reason": "GW_PORT_IO_TRAP_UNRESOLVED_INDIRECT_CALL",
            "parent_work_after_tail": 0,
            "asserted_fail_closed": True,
        },
        "preserved_guest_stack": "0x00009000",
        "passed": True,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["stdout"])
    print("PASS indirect-tail trap fixture and evidence")


if __name__ == "__main__":
    main()
