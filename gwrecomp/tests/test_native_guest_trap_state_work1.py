"""Check all GPR and lazy-flag state in the direct, indirect, and tail trap fixture."""
import hashlib
import json
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
GCC = r"E:\msys64\mingw32\bin\gcc.exe"
SOURCE = ROOT / "tests" / "test_native_guest_trap_wrappers.c"
EXE = ROOT / "build" / "test_native_guest_trap_wrappers.exe"
OUT = ROOT / "evidence" / "native_guest_trap_state_work1.json"


def main():
    env = {**os.environ, "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    command = [GCC, "-std=gnu11", "-m32", "-O0", "-I", str(ROOT / "runtime"),
               "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
               "-o", str(EXE), str(SOURCE), str(ROOT / "runtime" / "recomp_context.c"),
               str(ROOT / "runtime" / "gw_interrupts.c"), str(ROOT / "runtime" / "gw_segments.c"),
               str(ROOT / "runtime" / "recomp_bridge.c")]
    built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if built.returncode:
        raise SystemExit(built.stdout + built.stderr)
    run = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
    if run.returncode:
        raise SystemExit(run.stdout + run.stderr)
    report = {
        "test": "complete CPU-state preservation at nested guest trap boundaries",
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
        "compile_exit": built.returncode,
        "run_exit": run.returncode,
        "stdout": run.stdout.strip(),
        "paths": ["direct", "indirect", "stack_indirect_esp_plus_4", "conditional_indirect_tail"],
        "seed_registers": {"eax": "0x11111111", "ebx": "0x22222222", "ecx": "0x33333333", "edx": "0x44444444", "esi": "0x55555555", "edi": "0x66666666", "ebp": "0x77777777", "esp": "0x00009000"},
        "child_modified_registers": {"eax": "0xC0DE1234", "ebx": "0xB16B00B5", "esi": "0x51515151", "edi": "0xD1D1D1D1"},
        "preserved_registers": ["ecx", "edx", "ebp"],
        "lazy_flags": {"flag_k": "FK_TEST", "flag_a": "0x89ABCDEF", "flag_b": "0x76543210", "carry": 1},
        "passed": True,
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["stdout"])
    print("PASS all GPR, ESP, and lazy flag assertions across nested trap paths")


if __name__ == "__main__":
    main()
