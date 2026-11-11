"""Verify emitted memory access guards and their native x86-32 contract."""
import os
import pathlib
import hashlib
import json
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # noqa: E402
from tools.disasm.disasm32 import Instruction, BasicBlock, Function  # noqa: E402
from tools.lift.lift32 import Lifter  # noqa: E402


def verify_lifter_guard():
    raw = bytes.fromhex("8b 03 c3")  # mov eax,[ebx]; ret
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    decoded = [Instruction(i.address, i.size, i.mnemonic, i.op_str, bytes(i.bytes), i.operands)
               for i in md.disasm(raw, 0x12340000)]
    block = BasicBlock(0x12340000, 0x12340003, decoded, is_exit=True)
    function = Function(0x12340000, end=0x12340003, name="bounds_probe",
                        blocks={0x12340000: block}, size=3)
    lifted = Lifter().lift_function(function)
    assert "recomp_begin_memory_access_ex(RECOMP_SEG_DS, 4u, 0x12340000u" in lifted
    assert "recomp_memory_fault_pending()" in lifted
    assert "recomp_end_memory_access()" in lifted


def main():
    verify_lifter_guard()
    cache = ROOT / "cache"; cache.mkdir(exist_ok=True)
    env = {**os.environ, "TEMP": str(cache), "TMP": str(cache), "TMPDIR": str(cache),
           "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    exe = ROOT / "build" / "test_segment_access_bounds.exe"
    command = [r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0",
               "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
               "-o", str(exe), str(ROOT / "tests" / "test_segment_access_bounds.c"),
               str(ROOT / "runtime" / "gw_segments.c")]
    built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if built.returncode:
        raise SystemExit("compile failed:\n" + built.stdout + built.stderr)
    ran = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
    if ran.returncode:
        raise SystemExit(f"native test failed ({ran.returncode}):\n{ran.stdout}{ran.stderr}")
    target = ROOT / "evidence" / "genewars-1_1.exe"
    evidence = {
        "task": "W1-019",
        "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "lift_source_sha256": hashlib.sha256((ROOT / "third_party" / "pcrecomp" / "tools" / "lift" / "lift32.py").read_bytes()).hexdigest(),
        "generated_memory_op": {"bytes": "8b03", "instruction_va": "0x12340000", "segment": "DS", "width": 4, "guard_emitted": True},
        "native_cases": ["in-range write", "descriptor boundary crossing", "mapped-region boundary crossing", "null selector load accepted", "null-selector access fault"],
        "fault_fields": ["segment", "selector", "offset", "width", "linear", "instruction_va"],
        "compile_exit": built.returncode,
        "execution_exit": ran.returncode,
        "stdout": ran.stdout.strip(),
        "passed": True,
    }
    (ROOT / "evidence" / "segment_access_bounds.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(ran.stdout.strip())


if __name__ == "__main__":
    main()
