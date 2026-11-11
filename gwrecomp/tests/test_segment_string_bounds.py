"""Generate real lifted string operations and verify segment/range guards natively."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # noqa: E402
from tools.disasm.disasm32 import Instruction, BasicBlock, Function  # noqa: E402
from tools.lift.lift32 import Lifter  # noqa: E402

CASES = [
    ("movsb", "a4 c3", 0x14000000),
    ("rep_movsb", "f3 a4 c3", 0x14000010),
    ("std_rep_movsb", "fd f3 a4 c3", 0x14000020),
    ("rep_stosb", "f3 aa c3", 0x14000030),
    ("lodsb", "ac c3", 0x14000040),
    ("cmpsb", "a6 c3", 0x14000050),
    ("repe_cmpsb", "f3 a6 c3", 0x14000060),
    ("scasb", "ae c3", 0x14000070),
    ("repne_scasb", "f2 ae c3", 0x14000080),
    ("stosw", "66 ab c3", 0x14000090),
    ("lodsw", "66 ad c3", 0x140000A0),
    ("cmpsw", "66 a7 c3", 0x140000B0),
    ("scasw", "66 af c3", 0x140000C0),
    ("fs_movsb", "64 a4 c3", 0x140000D0),
]


def generate_lifts():
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    output = ["#define RECOMP_GENERATED_CODE", '#include "recomp_types.h"']
    for name, hex_bytes, va in CASES:
        raw = bytes.fromhex(hex_bytes)
        decoded = [Instruction(i.address, i.size, i.mnemonic, i.op_str, bytes(i.bytes), i.operands)
                   for i in md.disasm(raw, va)]
        assert b"".join(i.bytes for i in decoded) == raw, (name, decoded)
        block = BasicBlock(va, va + len(raw), decoded, is_exit=True)
        fn = Function(va, end=va + len(raw), name=name, blocks={va: block}, size=len(raw))
        output.append(Lifter().lift_function(fn))
    source = "\n".join(output) + "\n"
    assert "recomp_checked_segment_addr(RECOMP_SEG_ES" in source
    assert "recomp_checked_segment_addr(RECOMP_SEG_DS" in source
    (ROOT / "build" / "segment_string_lifts.c").write_text(source, encoding="utf-8")
    return source


def main():
    cache = ROOT / "cache"; cache.mkdir(exist_ok=True)
    source = generate_lifts()
    env = {**os.environ, "TEMP": str(cache), "TMP": str(cache), "TMPDIR": str(cache),
           "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    exe = ROOT / "build" / "test_segment_string_bounds.exe"
    command = [r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0", "-w",
               "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
               "-I", str(ROOT / "build"),
               "-o", str(exe), str(ROOT / "tests" / "test_segment_string_bounds.c"),
               str(ROOT / "runtime" / "gw_segments.c")]
    built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if built.returncode: raise SystemExit("compile failed:\n" + built.stdout + built.stderr)
    ran = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
    if ran.returncode: raise SystemExit(f"native test failed ({ran.returncode}):\n{ran.stdout}{ran.stderr}")
    target = ROOT / "evidence" / "genewars-1_1.exe"
    evidence = {
        "task": "W1-020", "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "lift_source_sha256": hashlib.sha256((ROOT / "third_party" / "pcrecomp" / "tools" / "lift" / "lift32.py").read_bytes()).hexdigest(),
        "cases": [{"name": n, "bytes": b, "va": f"0x{va:08X}"} for n,b,va in CASES],
        "generated_lift_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "compile_exit": built.returncode, "execution_exit": ran.returncode,
        "stdout": ran.stdout.strip(), "passed": True,
    }
    (ROOT / "evidence" / "segment_string_bounds.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(ran.stdout.strip())


if __name__ == "__main__": main()
