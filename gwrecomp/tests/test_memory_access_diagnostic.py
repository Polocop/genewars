"""Focused native and lifter checks for opt-in guest memory diagnostics."""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # noqa: E402
from tools.disasm.disasm32 import Instruction, BasicBlock, Function  # noqa: E402
from tools.lift.lift32 import Lifter  # noqa: E402


def lift(raw, address):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    decoded = [Instruction(i.address, i.size, i.mnemonic, i.op_str,
                           bytes(i.bytes), i.operands, i.id)
               for i in md.disasm(raw, address)]
    block = BasicBlock(address, address + len(raw), decoded, is_exit=True)
    fn = Function(address, end=address + len(raw), name="diag_probe",
                  blocks={address: block}, size=len(raw))
    return Lifter().lift_function(fn)


def main():
    read_lift = lift(bytes.fromhex("8b 03 c3"), 0x12340000)
    assert "recomp_begin_memory_access_ex(RECOMP_SEG_DS, 4u, 0x12340000u, RECOMP_MEM_ACCESS_READ, 460u, \"mov\")" in read_lift
    assert read_lift.index("gw_recomp_guest_instruction") < read_lift.index("recomp_begin_memory_access_ex")
    assert "recomp_begin_memory_access_ex(RECOMP_SEG_SS, 4u, 0x12340002u, RECOMP_MEM_ACCESS_READ, 633u, \"ret\")" in read_lift
    ret_lift = lift(bytes.fromhex("c3"), 0x12341000)
    assert "recomp_begin_memory_access_ex(RECOMP_SEG_SS, 4u, 0x12341000u, RECOMP_MEM_ACCESS_READ, 633u, \"ret\")" in ret_lift

    header = (ROOT / "third_party/pcrecomp/runtime/recomp32/recomp_types.h").read_text()
    assert "recomp_checked_mem_addr((uint32_t)(addr),4u)" in header
    harness = (ROOT / "tests/test_native_guest_image.c").read_text()
    assert "native_print_memory_diagnostic(stderr,\"unexpected_host_exception\")" in harness

    env = {**os.environ,
           "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
           "TMPDIR": str(ROOT / "cache"),
           "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    exe = ROOT / "build/test_memory_access_diagnostic.exe"
    command = [r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0",
               "-I", str(ROOT / "third_party/pcrecomp/runtime/recomp32"),
               "-o", str(exe), str(ROOT / "tests/test_memory_access_diagnostic.c"),
               str(ROOT / "runtime/gw_segments.c")]
    built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if built.returncode:
        raise SystemExit("diagnostic harness compile failed:\n" + built.stdout + built.stderr)
    ran = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
    if ran.returncode:
        raise SystemExit(f"diagnostic harness failed ({ran.returncode}):\n{ran.stdout}{ran.stderr}")
    print(ran.stdout.strip())
    print("PASS lifter metadata and unexpected-host-exception evidence path")


if __name__ == "__main__":
    main()
