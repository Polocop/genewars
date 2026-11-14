"""Compile the focused link-VA/guest-linear indirect-call regression."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GCC = Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
EXE = ROOT / "build" / "test_rebased_guest_icall_dispatch.exe"

def main():
    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le
    target = ROOT / "evidence" / "genewars-1_1.exe"
    image = load_le(target, object_rebases={1: 0x1EB000, 3: 0x1DA000})
    for slot, link_target in ((0x10A804, 0x989E8),
                              (0x10AA1C, 0x98C18), (0x10AA20, 0x98C18)):
        linear_slot = image.link_to_linear(slot)
        loaded_target = int.from_bytes(image.mem[linear_slot-image.mem_base:
                                                  linear_slot-image.mem_base+4], "little")
        expected = image.link_to_linear(link_target)
        if loaded_target != expected:
            raise SystemExit(f"LE-fixup callback mismatch slot=0x{slot:08X}: "
                             f"0x{loaded_target:08X} != 0x{expected:08X}")
    if (image.link_to_linear(0x91E90), image.link_to_linear(0x91E00)) != (0x27CE90, 0x27CE00):
        raise SystemExit("stack callback fixup target map changed")
    print("PASS canonical LE callback slots and stack callback targets match verified object deltas")
    env = {**os.environ,
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [str(GCC), "-std=gnu11", "-m32", "-O0",
               "-I", str(ROOT / "runtime"),
               "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
               "-o", str(EXE),
               str(ROOT / "tests" / "test_native_guest_trap_wrappers.c"),
               str(ROOT / "runtime" / "recomp_context.c"),
               str(ROOT / "runtime" / "gw_interrupts.c"),
               str(ROOT / "runtime" / "gw_segments.c"),
               str(ROOT / "runtime" / "gw_pit8254.c"),
               str(ROOT / "runtime" / "recomp_bridge.c")]
    for command_line in (command, [str(EXE)]):
        result = subprocess.run(command_line, cwd=ROOT, env=env, text=True, capture_output=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        if result.returncode:
            raise SystemExit(result.returncode)

    generator = [str(ROOT / ".venv" / "Scripts" / "python.exe"),
                 str(ROOT / "tools" / "lift_entry_path.py"),
                 "--object-map", "measured-1-3", "--partial-root", "0x989E8",
                 "--partial-root", "0x98C18", "--stack-range", "0x3FE000:0x2000",
                 "--output-c", str(ROOT / "build" / "resource_callback_stubs.c"),
                 "--report", str(ROOT / "evidence" / "resource_callback_stubs_lifts.json")]
    result = subprocess.run(generator, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, end=""); print(result.stderr, end="")
        raise SystemExit(result.returncode)
    closure = ROOT / "build" / "resource_callback_stubs.c"
    harness = ROOT / "tests" / "test_authentic_resource_callback_dispatch.c"
    callback_exe = ROOT / "build" / "test_authentic_resource_callback_dispatch.exe"
    callback_command = [str(GCC), "-std=gnu11", "-m32", "-O0",
                        "-I", str(ROOT / "runtime"),
                        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
                        "-o", str(callback_exe), str(harness), str(closure),
                        str(ROOT / "runtime" / "recomp_context.c"),
                        str(ROOT / "runtime" / "gw_interrupts.c"),
                        str(ROOT / "runtime" / "gw_segments.c"),
                        str(ROOT / "runtime" / "gw_pit8254.c"),
                        str(ROOT / "runtime" / "recomp_bridge.c")]
    callback_output = ""
    for command_line in (callback_command, [str(callback_exe)]):
        result = subprocess.run(command_line, cwd=ROOT, env=env, text=True, capture_output=True)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        if result.returncode:
            raise SystemExit(result.returncode)
        if command_line == [str(callback_exe)]:
            callback_output = result.stdout.strip()
    receipt = {
        "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "execution_mode": "bounded_partial_original_code_callback_dispatch",
        "natural_replay": False,
        "setup_game_or_resource_manager_executed": False,
        "functions_executed": [
            {"link_va": "0x000989E8", "guest_linear": "0x002839E8", "bytes": "c3",
             "role": "verified LE-fixed resource callback stub"},
            {"link_va": "0x00098C18", "guest_linear": "0x00283C18", "bytes": "c3",
             "role": "verified LE-fixed resource callback stub"}],
        "dispatcher": "RECOMP_ICALL maps only the verified object-1 guest-linear range back to link-space keys",
        "ghidra": {"provider": "REA 6.4.0 / Ghidra 12.1.4",
                   "carrier_sha256": "1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
                   "FUN_000989EC_evidence": "ev_ee2750127b20331b0431ae27a3fb771d80bc8d73ae708428f65d7186bf4d02cf",
                   "FUN_000AF9E4_evidence": "ev_2b0c8678d18c3d69b60d3f83e1d7a16d9006b9864db9f90825c04bdceb05912c"},
        "callback_closure_sha256": hashlib.sha256(closure.read_bytes()).hexdigest(),
        "test_executable_sha256": hashlib.sha256(callback_exe.read_bytes()).hexdigest(),
        "test_output": callback_output,
        "passed": True,
        "limitations": ["Does not initialize or execute FUN_00070D10; its resource object/table must be built by the authentic setup path.",
                        "Original DOSBox capture was not run because verify_oracle_sandbox.ps1 reported VHDX is not attached.",
                        "The saved DS word is copied from DS by FUN_000AF9E4; this turn did not capture that runtime value at FUN_000AFC38."]}
    (ROOT / "evidence" / "resource_callback_dispatch_rebased.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
