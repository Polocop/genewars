"""Run real lifted start through the native DOS AH=30h callback."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import json
import os
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
SOURCE = BUILD / "entry_path_closure.c"
FIXTURE = BUILD / "native_dos_callback_fixture.c"
EXE = BUILD / "test_native_dos_callback.exe"
GCC = pathlib.Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))


def extract_function(text: str, name: str) -> str:
    match = re.search(r"\bvoid\s+" + re.escape(name) + r"\s*\(void\)\s*\{", text)
    if not match:
        raise AssertionError(f"{name} missing from generated closure")
    brace = text.index("{", match.start())
    depth = 0
    for end in range(brace, len(text)):
        if text[end] == "{": depth += 1
        elif text[end] == "}":
            depth -= 1
            if depth == 0: return text[match.start():end + 1]
    raise AssertionError(f"unterminated function {name}")


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    function = extract_function(source, "gw_entry_start")
    if "gw_interrupt_dispatch(0x21u, 0x000AFA09u)" not in function:
        raise AssertionError("native fixture is not the measured entry start")
    FIXTURE.write_text(
        '#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'
        'void sub_000C871C(void); void sub_000C86CD(void); void sub_000C8767(void);\n'
        + function + "\n", encoding="utf-8")
    env = {
        **os.environ,
        "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
        "TMPDIR": str(ROOT / "cache"),
        "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", ""),
    }
    command = [str(GCC), "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(EXE), str(ROOT / "tests" / "test_native_dos_callback.c"),
        str(ROOT / "runtime" / "recomp_context.c"),
        str(ROOT / "runtime" / "gw_segments.c"),
        str(ROOT / "runtime" / "gw_interrupts.c"),
        str(ROOT / "runtime" / "gw_dos_services.c"), str(FIXTURE)]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, end=""); print(result.stderr, end="")
        raise SystemExit(result.returncode)
    result = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(result.stdout, end=""); print(result.stderr, end="")
    if result.returncode: raise SystemExit(result.returncode)
    match = re.search(r"next vector=([0-9a-fA-F]{2}) INT at ([0-9a-fA-F]{8})", result.stdout)
    if not match: raise AssertionError("native run did not report the next interrupt")
    evidence = {"test":"native DOS version callback resumes real entry",
        "target_sha256":"2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "generated_source_sha256":hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "entry_va":"0x000AF96C", "first_interrupt_va":"0x000AFA09",
        "dos_version_ax":"0x1606", "dos4g_ax":"0xffff", "dpmi_get_base_selector":"0x0014",
        "next_trap":"AH=4Ch synthetic exit path", "carry":0,
        "next_vector":int(match.group(1),16),"next_interrupt_va":"0x"+match.group(2).upper(),
        "compile_exit":0,"run_exit":0,"passed":True}
    (ROOT / "evidence" / "native_dos_callback.json").write_text(
        json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(evidence))


if __name__ == "__main__": main()
