"""Build and run the native DOS vector service harness."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib
import json
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
EXE = BUILD / "test_native_dos_vectors.exe"
GCC = pathlib.Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
TARGET = ROOT / "evidence" / "genewars-1_1.exe"

def main():
    BUILD.mkdir(exist_ok=True)
    env = {**os.environ, "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
           "TMPDIR": str(ROOT / "cache"),
           "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
    command = [str(GCC), "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(EXE), str(ROOT / "tests" / "test_native_dos_vectors.c"),
        str(ROOT / "runtime" / "recomp_context.c"),
        str(ROOT / "runtime" / "gw_segments.c"),
        str(ROOT / "runtime" / "gw_interrupts.c"),
        str(ROOT / "runtime" / "gw_dos_services.c")]
    built = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if built.returncode:
        print(built.stdout, end=""); print(built.stderr, end=""); raise SystemExit(built.returncode)
    ran = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(ran.stdout, end=""); print(ran.stderr, end="")
    if ran.returncode: raise SystemExit(ran.returncode)
    result = {"test":"native DOS AH=35h/AH=25h vectors",
        "target_sha256":hashlib.sha256(TARGET.read_bytes()).hexdigest(),
        "compile_exit":built.returncode,"run_exit":ran.returncode,
        "output":ran.stdout.strip(),"passed":"PASS native DOS" in ran.stdout}
    (ROOT/"evidence"/"native_dos_vectors_work2.json").write_text(
        json.dumps(result,indent=2)+"\n",encoding="utf-8")
    if not result["passed"]: raise SystemExit("native DOS vector harness did not report PASS")

if __name__=="__main__": main()
