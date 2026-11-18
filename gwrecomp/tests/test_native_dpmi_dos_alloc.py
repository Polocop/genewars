import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import os, pathlib, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
GCC = pathlib.Path((_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'))
EXE = ROOT / "build" / "test_native_dpmi_dos_alloc.exe"
ENV = {**os.environ, "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
       "TMPDIR": str(ROOT / "cache"),
       "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", "")}
COMMAND = [str(GCC), "-std=gnu11", "-m32", "-O0", "-I", str(ROOT / "runtime"),
           "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
           "-o", str(EXE), str(ROOT / "tests" / "test_native_dpmi_dos_alloc.c"),
           str(ROOT / "runtime" / "gw_segments.c"),
           str(ROOT / "runtime" / "gw_interrupts.c"),
           str(ROOT / "runtime" / "gw_dos_services.c")]
compiled = subprocess.run(COMMAND, cwd=ROOT, env=ENV, text=True, capture_output=True)
print(compiled.stdout, end=""); print(compiled.stderr, end="")
if compiled.returncode: raise SystemExit(compiled.returncode)
ran = subprocess.run([str(EXE)], cwd=ROOT, env=ENV, text=True, capture_output=True)
print(ran.stdout, end=""); print(ran.stderr, end="")
raise SystemExit(ran.returncode)
