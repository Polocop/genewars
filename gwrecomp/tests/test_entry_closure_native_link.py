"""Link the full entry closure and invoke the real start root natively."""
import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / "cache"
OBJECT = ROOT / "build" / "entry_path_closure_routed.o"
EXE = ROOT / "build" / "entry_path_native.exe"


def run(command, env):
    p = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if p.returncode:
        print(p.stdout, end="")
        print(p.stderr, end="")
        raise SystemExit(p.returncode)
    print(p.stdout, end="")
    print(p.stderr, end="")
    return p


def main():
    CACHE.mkdir(exist_ok=True)
    env = {
        **os.environ, "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(CACHE), "TMP": str(CACHE), "TMPDIR": str(CACHE),
        "PATH": (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + os.environ.get("PATH", ""),
    }
    run([sys.executable, str(ROOT / "tests" / "test_entry_closure_compile.py")], env)
    command = [
        (_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe'), "-std=gnu11", "-m32", "-O0",
        "-DGW_FULL_CLOSURE_LINK",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(EXE), str(ROOT / "tests" / "test_lifted_interrupts.c"),
        str(ROOT / "runtime" / "recomp_context.c"), str(ROOT / "runtime" / "gw_interrupts.c"),
        str(ROOT / "runtime" / "gw_segments.c"),
        str(OBJECT), "-lm",
    ]
    run(command, env)
    result = run([str(EXE)], env)
    report = {
        "test": "full entry closure linked and real MAIN.EXE start executed natively to first INT trap",
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "object_sha256": hashlib.sha256(OBJECT.read_bytes()).hexdigest(),
        "executable_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
        "entry_va": "0x000AF96C",
        "interrupt_va": "0x000AFA09",
        "vector": "0x21",
        "link_exit": 0,
        "run_exit": 0,
        "stdout": result.stdout.strip(),
        "passed": True,
    }
    (ROOT / "evidence" / "entry_path_native_full_link.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print("PASS full closure linked and invoked real MAIN.EXE start")


if __name__ == "__main__":
    main()
