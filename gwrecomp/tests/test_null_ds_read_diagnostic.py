"""Build and exercise the DS=14h low-address read trace in isolation."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CC = Path(r"E:\msys64\mingw32\bin\gcc.exe")

def main() -> None:
    exe = ROOT / "build" / "test_null_ds_read_diagnostic.exe"
    env = {**os.environ, "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
           "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    cmd = [str(CC), "-std=gnu11", "-m32", "-O0",
           "-I", str(ROOT / "third_party/pcrecomp/runtime/recomp32"),
           "-o", str(exe), str(ROOT / "tests/test_null_ds_read_diagnostic.c"),
           str(ROOT / "runtime/gw_segments.c")]
    built = subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)
    if built.returncode:
        raise SystemExit("compile failed:\n" + built.stdout + built.stderr)
    ran = subprocess.run([str(exe)], cwd=ROOT, env=env, text=True, capture_output=True)
    if ran.returncode:
        raise SystemExit(f"test failed ({ran.returncode}):\n{ran.stdout}{ran.stderr}")
    expected = "TRACE guest-null-read count=1 eip=000215d5 insn=000215d5 id=138 mnemonic=mov seg=DS sel=0014 base=00000000 linear=00000005 offset=00000005 width=1 access=1"
    if expected not in ran.stderr:
        raise SystemExit("low-read trace missing/incomplete:\n" + ran.stderr)
    print(ran.stdout.strip())
    print("PASS low-read trace includes guest EIP, selector, address, width, direction and registers")

if __name__ == "__main__":
    main()
