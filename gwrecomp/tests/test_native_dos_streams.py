"""Build and run the bounded native DOS stdio callback harness."""
import hashlib
import json
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
EXE = BUILD / "test_native_dos_streams.exe"
GCC = pathlib.Path(r"E:\msys64\mingw32\bin\gcc.exe")
TARGET = ROOT / "evidence" / "genewars-1_1.exe"

def main():
    BUILD.mkdir(exist_ok=True)
    env = {**os.environ, "TEMP": str(ROOT / "cache"), "TMP": str(ROOT / "cache"),
           "TMPDIR": str(ROOT / "cache"),
           "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}
    command = [str(GCC), "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(EXE), str(ROOT / "tests" / "test_native_dos_streams.c"),
        str(ROOT / "runtime" / "recomp_context.c"),
        str(ROOT / "runtime" / "gw_pit8254.c"),
        str(ROOT / "runtime" / "gw_segments.c"),
        str(ROOT / "runtime" / "gw_interrupts.c"),
        str(ROOT / "runtime" / "gw_dos_services.c")]
    compiled = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if compiled.returncode:
        print(compiled.stdout, end=""); print(compiled.stderr, end="")
        raise SystemExit(compiled.returncode)
    ran = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(ran.stdout, end=""); print(ran.stderr, end="")
    if ran.returncode:
        raise SystemExit(ran.returncode)
    result = {"test": "native DOS AH=3Fh/40h injected standard streams",
        "target_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
        "compile_exit": compiled.returncode, "run_exit": ran.returncode,
        "output": ran.stdout.strip(), "passed": "PASS native DOS" in ran.stdout}
    (ROOT / "evidence" / "native_dos_streams_work2.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if not result["passed"]:
        raise SystemExit("native DOS stream harness did not report PASS")

if __name__ == "__main__":
    main()
