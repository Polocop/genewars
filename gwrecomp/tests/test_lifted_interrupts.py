"""Compile and execute the real LE entry stub through its first DOS INT."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
CACHE = ROOT / "cache"
SOURCE = BUILD / "entry_path_closure.c"
FIXTURE = BUILD / "lifted_start_interrupt_fixture.c"
EXE = BUILD / "test_lifted_interrupts.exe"


def extract_function(text: str, name: str) -> str:
    match = re.search(r"\bvoid\s+" + re.escape(name) + r"\s*\(void\)\s*\{", text)
    if not match:
        raise AssertionError(f"{name} missing from generated entry closure")
    start = match.start()
    brace = text.index("{", match.start())
    depth = 0
    for end in range(brace, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if depth == 0:
                return text[start:end + 1]
    raise AssertionError(f"unterminated generated function {name}")


def main() -> None:
    CACHE.mkdir(exist_ok=True)
    for helper in ("refresh_entry_start.py", "route_lifted_interrupts.py"):
        step = subprocess.run(
            [sys.executable, str(ROOT / "tools" / helper)],
            cwd=ROOT, text=True, capture_output=True,
        )
        if step.returncode:
            print(step.stdout, end="")
            print(step.stderr, end="")
            raise SystemExit(step.returncode)
    source = SOURCE.read_text(encoding="utf-8")
    function = extract_function(source, "gw_entry_start")
    expected = "gw_interrupt_dispatch(0x21u, 0x000AFA09u)"
    if expected not in function:
        raise AssertionError("real start function does not trap at its first INT 21h")
    if "UNIMPLEMENTED: int" in function:
        raise AssertionError("real start still contains a no-op INT instruction")
    if "UNIMPLEMENTED: int" in source:
        raise AssertionError("entry closure still contains an INT no-op")
    FIXTURE.write_text(
        '#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'
        'void sub_000C871C(void); void sub_000C86CD(void); void sub_000C8767(void);\n'
        + function + "\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "TEMP": str(CACHE), "TMP": str(CACHE), "TMPDIR": str(CACHE),
        "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
    }
    command = [
        r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        "-o", str(EXE), str(ROOT / "tests" / "test_lifted_interrupts.c"),
        str(ROOT / "runtime" / "recomp_context.c"),
        str(ROOT / "runtime" / "gw_interrupts.c"), str(ROOT / "runtime" / "gw_segments.c"), str(FIXTURE),
    ]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="")
        raise SystemExit(result.returncode)
    result = subprocess.run([str(EXE)], cwd=ROOT, env=env, text=True, capture_output=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
    if result.returncode:
        raise SystemExit(result.returncode)
    evidence = {
        "test": "real MAIN.EXE start lifted and executed to first unhandled DOS interrupt",
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "generated_source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "entry_va": "0x000AF96C",
        "interrupt_va": "0x000AFA09",
        "vector": "0x21",
        "compile_exit": 0,
        "run_exit": 0,
        "passed": True,
    }
    (ROOT / "evidence" / "lifted_interrupt_entry.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print("PASS real gw_entry_start -> DOS INT 21h trap at 0x000AFA09")


if __name__ == "__main__":
    main()
