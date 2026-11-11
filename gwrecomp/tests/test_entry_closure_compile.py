"""Regenerate/route the entry closure, then compile its complete x86-32 unit."""
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
OBJECT = BUILD / "entry_path_closure_routed.o"


def run(command, env):
    p = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    if p.returncode:
        print(p.stdout, end="")
        print(p.stderr, end="")
        raise SystemExit(p.returncode)
    return p


def main():
    CACHE.mkdir(exist_ok=True)
    task_temp = pathlib.Path(os.environ.get("GW_TASK_TEMP", str(CACHE)))
    task_temp.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TEMP": str(task_temp), "TMP": str(task_temp), "TMPDIR": str(task_temp),
        "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", ""),
        "PYTHONPATH": str(ROOT / "third_party" / "python") + os.pathsep + os.environ.get("PYTHONPATH", ""),
    }
    for helper in ("refresh_entry_start.py", "route_lifted_interrupts.py"):
        run([sys.executable, str(ROOT / "tools" / helper)], env)
    source = SOURCE.read_text(encoding="utf-8")
    port_callbacks_present = ("gw_recomp_port_io(" in source or
                              "gw_recomp_guest_instruction(" in source)
    runtime_header = '#include "recomp_context.h"'
    if port_callbacks_present and runtime_header not in source:
        if '#include "recomp_types.h"' not in source:
            raise AssertionError("generated callback closure lacks the recomp type header insertion point")
        source = source.replace(
            '#include "recomp_types.h"',
            '#include "recomp_types.h"\n' + runtime_header,
            1,
        )
        SOURCE.write_text(source, encoding="utf-8")
    function_count = len(re.findall(r"\bvoid\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{", source))
    if function_count < 1000:
        raise AssertionError(f"entry closure unexpectedly small: {function_count} functions")
    if "UNIMPLEMENTED: int" in source:
        raise AssertionError("entry closure contains an unhandled INT no-op")
    command = [
        r"E:\msys64\mingw32\bin\gcc.exe", "-std=gnu11", "-m32", "-O0", "-c",
        "-I", str(ROOT / "runtime"),
        "-I", str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32"),
        str(SOURCE), "-o", str(OBJECT),
    ]
    run(command, env)
    nm = subprocess.run(
        [r"E:\msys64\mingw32\bin\nm.exe", "-u", str(OBJECT)],
        cwd=ROOT, env=env, text=True, capture_output=True,
    )
    if nm.returncode:
        print(nm.stderr, end="")
        raise SystemExit(nm.returncode)
    undefined = [line.strip() for line in nm.stdout.splitlines() if line.strip()]
    if not any("gw_interrupt_dispatch" in line for line in undefined):
        raise AssertionError("object has no host INT callback relocation")
    report = {
        "test": "full entry-rooted 1111-function closure compiles as x86-32",
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "object_sha256": hashlib.sha256(OBJECT.read_bytes()).hexdigest(),
        "object_bytes": OBJECT.stat().st_size,
        "function_definitions": function_count,
        "routed_int_callbacks": len(re.findall(r"gw_interrupt_dispatch\(0x", source)),
        "runtime_header_added_for_port_io": port_callbacks_present,
        "undefined_symbols": undefined,
        "compile_exit": 0,
        "passed": True,
    }
    evidence_name = os.environ.get(
        "GW_ENTRY_PATH_COMPILE_EVIDENCE_NAME",
        "entry_path_closure_routed_compile.json",
    )
    if pathlib.Path(evidence_name).name != evidence_name or not evidence_name.endswith(".json"):
        raise SystemExit("invalid entry closure compile evidence filename")
    (ROOT / "evidence" / evidence_name).write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(f"PASS full x86-32 entry closure: {function_count} function bodies, {report['routed_int_callbacks']} INT callbacks")


if __name__ == "__main__":
    main()
