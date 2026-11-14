import os as _gw_os
from pathlib import Path as _GwPath
_GW_MSYS2=_gw_os.environ.get("MSYS2_ROOT",r"C:\msys64")
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "build" / "recomp_282.c"
TABLE = ROOT / "evidence" / "icall_dispatch_table.json"
TARGETS = {0x989E8, 0xBC129, 0xD71E0, 0xE0718, 0xE1730}


def run(command, env):
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(f"command failed ({result.returncode}): {command}\n{result.stdout}\n{result.stderr[-5000:]}")
    return result


def main():
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(ROOT / "build" / "tmp")
    env["PATH"] = (_GW_MSYS2 + '\\mingw32\\bin;' + _GW_MSYS2 + '\\usr\\bin;') + env.get("PATH", "")
    (ROOT / "build" / "tmp").mkdir(exist_ok=True)

    table = json.loads(TABLE.read_text(encoding="utf-8"))
    metrics = table["metrics"]
    source = SOURCE.read_text(encoding="utf-8")
    entries = {int(value, 16) for value in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]{8})u\)", source)}
    assert TARGETS <= entries, f"missing generated bodies: {sorted(TARGETS - entries)}"
    assert metrics["resolved_by_class"].get("not_lifted_in_range", 0) == 0
    assert metrics["resolved_by_class"].get("lifted", 0) >= 22
    # The ICALL analyzer counts emitted function definitions (including one
    # legacy body without a RECOMP_ENTER marker); the marker set is 1,566 VAs.
    assert metrics["lifted_functions_in_c"] == 1567 and len(entries) == 1566

    gcc = (_GW_MSYS2 + '\\mingw32\\bin\\gcc.exe')
    hdr = str(ROOT / "third_party" / "pcrecomp" / "runtime" / "recomp32")
    obj = ROOT / "build" / "recomp_282.o"
    link_obj = ROOT / "build" / "recomp_282_icall_linkcheck.o"
    run([gcc, "-m32", "-std=gnu99", "-Wno-implicit-function-declaration", f"-I{hdr}", f"-I{ROOT / 'build'}", "-c", str(SOURCE), "-o", str(obj)], env)
    run([gcc, "-m32", "-nostdlib", "-Wl,-r", str(obj), "-o", str(link_obj)], env)

    corpus_exe = ROOT / "build" / "test_icall_baseline_corpus.exe"
    corpus_test = ROOT / "tests" / "test_recomp_cfg_leaf_work3.c"
    run([gcc, "-std=gnu11", "-m32", "-O0", "-w", "-fcommon", "-I", str(ROOT / "runtime"), "-I", str(ROOT / "build"), "-I", hdr,
         "-o", str(corpus_exe), str(corpus_test), str(ROOT / "runtime" / "gw_segments.c"), str(ROOT / "runtime" / "recomp_x87.c")], env)
    corpus = run([str(corpus_exe)], env)
    match = re.search(r"COMPLETED (\d+) cases; divergences=(\d+)", corpus.stdout)
    assert match and (int(match.group(1)), int(match.group(2))) == (120, 0), corpus.stdout

    report = {
        "task": "L-ICALL-LIFT7",
        "target_sha256": hashlib.sha256((ROOT / "evidence" / "genewars-1_1.exe").read_bytes()).hexdigest(),
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "icall_table_sha256": hashlib.sha256(TABLE.read_bytes()).hexdigest(),
        "generated_function_bodies": len(entries),
        "new_icall_targets": [f"0x{x:08X}" for x in sorted(TARGETS)],
        "resolved_by_class": metrics["resolved_by_class"],
        "compile": {"exit": 0, "object_bytes": obj.stat().st_size},
        "relocatable_link": {"exit": 0, "object_bytes": link_obj.stat().st_size},
        "baseline_corpus": {"cases": int(match.group(1)), "divergences": int(match.group(2)), "stdout": corpus.stdout.strip()},
        "passed": True,
    }
    out = ROOT / "evidence" / "icall_lift_work1.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
