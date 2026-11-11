"""Synthetic check for the opt-in function-entry counter (runtime/gw_func_coverage.c).

No GeneWars binary, snapshot, or replay is used. A tiny driver calls the counter with known
multiplicities and the prelude macro, once with GWRECOMP_FUNC_COVERAGE=1 and once without.
Passes when the JSON schema, counts, sort order and integrity flags are as expected, and when
the disabled run writes nothing and prints no summary line.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLANG = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang.exe")

DRIVER = r"""
#include <stdint.h>
#include <stdio.h>
#include "gw_func_coverage.h"
int main(void) {
    /* 3x VA 0x2000, 1x VA 0x1000, 2x VA 0x3000 and one colliding-probe pattern. */
    for (int i = 0; i < 3; i++) gw_func_coverage_count(0x00002000u);
    gw_func_coverage_count(0x00001000u);
    for (int i = 0; i < 2; i++) gw_func_coverage_count(0x00003000u);
    for (uint32_t va = 0x00010000u; va < 0x00010000u + 300u; va++) gw_func_coverage_count(va);
    return 0;
}
"""


def build_driver(workdir: Path) -> Path:
    src = workdir / "driver.c"
    src.write_text(DRIVER, encoding="ascii")
    exe = workdir / "driver.exe"
    cmd = [str(CLANG), "-m32", "-std=gnu11", "-O0", "-I", str(ROOT / "runtime"),
           str(src), str(ROOT / "runtime" / "gw_func_coverage.c"), "-o", str(exe)]
    subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    return exe


def run(exe: Path, out: Path, enabled: bool) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("GWRECOMP_FUNC_COVERAGE", None)
    env.pop("GWRECOMP_FUNC_COVERAGE_OUT", None)
    if enabled:
        env["GWRECOMP_FUNC_COVERAGE"] = "1"
        env["GWRECOMP_FUNC_COVERAGE_OUT"] = str(out)
    return subprocess.run([str(exe)], env=env, capture_output=True, text=True, timeout=120)


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="gwfc_") as tmp:
        workdir = Path(tmp)
        exe = build_driver(workdir)

        out_on = workdir / "on.json"
        res_on = run(exe, out_on, enabled=True)
        if res_on.returncode != 0:
            failures.append(f"enabled run exited {res_on.returncode}")
        if "TRACE func_coverage_summary enabled=1" not in res_on.stderr:
            failures.append("enabled run printed no func_coverage_summary line")
        data = json.loads(out_on.read_text(encoding="utf-8"))
        expected_total = 3 + 1 + 2 + 300
        if data.get("schema") != "gw-function-coverage/v1":
            failures.append(f"schema={data.get('schema')!r}")
        if data.get("total_entries") != expected_total:
            failures.append(f"total_entries={data.get('total_entries')} expected {expected_total}")
        if data.get("distinct_functions") != 1 + 1 + 1 + 300 + 0:
            # 0x2000, 0x1000, 0x3000 plus 300 consecutive VAs from 0x10000.
            failures.append(f"distinct_functions={data.get('distinct_functions')}")
        if data.get("overflow_entries") != 0:
            failures.append(f"overflow_entries={data.get('overflow_entries')}")
        entered = data.get("entered", [])
        counts = {int(e["va"], 16): e["count"] for e in entered}
        if counts.get(0x2000) != 3 or counts.get(0x1000) != 1 or counts.get(0x3000) != 2:
            failures.append(f"known counts wrong: {counts.get(0x1000)}, {counts.get(0x2000)}, {counts.get(0x3000)}")
        vas = [int(e["va"], 16) for e in entered]
        if vas != sorted(vas):
            failures.append("entered is not sorted by VA")
        integrity = data.get("integrity", {})
        if integrity.get("simulation_logic_modified") is not False or integrity.get("memory_forced") is not False:
            failures.append(f"integrity flags wrong: {integrity}")

        out_off = workdir / "off.json"
        res_off = run(exe, out_off, enabled=False)
        if res_off.returncode != 0:
            failures.append(f"disabled run exited {res_off.returncode}")
        if out_off.exists():
            failures.append("disabled run wrote a coverage file")
        if "func_coverage_summary" in res_off.stderr:
            failures.append("disabled run printed a summary line")

    if failures:
        for line in failures:
            print(f"FAIL {line}", file=sys.stderr)
        return 1
    print("PASS gw_func_coverage synthetic counter: counts, JSON schema, sort order, integrity, off-by-default")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
