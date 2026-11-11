"""Lift and run GeneWars 1.1 LbMemorySetup_ in a bounded guest memory map."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
GCC = Path(r"E:\msys64\mingw32\bin\gcc.exe")
TARGET = ROOT / "evidence" / "genewars-1_1.exe"
TARGET_SHA = "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f"
REBASES = {1: 0x1EB000, 3: 0x1DA000}
ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
       "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}


def run(command: list[object], *, quiet: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run([str(x) for x in command], cwd=ROOT, env=ENV,
                            text=True, capture_output=True)
    if result.stdout and not quiet:
        print(result.stdout, end="")
    if result.stderr and not quiet:
        print(result.stderr, end="")
    if result.returncode:
        if quiet:
            if result.stdout: print(result.stdout, end="")
            if result.stderr: print(result.stderr, end="")
        raise SystemExit(result.returncode)
    return result


def main() -> None:
    target_hash = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if target_hash != TARGET_SHA:
        raise SystemExit(f"protected GeneWars 1.1 LE hash mismatch: {target_hash}")

    generated = ROOT / "work" / "memory_setup_closure.c"
    report_path = ROOT / "work" / "memory_setup_closure.json"
    run([PYTHON, "tools/lift_entry_path.py", "--object-map", "measured-1-3",
         "--partial-root", "0x921F0", "--stack-range", "0x3FD000:0x3000",
         "--dynamic-range", "0x2DA000:0xA8C50", "--output-c", generated,
         "--report", report_path], quiet=True)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report["partial_rejections"] or report["missing_or_unsupported"] or report["unresolved_direct_calls"]:
        raise SystemExit("LbMemorySetup_ partial closure is not complete")
    qsort_edges = [x for x in report["verified_indirect_targets"]
                   if x["provenance"] == "verified_heap_qsort_argument"]
    if len(qsort_edges) != 8 or any(x["link_target"] != "0x00092670" for x in qsort_edges):
        raise SystemExit("the exact qsort comparator target is not fully resolved")
    if any(x["linear_base_verified"] for x in report["object_map"] if x["index"] in (2, 4)):
        raise SystemExit("the partial memory proof must preserve unknown objects 2 and 4")
    lifted = {int(row["address"], 16) for row in report["lifted"]}
    if not {0x921F0, 0x92670, 0xA33C0, 0xADF95, 0xAE078}.issubset(lifted):
        raise SystemExit("original memory setup, comparator, allocator and expansion functions are missing")

    sys.path.insert(0, str(ROOT / "src"))
    from le_loader import load_le
    image = load_le(TARGET, object_rebases=REBASES)
    guest_image = ROOT / "work" / "memory_setup_guest.bin"
    guest_image.write_bytes(image.mem)
    executable = ROOT / "build" / "test_authentic_memory_setup.exe"
    run([GCC, "-std=gnu11", "-m32", "-O0", "-I", ROOT / "runtime",
         "-I", ROOT / "third_party/pcrecomp/runtime/recomp32", "-o", executable,
         ROOT / "tests/test_authentic_memory_setup.c", generated,
         ROOT / "runtime/recomp_context.c", ROOT / "runtime/gw_interrupts.c",
         ROOT / "runtime/gw_segments.c", ROOT / "runtime/gw_pit8254.c",
         ROOT / "runtime/gw_dos_services.c"])
    executed = run([executable, guest_image, hex(image.mem_base)])

    summary_line = next((line for line in executed.stdout.splitlines()
                         if line.startswith("MEMORY_SETUP_RESULT ")), "")
    if not summary_line:
        raise SystemExit("native harness omitted its allocator summary")
    fields = dict(item.split("=", 1) for item in summary_line.split()[1:])
    if int(fields["result"]) != 1 or int(fields["block_count"]) < 1 or int(fields["arena_count"]) != int(fields["block_count"]):
        raise SystemExit(f"original LbMemorySetup_ failed to construct bounded arenas: {fields}")

    evidence = {
        "schema": "gw-authentic-bounded-memory-setup/v1",
        "target_sha256": target_hash,
        "execution_mode": "original_recompiled_partial_closure",
        "natural_replay": False,
        "original_equivalence_claimed": False,
        "ghidra": {
            "provider": "REA 6.4.0 / Ghidra 12.1.4",
            "carrier_sha256": "1523022fb1febcfb939b2ed04145ee6e7dcd8b99113d932d21d33301c0052a97",
            "assembly_921f0": "ev_c18edf1ed916a5d0600b8ec326d243efaee76a9d141f9980ae91f0da99b15395",
            "qsort_assembly": "ev_3f1a2cdccd1c957ba8adce22ff8600d1bdc53c7dffdefb12bb9dca938e191c70",
            "qsort_callers": "ev_a6fae3b8494a3593eed2c757791be3dc04fd868292fe7621847fcf54f5180be0",
        },
        "layout": {
            "mem_block_size": 12, "mem_block_table_link": "0x186C40",
            "mem_arena_size": 18, "mem_arena_table_link": "0x187840",
            "entries": 256, "memory_initialized_guard_link": "0x186C48",
            "comparison": "Capstone instructions from exact 1.1 LE agree with REA listing; table stride, capacity and guard are byte-addressed",
        },
        "qsort_callback": {"target_link": "0x92670", "callsite_count": len(qsort_edges),
                           "provenance": "original caller setup and exact helper argument forwarding"},
        "guest_memory_experiment": {
            "profile": "experimental DOS/4GW flat backing, bounded to 0x03002000 bytes",
            "cause": "original __brk_ requests up to 0x03001000; the next growth attempt receives the DOS insufficient-memory result",
            "flat_heap_begin": fields["flat_heap_begin"],
            "provider": "opt-in gw_dos_services DOS/4GW AH=ED/AH=4A contract; AH=4A rejects growth past backing",
            "dpmi_ax0501_calls": int(fields["dpmi0501"]),
            "lifetime": "one isolated test process",
        },
        "execution": {"summary": fields, "stdout": executed.stdout.strip(),
                      "generated_c_sha256": hashlib.sha256(generated.read_bytes()).hexdigest(),
                      "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()},
        "passed": True,
    }
    (ROOT / "evidence" / "authentic_bounded_memory_setup.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("evidence: evidence/authentic_bounded_memory_setup.json")


if __name__ == "__main__":
    main()
