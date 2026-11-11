"""Generate and execute a bounded authentic GeneWars 1.1 graphics helper."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
GCC = Path(r"E:\msys64\mingw32\bin\gcc.exe")
TARGET = ROOT / "evidence" / "genewars-1_1.exe"
ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(ROOT / "cache"),
       "TMP": str(ROOT / "cache"), "TMPDIR": str(ROOT / "cache"),
       "PATH": r"E:\msys64\mingw32\bin;E:\msys64\usr\bin;" + os.environ.get("PATH", "")}


def run(cmd, expect=0):
    result = subprocess.run([str(x) for x in cmd], cwd=ROOT, env=ENV, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    if result.returncode != expect:
        raise SystemExit(f"command exit {result.returncode}, expected {expect}: {cmd}")
    return result


def main():
    run([PYTHON, "tools/lift_entry_path.py", "--object-map", "measured-1-3",
         "--partial-root", "0x96338", "--stack-range", "0x3FE000:0x2000"])
    report_path = ROOT / "evidence" / "partial_entry_path_lifts.json"
    report = json.loads(report_path.read_text())
    lift = next(row for row in report["lifted"] if row["address"] == "0x00096338")
    if lift["end"] != "0x000963E0" or lift["instructions"] != 65 or lift["calls_to"]:
        raise SystemExit(f"unexpected recovered function extent/dependencies: {lift}")
    if report["object_map"][1]["linear_base_verified"] or report["object_map"][3]["linear_base_verified"]:
        raise SystemExit("partial proof must leave LE objects 2 and 4 unresolved")

    # Cross-check the original link-space instruction stream against REA/Ghidra.
    sys.path[:0] = [str(ROOT / "src"), str(ROOT / "third_party" / "pcrecomp")]
    from le_loader import load_le
    from tools.disasm.disasm32 import Disassembler
    from tools.pe.pe_analyze import Section
    link_image = load_le(TARGET)
    obj = link_image.objects[0]
    capstone_fn = Disassembler(bytes(link_image.object_data(1)), 0,
                               [Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)]).disassemble_function(0x96338)
    rea = json.loads((ROOT / "evidence" / "rea_partial_graphics_instructions.json").read_text())
    def norm(text):
        text = re.sub(r"\b(?:byte|word|dword|qword) ptr\b", "", text.lower())
        text = re.sub(r"0x[0-9a-f]+", lambda m: hex(int(m.group(0), 16)), text)
        text = re.sub(r"(?<![a-z0-9_])\d+(?![a-z0-9_])", lambda m: hex(int(m.group(0), 10)), text)
        return re.sub(r"\s+", "", text)
    capstone_rows = [(f"0x{i.address:x}", i.mnemonic.lower(), norm(i.op_str))
                     for b in capstone_fn.blocks.values() for i in b.instructions]
    rea_rows = []
    for line in rea["instructions"]:
        match = re.fullmatch(r"(0x[0-9a-fA-F]+):\s*([A-Za-z0-9]+)\s*(.*)", line)
        if not match:
            raise SystemExit(f"unparsed REA instruction: {line}")
        rea_rows.append((hex(int(match.group(1), 16)), match.group(2).lower(), norm(match.group(3))))
    if capstone_rows != rea_rows:
        for index, (left, right) in enumerate(zip(capstone_rows, rea_rows)):
            if left != right:
                raise SystemExit(f"REA/Capstone mismatch at instruction {index}: {left} != {right}")
        raise SystemExit(f"REA/Capstone instruction count differs: {len(rea_rows)} != {len(capstone_rows)}")

    # The other link-space executable object is deliberately not accepted as guest code.
    rejected = run([PYTHON, "tools/lift_entry_path.py", "--object-map", "measured-1-3",
                    "--partial-root", "0xF0000", "--stack-range", "0x3FE000:0x2000"], expect=1)
    if "outside verified executable" not in rejected.stderr:
        raise SystemExit("unverified-object root rejection did not explain its cause")
    full_guard = run([PYTHON, "tools/lift_entry_path.py", "--object-map", "measured-1-3"], expect=1)
    if "incomplete runtime map" not in full_guard.stderr:
        raise SystemExit("full-closure guard did not retain the unknown-object block")

    exe = ROOT / "build" / "test_partial_graphics_lift.exe"
    run([GCC, "-std=gnu11", "-m32", "-O0", "-I", ROOT / "runtime",
         "-I", ROOT / "third_party/pcrecomp/runtime/recomp32", "-o", exe,
         ROOT / "tests/test_partial_graphics_lift.c", ROOT / "build/partial_entry_path.c",
         ROOT / "runtime/recomp_context.c", ROOT / "runtime/gw_interrupts.c",
         ROOT / "runtime/gw_segments.c", ROOT / "runtime/gw_pit8254.c"])
    run([exe])

    evidence = {
        "execution_mode": "bounded_partial_authentic_lift",
        "natural_replay": False,
        "synthetic_fixture_state": True,
        "target_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
        "function": "LbScreenSetGraphicsWindow_",
        "link_range": ["0x00096338", "0x000963E0"],
        "ghidra_evidence": {
            "function_info": "ev_8fb9753bf829cfb2dc199e11cfac5e9784332350dc7bcaac770498cc9aba61e9",
            "assembly": "ev_bf4c3ec4c9edd92f15155f8f35455cff3126889d4e8d0e16496d9a41",
            "pseudo_code": "ev_26f1196896124cb89e8982ff5837069b86537d07f4a5a3af2e25eaa7a412c469",
            "outgoing_references": "ev_4d96528f29db7f564398406ed318c10db896c5afa723e35890e64f05c958c1ca"
        },
        "dependencies": {"code_object": 1, "data_object": 3, "direct_calls": 0,
                          "dynamic_accesses": "bounded stack only", "unresolved_static_accesses": 0,
                          "objects_2_and_4": "left unknown and partial roots there rejected"},
        "capstone": {"recovered_instruction_count": lift["instructions"],
                     "body_end_exclusive": lift["end"], "loaded_bytes_include_le_fixups": True,
                     "original_link_stream_matches_ghidra": True,
                     "ghidra_instruction_evidence_id": rea["evidence_id"]},
        "fixture": {"screen_width": 640, "screen_height": 480, "framebuffer_guest_base": "0x00390000",
                    "register_inputs": {"EAX": 10, "EBX": 100, "ECX": 50, "EDX": 20},
                    "expected_window": {"x": 10, "y": 20, "width": 100, "height": 50},
                    "expected_draw_pointer": "0x0039320A"},
        "checks": ["generated C compiled with GWRecomp runtime", "native invocation via gw_recomp_invoke",
                   "verified LE object 3 globals read/written through guest memory", "registers and return state checked",
                   "not a full replay and not a framebuffer pixel write"],
        "passed": True
    }
    (ROOT / "evidence" / "partial_graphics_window.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("PASS bounded partial-closure generation and native execution")


if __name__ == "__main__":
    main()
