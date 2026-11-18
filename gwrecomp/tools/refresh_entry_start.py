"""Refresh the verified MAIN.EXE start lift without rescanning the full object."""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter


def function_span(source: str, name: str):
    m = re.search(r"\bvoid\s+" + re.escape(name) + r"\s*\(void\)\s*\{", source)
    if not m:
        raise ValueError(f"definition not found: {name}")
    brace = source.index("{", m.start())
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return m.start(), i + 1
    raise ValueError(f"unterminated definition: {name}")


image_path = ROOT / "evidence" / "genewars-1_1.exe"
image = load_le(image_path)
obj = image.objects[0]
code = bytes(image.mem[obj.base - image.mem_base:obj.base + obj.virtual_size - image.mem_base])
section = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
disassembler = Disassembler(code, 0, [section])
func = disassembler.disassemble_function(0x000AF96C)
if func is None or func.address != 0x000AF96C:
    raise SystemExit("could not recover exact start boundary")
func.name = "gw_entry_start"
lift = Lifter().lift_function(func)
if "gw_interrupt_dispatch(0x21u, 0x000AFA09u)" not in lift:
    raise SystemExit("start lift missed expected first DOS INT 21h")

updated = []
for relative in ("build/entry_path.c", "build/entry_path_combined.c", "build/entry_path_closure.c"):
    path = ROOT / relative
    source = path.read_text(encoding="utf-8")
    stop_include = '#include "gw_recomp_stop.h"'
    if stop_include not in source:
        source = source.replace('#include "recomp_types.h"', '#include "recomp_types.h"\n' + stop_include, 1)
        if stop_include not in source:
            raise SystemExit(f"could not install guest-stop wrappers in {relative}")
    start, end = function_span(source, "gw_entry_start")
    path.write_text(source[:start] + lift + source[end:], encoding="utf-8")
    updated.append(relative)

raw = bytes(image.mem[func.address - image.mem_base:func.end - image.mem_base])
evidence = {
    "test": "refreshed exact MAP start root using current x86 lifter",
    "target_sha256": hashlib.sha256(image_path.read_bytes()).hexdigest(),
    "entry_va": "0x000AF96C",
    "entry_end": f"0x{func.end:08X}",
    "entry_size": len(raw),
    "instruction_count": func.num_instructions,
    "first_interrupt": {"vector": "0x21", "va": "0x000AFA09"},
    "refreshed_files": updated,
    "passed": True,
}
(ROOT / "evidence" / "lifted_interrupt_entry_refresh.json").write_text(
    json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
)
print(json.dumps(evidence, indent=2))
