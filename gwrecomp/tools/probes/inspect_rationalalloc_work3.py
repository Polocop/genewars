"""Read-only original-byte disassembly for W3-059."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "third_party" / "pcrecomp"))

from le_loader import load_le  # noqa: E402
from tools.disasm.disasm32 import Disassembler  # noqa: E402
from tools.pe.pe_analyze import Section  # noqa: E402


TARGET = ROOT / "evidence" / "genewars-1_1.exe"
MAP = ROOT / "evidence" / "genewars-1_1.map"
START = 0x000C3CA9
END = 0x000C3D7A
SITE = 0x000C3D42

image = load_le(TARGET)
obj = image.objects[0]
code = bytes(image.mem[obj.base - image.mem_base : obj.base - image.mem_base + obj.virtual_size])
section = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
function = Disassembler(code, 0, [section]).disassemble_function(START)
if function is None:
    raise SystemExit("RationalAlloc_ did not disassemble at the MAP address")

instructions = sorted(
    (ins for block in function.blocks.values() for ins in block.instructions),
    key=lambda ins: ins.address,
)
map_lines = MAP.read_text(errors="replace").splitlines()
symbols = {}
for line in map_lines:
    fields = line.split()
    if len(fields) >= 2 and fields[0].startswith("0001:"):
        try:
            symbols[int(fields[0].split(":", 1)[1], 16)] = fields[1]
        except ValueError:
            pass

print(json.dumps({
    "target_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
    "map_sha256": hashlib.sha256(MAP.read_bytes()).hexdigest(),
    "map_symbols": {f"0x{addr:08X}": symbols.get(addr) for addr in (0xC3AE6, 0xC3BE5, 0xC3C59, START, END, 0xC3E2A, 0xC3F76)},
    "disassembler_function_end": f"0x{function.end:08X}",
    "function_instructions": [
        {"va": f"0x{ins.address:08X}", "bytes": ins.bytes.hex().upper(), "mnemonic": ins.mnemonic, "operands": ins.op_str}
        for ins in instructions if START <= ins.address < END
    ],
    "mov_es_eax_at_c3d42": next((
        {"va": f"0x{ins.address:08X}", "bytes": ins.bytes.hex().upper(), "mnemonic": ins.mnemonic, "operands": ins.op_str}
        for ins in instructions if ins.address == SITE
    ), None),
}, indent=2))
