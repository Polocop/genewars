"""Refresh only the original allocator call chain with current access hooks."""
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

TARGET = ROOT / "evidence" / "genewars-1_1.exe"
CLOSURE = ROOT / "build" / "entry_path_closure.c"
ADDRESSES = (
    0x000921F0,  # LbMemorySetup_: exact prior exception guest-function boundary
    0x000ADF95,  # _nmalloc_
    0x000C3898,  # pool/block lookup
    0x000C3BE5,  # heap split / block header helper
    0x000C3D7A,
    0x000C3E2A,  # heap block allocation
    0x000C3F76,
    0x000C3FF3,
    0x000D710F,
    0x000ADF13,
)

target_bytes = TARGET.read_bytes()
target_sha = hashlib.sha256(target_bytes).hexdigest()
image = load_le(TARGET)
obj = image.objects[0]
code = bytes(image.mem[obj.base - image.mem_base:obj.base + obj.virtual_size - image.mem_base])
section = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
disassembler = Disassembler(code, 0, [section])
lifter = Lifter()
source = CLOSURE.read_text(encoding="utf-8")
source_before = hashlib.sha256(source.encode("utf-8")).hexdigest()
refreshed = []

for address in ADDRESSES:
    defs = {}
    for item in re.finditer(r"(?m)^void\s+([A-Za-z_]\w*)\s*\(void\)\s*\{", source):
        opening = source.index("{", item.start())
        depth = 0
        finish = opening
        for finish in range(opening, len(source)):
            if source[finish] == "{": depth += 1
            elif source[finish] == "}":
                depth -= 1
                if depth == 0: break
        body = source[item.start():finish+1]
        entry = re.search(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)", body)
        if entry:
            defs[int(entry.group(1), 16)] = (item.group(1), item.start())
    if address not in defs:
        raise SystemExit(f"allocator function 0x{address:08X} is absent from the current closure")
    fn_name, _ = defs[address]
    recovered = disassembler.disassemble_function(address)
    if recovered is None or recovered.address != address:
        raise SystemExit(f"could not recover exact original boundary 0x{address:08X}")
    recovered.name = fn_name
    lifted = lifter.lift_function(recovered)
    pattern = re.compile(r"(?ms)^void\s+" + re.escape(fn_name) + r"\s*\(void\)\s*\{.*?^\}")
    source, count = pattern.subn(lambda _: lifted, source, count=1)
    if count != 1:
        raise SystemExit(f"expected one definition for {fn_name} at 0x{address:08X}")
    access_hooks = lifted.count("recomp_begin_memory_access_ex(")
    instruction_hooks = lifted.count("gw_recomp_guest_instruction(")
    if instruction_hooks < 1:
        raise SystemExit(f"fresh lift at 0x{address:08X} has no guest instruction hooks")
    refreshed.append({"address": f"0x{address:08X}", "name": fn_name,
                      "instructions": sum(len(block.instructions) for block in recovered.blocks.values()),
                      "memory_access_hooks": access_hooks,
                      "instruction_hooks": instruction_hooks})

CLOSURE.write_text(source, encoding="utf-8")
evidence = {
    "schema": "gwrecomp.memory-diagnostic-allocator-refresh/v1",
    "target_sha256": target_sha,
    "closure_sha256_before": source_before,
    "closure_sha256_after": hashlib.sha256(CLOSURE.read_bytes()).hexdigest(),
    "functions": refreshed,
    "original_entry_executed": False,
}
(ROOT / "evidence" / "memory_diag_allocator_refresh_w1_105.json").write_text(
    json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print(json.dumps(evidence, indent=2))
