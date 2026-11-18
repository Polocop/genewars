import sys
from pathlib import Path
from capstone import x86_const
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root/"src"))
sys.path.insert(0, str(root/"third_party"/"pcrecomp"))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
import re, json

im = load_le(root/"evidence"/"genewars-1_1.exe")
obj = im.objects[0]
START = obj.base; END = START + obj.virtual_size
code = bytes(im.mem[START - im.mem_base : END - im.mem_base])
sec = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
ds = Disassembler(code, 0, [sec])

tx = (root/"build"/"entry_path_closure.c").read_text(encoding="utf-8", errors="replace")
closure_vas = {int(m,16) for m in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)", tx)}
funcs = ds.find_functions(START, END, seeds=sorted(closure_vas))

STRING = {"scasb","scasw","scasd","cmpsb","cmpsw","cmpsd","stosb","stosw","stosd","movsb","movsw","movsd"}
REP = (x86_const.X86_INS_REP, x86_const.X86_INS_REPNE, x86_const.X86_INS_REPE)
samples=[]; checked=0
for va,f in funcs.items():
    for b in f.blocks.values():
        for i in b.instructions:
            if i.mnemonic.lower() in STRING and any(p in REP for p in i.prefixes):
                idx=i.address-START
                samples.append({
                    "va":i.address,"mnem":i.mnemonic.lower(),
                    "prefixes":[p for p in i.prefixes],
                    "b_at":code[idx] if idx>=0 else None,
                    "b_prev":code[idx-1] if idx-1>=0 else None,
                    "addr_is_rep":code[idx] in (0xF2,0xF3) if idx>=0 else None,
                    "prev_is_rep":code[idx-1] in (0xF2,0xF3) if idx-1>=0 else None,
                })
                checked+=1
                if checked>=14: break
        if checked>=14: break
    if checked>=14: break

print(json.dumps(samples, indent=2))
print(f"\nchecked {checked} rep-prefixed string-op insns via the tool's own capstone decoder")
at=sum(1 for s in samples if s["addr_is_rep"])
pr=sum(1 for s in samples if s["prev_is_rep"])
print(f"rep_prefix as written code[addr-START] would see the REP byte in {at}/{len(samples)}")
print(f"code[addr-START-1] would see the REP byte in {pr}/{len(samples)}")