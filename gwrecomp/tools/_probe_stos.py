
import sys, re
from pathlib import Path
from collections import Counter
root = Path(r"E:\GWRecomp")
sys.path.insert(0, str(root/"src")); sys.path.insert(0, str(root/"third_party"/"pcrecomp"))
from le_loader import load_le
from tools.pe.pe_analyze import Section
from tools.disasm.disasm32 import Disassembler
im=load_le(root/"evidence"/"genewars-1_1.exe"); obj=im.objects[0]
START=obj.base; code=bytes(im.mem[START-im.mem_base: START+obj.virtual_size-im.mem_base])
def reenter(p):
    tx=(root/p).read_text(encoding="utf-8",errors="replace")
    return {int(m,16) for m in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)",tx)}
closure=reenter("build/entry_path_closure.c")
ds=Disassembler(code,0,[Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)])
funcs=ds.find_functions(START,START+obj.virtual_size,seeds=sorted(closure))
def bop(i): return i.mnemonic.lower().split()[-1]
seen=set(); hits=[]
for seed in sorted(closure):
    f=funcs.get(seed)
    if f is None:
        try: f=ds.disassemble_at(seed)
        except: f=None
    if f is None or not f.blocks: continue
    for b in f.blocks.values():
        for i in b.instructions:
            if bop(i).startswith("stos") and i.address not in seen:
                seen.add(i.address)
                first=i.mnemonic.lower().split()[0] if len(i.mnemonic.lower().split())>1 else None
                if first in ("rep","repe","repz","repne","repnz") or (i.bytes and i.bytes[0] in (0xF2,0xF3)):
                    hits.append((i.address, i.mnemonic, bytes(i.bytes)))
print(f"rep stos* found: {len(hits)}")
opc=Counter()
for va,mn,b in hits:
    opc[(mn, b.hex())]+=1
for (mn,bh),n in sorted(opc.items(), key=lambda x:-x[1]):
    print(f"  {mn:12s} {bh:12s} x{n}")
# distinct last-byte opcodes
print("last-byte opcodes:", Counter(bytes(b)[-1] for _,_,b in hits))
