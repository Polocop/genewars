
import sys, re
from pathlib import Path
from collections import Counter
root = Path(r"E:\GWRecomp")
sys.path.insert(0, str(root/"src")); sys.path.insert(0, str(root/"third_party"/"pcrecomp"))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
im = load_le(root/"evidence"/"genewars-1_1.exe")
obj = im.objects[0]; START=obj.base; END=START+obj.virtual_size
code = bytes(im.mem[START-im.mem_base:END-im.mem_base])
ds = Disassembler(code, 0, [Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)])
def re_vas(p):
    if not p.exists(): return set()
    return {int(m,16) for m in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)", p.read_text(encoding="utf-8",errors="replace"))}
cv = re_vas(root/"build"/"entry_path_closure.c")
funcs = ds.find_functions(START, END, seeds=sorted(cv))
bounds=set()
for s in cv:
    f=funcs.get(s)
    if not f or not f.blocks: continue
    for b in f.blocks.values():
        for i in b.instructions: bounds.add(i.address)
print("closure instruction-boundary VAs:", len(bounds))
OP = {0xAE:"scasb",0xA6:"cmpsb",0x8A:"stosb",0xAA:"stosw",0xA4:"movsb",0xA5:"movsw",0xA3:"movsd"}
cnt=Counter(); p05=[]; p06=[]
for va in sorted(bounds):
    b0=code[va-START]; b1=code[va-START+1]
    rep = "REPNE" if b0==0xF2 else ("REPE" if b0==0xF3 else None)
    if rep and b1 in OP:
        cnt[(rep,OP[b1])]+=1
        if rep=="REPNE" and OP[b1]=="scasb": p05.append(va)
        if rep=="REPE" and OP[b1]=="cmpsb": p06.append(va)
print("\nGROUND TRUTH (decoder-independent 2-byte byte-scan at closure boundaries):")
for k in sorted(cnt, key=lambda k:(k[1],k[0])):
    print(f"  {k[0]:5s} {k[1]:8s}: {cnt[k]}")
print("\nP05 repne scasb distinct VAs:", len(p05), [hex(v) for v in p05])
print("P06 repe  cmpsb distinct VAs:", len(p06), [hex(v) for v in p06])
print("\nCONTROL for self-test:")
print("  P05 =", len(p05))
print("  P06 =", len(p06))
