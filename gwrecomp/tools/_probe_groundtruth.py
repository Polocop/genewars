
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
# instruction-boundary VAs from the tool's own function walk (same as tool)
ds = Disassembler(code, 0, [Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)])
def re_vas(p):
    if not p.exists(): return set()
    return {int(m,16) for m in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)", p.read_text(encoding="utf-8",errors="replace"))}
cv = re_vas(root/"build"/"entry_path_closure.c")
funcs = ds.find_functions(START, END, seeds=sorted(cv))
bounds = set()
for s in cv:
    f=funcs.get(s)
    if not f or not f.blocks: continue
    for b in f.blocks.values():
        for i in b.instructions: bounds.add(i.address)
print("instruction-boundary VAs in closure:", len(bounds))

# GROUND TRUTH: raw byte-scan for exact opcodes AT instruction boundaries (closure)
def rel(va): return va-START
OPS = {
  0xAE: ("scasb"),
  0xA6: ("cmpsb"),
  0x8A: ("stosb"),
  0xA4: ("movsb"),
}
repne, repe = 0xF2, 0xF3
# For each boundary, peek (rep, opcode) two-byte sequence
cnt = Counter()
p05va, p06va = [], []
repstos = []
for va in sorted(bounds):
    r = rel(va)
    b0 = code[r]; b1 = code[r+1]
    rep = None
    if b0==repne: rep="REPNE"
    elif b0==repe: rep="REPE"
    if rep and b1 in OPS:
        cnt[(rep,OPS[b1][0])]+=1
        if OPS[b1][0]=="scasb" and rep=="REPNE": p05va.append(va)
        if OPS[b1][0]=="cmpsb" and rep=="REPE": p06va.append(va)
        if OPS[b1][0]=="stosb": repstos.append((va,rep))
# also scan the wider (non-alias) image boundaries we already have from probe: 120 string ops total in image.
print("\nGROUND-TRUTH byte-scan at closure instruction boundaries:")
for k in sorted(cnt): print(f"  {k[0]} {k[1]:8s}: {cnt[k]}")
print("  P05 repne scasb VAs:", [hex(v) for v in p05va], "=>", len(p05va))
print("  P06 repe  cmpsb VAs:", [hex(v) for v in p06va], "=>", len(p06va))
print("  rep stosb:", [hex(v) for v,_ in repstos], "=>", len(repstos))

# Compare to the tool detector's 29 and the lift literal 30
print("\n=== SETTLE 29 vs 30 ===")
print("byte-scan closure P05:", len(p05va))
print("tool-detector P05 (distinct VA): 29   (from _probe_p05disc)")
print("lift literal-text 'repne scasb' lines: 30")
print("=> ground truth = byte-scan value above")
