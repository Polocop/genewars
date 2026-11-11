
# _probe_p08verify.py — INDEPENDENT P08 re-derivation via explicit forward walk
import sys
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
    return {int(m,16) for m in __import__("re").findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)",tx)}
closure=reenter("build/entry_path_closure.c"); dynamic=reenter("build/entry_path_combined.c")
ds=Disassembler(code,0,[Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)])
funcs=ds.find_functions(START,START+obj.virtual_size,seeds=sorted(closure))

CF_WRITE={"add","adc","sub","sbb","neg","cmp","xadd","and","or","xor","test",
"cmpsb","cmpsw","cmpsd","scasb","scasw","scasd","shl","shr","sar","rol","ror","rcl","rcr",
"popf","imul","mul","div","idiv"}
CF_BOUNDARY={"call","callf","ret","retf","int","int3","loop","loopz","loopnz","jmp","jmpf","jcxz","jecxz"}
CF_CONSUMER={"sbb","adc"}
def bop(i): return i.mnemonic.lower().split()[-1]
def stream(f):
    out=[]
    for b in f.blocks.values(): out.extend(b.instructions)
    out.sort(key=lambda i:i.address)
    return out

hits=[]; neg_total=0; close_reason=Counter()
for seed in sorted(closure):
    f=funcs.get(seed)
    if f is None:
        try: f=ds.disassemble_at(seed)
        except: f=None
    if f is None or not f.blocks: continue
    ins=stream(f)
    for idx,i in enumerate(ins):
        if bop(i)!="neg": continue
        neg_total+=1
        # forward walk: CF stays live through CF-retaining insns; closes on CF_WRITE (non-neg) or boundary
        k=idx+1
        consumed=None
        while k<len(ins):
            b=bop(ins[k])
            if b in CF_CONSUMER:
                consumed=ins[k]; break
            if b in CF_WRITE or b in CF_BOUNDARY:
                break
            k+=1
        if consumed is not None:
            hits.append((i.address, consumed.address, bop(consumed), seed in dynamic))
        else:
            if k<len(ins): close_reason[bop(ins[k]) or "<boundary>"]+=1
            else: close_reason["<eow>"]+=1

seen=set(); uniq=[]
for va,ca,op,dyn in hits:
    if va in seen: continue
    seen.add(va); uniq.append((va,ca,op,dyn))
print(f"NEG total (distinct): {len([1 for s in seen])}")
print(f"P08 NEG->SBB/ADC (distinct NEG VA): {len(uniq)}")
print(f"  of which on dynamic route: {sum(1 for h in uniq if h[3])}")
print("window-close distribution (why a NEG's CF died):")
for k,v in close_reason.most_common(): print(f"   {k:10s} {v}")
print("sample hits:", [(hex(a),hex(c),o,"DYN" if d else "-") for a,c,o,d in uniq[:12]])
