
# _probe_discriminating.py — current vs fixed detector over REAL closure functions
import sys, re
from pathlib import Path
root = Path(r"E:\GWRecomp")
sys.path.insert(0, str(root/"src"))
sys.path.insert(0, str(root/"third_party"/"pcrecomp"))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section

im = load_le(root/"evidence"/"genewars-1_1.exe")
obj = im.objects[0]; START=obj.base; END=START+obj.virtual_size
code = bytes(im.mem[START-im.mem_base : END-im.mem_base])
sec = Section(".text", obj.base, obj.virtual_size, 0, obj.virtual_size, 0x20000020)
ds = Disassembler(code, 0, [sec])

def recomp_enter_vas(path):
    if not path.exists(): return set()
    tx = path.read_text(encoding="utf-8", errors="replace")
    return {int(m,16) for m in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)", tx)}
closure_vas = recomp_enter_vas(root/"build"/"entry_path_closure.c")
dynamic_vas = recomp_enter_vas(root/"build"/"entry_path_combined.c")
print("closure bodies:", len(closure_vas), "dynamic:", len(dynamic_vas))

funcs = ds.find_functions(START, END, seeds=sorted(closure_vas))
print("functions:", len(funcs))

def insn_stream(f):
    out=[]
    for b in f.blocks.values(): out.extend(b.instructions)
    out.sort(key=lambda i:i.address)
    return out

STRING_OPS = {"scasb","scasw","scasd","cmpsb","cmpsw","cmpsd","stosb","stosw","stosd","movsb","movsw","movsd"}
REPB={0xF2:"REPNE",0xF3:"REPE"}
def rep_prefix(va):
    b0=code[va-START]; return REPB.get(b0)
def rep_mode(insn):
    b0 = insn.bytes[0] if insn.bytes else None
    if b0==0xF2: return "REPNE"
    if b0==0xF3: return "REPE"
    m=insn.mnemonic.lower()
    if m.startswith("repne") or m.startswith("repz"): return "REPNE"
    if m.startswith("repe") or m.startswith("repz") or m=="rep": return "REPE"
    return None
def base_op(insn): return insn.mnemonic.lower().split()[-1]

cur = {"P05":0,"P06":0,"P07_stos":0,"P07_other":0,"bare_total":0}
fix = {"P05":0,"P06":0,"P07_stos":0,"P07_other":0,"rep_total":0}
cur_samples=[]; fix_samples=[]
for seed in sorted(closure_vas):
    f=funcs.get(seed)
    if f is None:
        try: f=list(ds.disassemble_at(seed))
        except Exception: f=None
    if f is None: continue
    # find_functions returns Function (has .blocks); on-the-fly returns generator -> skip
    if not hasattr(f,"blocks"): continue
    dyn = seed in dynamic_vas
    for i in insn_stream(f):
        m=i.mnemonic.lower()
        # CURRENT logic
        if m in STRING_OPS:
            cur["bare_total"]+=1
            rp=rep_prefix(i.address)
            if rp:
                if m=="scasb": cur["P05"]+=1
                elif m=="cmpsb": cur["P06"]+=1
                elif m.startswith("stos"): cur["P07_stos"]+=1
                else: cur["P07_other"]+=1
        # FIXED logic
        b=base_op(i)
        if b in STRING_OPS:
            rp=rep_mode(i)
            if rp:
                fix["rep_total"]+=1
                if b=="scasb":
                    fix["P05"]+=1
                    if len(fix_samples)<6 and dyn: fix_samples.append((i.address,seed))
                elif b=="cmpsb": fix["P06"]+=1
                elif b.startswith("stos"): fix["P07_stos"]+=1
                else: fix["P07_other"]+=1

print("\n=== CURRENT detector (m in STRING_OPS, folded-mnemonic bug) ===")
print(cur)
print("\n=== FIXED detector (base-op + capstone rep byte) ===")
print(fix)

print("\n=== INDEPENDENT CONTROL (regex on lifted closure C) ===")
tx=(root/"build"/"entry_path_closure.c").read_text(encoding="utf-8",errors="replace")
ctrl={
 "repne_scasb":len(re.findall(r"\brepne\s+scasb\b",tx,re.I)),
 "repe_cmpsb": len(re.findall(r"\brepe\s+cmpsb\b",tx,re.I)),
 "rep_stos":   len(re.findall(r"\brepe?ne?\s+stos[wd]\b",tx,re.I)),
}
print(ctrl)

print("\n=== VERDICT ===")
print(f"Control repne_scasb={ctrl['repne_scasb']}  fixed P05={fix['P05']}  -> {'MATCH' if fix['P05']==ctrl['repne_scasb'] else 'MISMATCH'}")
print(f"Control repe_cmpsb ={ctrl['repe_cmpsb']}  fixed P06={fix['P06']}  -> {'MATCH' if fix['P06']==ctrl['repe_cmpsb'] else 'MISMATCH'}")
print(f"Control rep_stos   ={ctrl['rep_stos']}  fixed P07_stos={fix['P07_stos']} -> {'MATCH' if fix['P07_stos']==ctrl['rep_stos'] else 'NOTE: fixed also counts movsb/movsd as P07_other='+str(fix['P07_other'])}")
print("\nFixed P05 sample VAs (dynamic route):", [hex(a) for a,_ in fix_samples])
print("root cause: capstone folds REP prefix into mnemonic -> `m in STRING_OPS` never true for rep-prefixed ops")
