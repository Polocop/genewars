import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import sys
from pathlib import Path
root = Path((_GW_ROOT))
sys.path.insert(0, str(root/"src")); sys.path.insert(0, str(root/"third_party"/"pcrecomp"))
from le_loader import load_le
from tools.pe.pe_analyze import Section
from tools.disasm.disasm32 import Disassembler
import re
im=load_le(root/"evidence"/"genewars-1_1.exe"); obj=im.objects[0]
START=obj.base; code=bytes(im.mem[START-im.mem_base: START+obj.virtual_size-im.mem_base])
def reenter(p):
    tx=(root/p).read_text(encoding="utf-8",errors="replace")
    return {int(m,16) for m in re.findall(r"RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)",tx)}
closure=reenter("build/entry_path_closure.c")
ds=Disassembler(code,0,[Section(".text",obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)])
funcs=ds.find_functions(START,START+obj.virtual_size,seeds=sorted(closure))
REPN={"repne","repnz"}
def bop(insn): return insn.mnemonic.lower().split()[-1]
det=set(); ctl=set()
for seed in sorted(closure):
    f=funcs.get(seed)
    if f is None:
        try: f=ds.disassemble_at(seed)
        except: f=None
    if f is None or not f.blocks: continue
    for b in f.blocks.values():
        for i in b.instructions:
            if bop(i)=="scasb":
                first=i.mnemonic.lower().split()[0]
                rep = first in REPN or (i.bytes and i.bytes[0]==0xF2)
                if rep:
                    det.add(i.address)
                    r=i.address-START
                    if code[r]==0xF2 and code[r+1]==0xAE:
                        ctl.add(i.address)
print("detector distinct P05 VAs:",len(det))
print("control  distinct P05 VAs:",len(ctl))
only_det=sorted(det-ctl)
only_ctl=sorted(ctl-det)
print("detector-only (control missed):",[hex(v) for v in only_det])
print("control-only  (detector missed):",[hex(v) for v in only_ctl])
for v in only_det:
    r=v-START
    print(f"  VA {hex(v)} bytes@r: {[hex(code[r+k]) for k in range(5)]}  (r={r})")
for v in only_ctl:
    r=v-START
    print(f"  VA {hex(v)} bytes@r: {[hex(code[r+k]) for k in range(5)]}  (r={r})")
