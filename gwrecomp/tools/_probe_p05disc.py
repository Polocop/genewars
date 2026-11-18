import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])

import sys, re
from pathlib import Path
from collections import Counter
root = Path((_GW_ROOT))
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
dv = re_vas(root/"build"/"entry_path_combined.c")
funcs = ds.find_functions(START, END, seeds=sorted(cv))
def stream(f):
    o=[]
    for b in f.blocks.values(): o.extend(b.instructions)
    o.sort(key=lambda i:i.address); return o
# detector P05 VAs
det=[]
for s in sorted(cv):
    f=funcs.get(s)
    if not f or not f.blocks: continue
    for i in stream(f):
        b=i.mnemonic.lower().split()[-1]
        first=i.mnemonic.lower().split()[0]
        b0=i.bytes[0] if i.bytes else 0
        rp = "REPNE" if b0==0xF2 or first in ("repne","repnz") else ("REPE" if b0==0xF3 or first in ("repe","repz","rep") else None)
        if b=="scasb" and rp=="REPNE": det.append((s,i.address))
det_vas={a for _,a in det}
print("detector P05 count:", len(det_vas))
# control VAs: lifted-C lines carrying 'repne scasb' have an address-anchored form
tx=(root/"build"/"entry_path_closure.c").read_text(encoding="utf-8",errors="replace")
# find the anchor pattern used in the lifted C for each insn
m= re.findall(r"repne\s+scasb", tx, re.I)
print("control literal count:", len(m))
# Show 3 raw lifted lines to learn the address anchor format
for ln in tx.splitlines():
    if re.search(r"repne\s+scasb", ln, re.I):
        print("SAMPLE:", ln.strip()[:140]); break
# Now: does the lifted C use a per-instruction VA comment? grep a known VA
va_sample = 0x1532D
hits=[ln.strip()[:120] for ln in tx.splitlines() if format(va_sample,'X').lower() in ln.lower() or f"{va_sample:08X}" in ln]
print(f"lines mentioning VA {va_sample:#x}:", len(hits), hits[:2])
# The extra one: which detector VA is NOT near a control text occurrence?
# Pair each detector VA with nearest control text by scanning a per-VA VA->line map.
# Build VA -> count of 'repne scasb' in the lifted C using the RECOMP_*VA anchor if present.
anchor_re = re.compile(r"(?:RECOMP_ENTER|0x)([0-9A-Fa-f]{5,8})")
# Simpler: the lift likely tags each insn with its VA in a comment like /* 0xADDR: repne scasb */
cm = re.findall(r"0x([0-9A-Fa-f]{5,8})\s*:\s*repne\s+scasb", tx, re.I)
ctrl_vas = {int(x,16) for x in cm}
print("control VAs from '0xADDR: repne scasb' comments:", len(ctrl_vas))
if ctrl_vas:
    only_det = det_vas - ctrl_vas
    only_ctrl = ctrl_vas - det_vas
    print("  in detector not in control:", [hex(v) for v in sorted(only_det)])
    print("  in control not in detector:", [hex(v) for v in sorted(only_ctrl)])
else:
    print("  (no '0xADDR: mnemonic' comment anchor found; lift uses different encoding)")
