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
im=load_le(root/"evidence"/"genewars-1_1.exe"); obj=im.objects[0]
START=obj.base; code=bytes(im.mem[START-im.mem_base: START+obj.virtual_size-im.mem_base])
def find3(pat):
    out=[]; n=len(pat)
    for i in range(len(code)-n+1):
        if code[i:i+n]==pat: out.append(START+i)
    return out
# 3-byte repne scasb with operand-size prefix: F3 66 AE  and F2 66 AE
for name,pat in [("F3 66 AE",(0xF3,0x66,0xAE)),("F2 66 AE",(0xF2,0x66,0xAE)),
                 ("F3 AE  (2b)",(0xF3,0xAE)),("F2 AE  (2b)",(0xF2,0xAE))]:
    vs=find3(bytes(pat))
    print(f"{name:12s} -> {len(vs)} VAs {[hex(v) for v in vs]}")
