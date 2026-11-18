import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
from pathlib import Path
from dos_re.le import load_le
from capstone import *
im=load_le((_GW_ROOT + '\\evidence\\genewars-1_1.exe')); rows=[]
for l in Path((_GW_ROOT + '\\evidence\\genewars-1_1.map')).read_text(errors='replace').splitlines():
 s=l.split()
 if len(s)>=2 and s[0].startswith('0001:'):
  try:rows.append((int(s[0].split(':')[1],16),s[1]))
  except:pass
md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True; cand=[]; cats={}
for i,(a,n) in enumerate(rows):
 if not n.startswith('W?') or not 0x10000<=a<0xef930:continue
 b=min((x for x,y in rows[i+1:] if y.startswith('W?')),default=a+0x400); b=min(b,a+0x400)
 ins=[]
 for x in md.disasm(im.mem[a-im.mem_base:b-im.mem_base],a):
  if x.mnemonic in ('call','jmp','int','int3') or x.mnemonic.startswith('j'):break
  ins.append(x)
  if x.mnemonic.startswith('ret'):break
 if ins and ins[-1].mnemonic.startswith('ret'):
  sig=tuple(x.mnemonic for x in ins);cats[len(ins)]=cats.get(len(ins),0)+1;cand.append((a,n,ins))
print('straight singleblock function candidates',len(cand),'length histogram',sorted(cats.items())[:30])
print('examples',[(hex(a),n,len(ins),[x.mnemonic for x in ins]) for a,n,ins in cand[:30]])
