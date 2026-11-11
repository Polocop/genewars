from pathlib import Path
from dos_re.le import load_le
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
im=load_le(Path(r'E:\GWRecomp\evidence\genewars-1_1.exe')); rows=[]
for l in Path(r'E:\GWRecomp\evidence\genewars-1_1.map').read_text(errors='replace').splitlines():
 s=l.split()
 if len(s)>=2 and s[0].startswith('0001:'):
  try:rows.append((int(s[0].split(':')[1],16),s[1]))
  except:pass
md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True; counts={}; out=[]
for i,(a,n) in enumerate(rows):
 if not n.startswith('W?') or a<im.mem_base or a>=0xef930:continue
 nextm=min((x for x,y in rows[i+1:] if y.startswith('W?')),default=a+0x80); lim=min(nextm,a+0x100); ins=list(md.disasm(im.mem[a-im.mem_base:lim-im.mem_base],a));sel=[]
 for x in ins:
  sel.append(x)
  if x.mnemonic=='ret':break
  if x.mnemonic in ('call','jmp','int','int3') or x.mnemonic.startswith('j'):break
 if sel and sel[-1].mnemonic=='ret':
  k=';'.join(sorted({x.mnemonic for x in sel}));counts[k]=counts.get(k,0)+1
  if len(out)<100: out.append((hex(a),n,[(x.mnemonic,x.op_str) for x in sel]))
print('categories',sorted(counts.items(),key=lambda x:-x[1])[:20]);
for x in out: print(x)

