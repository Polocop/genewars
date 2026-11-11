from pathlib import Path
from dos_re.le import load_le
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
im=load_le(Path(r'E:\GWRecomp\evidence\genewars-1_1.exe')); lines=Path(r'E:\GWRecomp\evidence\genewars-1_1.map').read_text(errors='replace').splitlines(); rows=[]
for l in lines:
 s=l.split()
 if len(s)>=2 and s[0].startswith('0001:'):
  try: rows.append((int(s[0].split(':')[1],16),s[1]))
  except:pass
md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
for i,(a,n) in enumerate(rows[:-1]):
 if not n.startswith(('W?','Lb')):continue
 b=rows[i+1][0]
 if not a<b or b-a>0x100:continue
 raw=im.mem[a-im.mem_base:b-im.mem_base]
 ins=list(md.disasm(raw,a))
 if not ins or not any(x.mnemonic.startswith('ret') for x in ins):continue
 end=next((x for x in ins if x.mnemonic.startswith('ret')),None)
 if not end or end.address+end.size-a>0x60:continue
 ins=ins[:ins.index(end)+1]
 if any(x.mnemonic in ('call','jmp','int','int3','hlt','loop','loope','loopne') or x.mnemonic.startswith('j') for x in ins):continue
 print(hex(a),hex(end.address+end.size),n, 'bytes',end.address+end.size-a,'insns',len(ins),'; '.join(x.mnemonic+' '+x.op_str for x in ins))
 if len(ins)<=12:break
