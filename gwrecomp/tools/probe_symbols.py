from pathlib import Path
from dos_re.le import load_le
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
im=load_le(Path(r'E:\GWRecomp\evidence\genewars-1_1.exe'))
raw=Path(r'E:\GWRecomp\evidence\genewars-1_1.map').read_text(errors='replace')
rows=[]
for line in raw.splitlines():
 s=line.split()
 if len(s)>=2 and s[0].startswith('0001:'):
  try: off=int(s[0].split(':')[1],16)
  except: continue
  rows.append((off,s[1]))
print('map symbols seg1',len(rows))
for i,(off,name) in enumerate(rows):
 if name in ('LbDataLoad_','LbDataLoadAll_','LbFileLoadAt_','main_','LbDataLoad','LbDataLoadAll') or name.startswith('LbFileLoadAt'):
  end=rows[i+1][0] if i+1<len(rows) else off+0x100
  print('\nCANDIDATE',hex(off),name,'next',hex(end),hex(end-off))
  code=im.mem[off-im.mem_base:off-im.mem_base+min(48,end-off)]
  print(' '.join(f'{x:02x}' for x in code))
  for ins in Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,off):print(f'{ins.address:08x} {ins.mnemonic:8} {ins.op_str}')
