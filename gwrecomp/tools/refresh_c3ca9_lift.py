import hashlib, json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter
TARGET=0x000C3CA9
imgpath=ROOT/'evidence'/'genewars-1_1.exe'
img=load_le(imgpath); obj=img.objects[0]; lo=obj.base; hi=lo+obj.virtual_size
code=bytes(img.mem[lo-img.mem_base:hi-img.mem_base])
mapnames={}
for line in (ROOT/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: mapnames[int(p[0].split(':')[1],16)]=p[1]
  except ValueError: pass
seeds=sorted(a for a,n in mapnames.items() if lo<=a<hi and (n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_'))))
sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
f=Disassembler(code,0,[sec]).disassemble_function(TARGET)
if f is None: raise SystemExit('exact function boundary missing')
f.name=f'sub_{TARGET:08X}'; lifted=Lifter().lift_function(f)
pat=re.compile(r'void\s+sub_000C3CA9\s*\(void\)\s*\{')
def replace_body(source):
 old=source.read_text(encoding='utf-8'); m=pat.search(old)
 if not m: raise SystemExit(f'generated function missing in {source}')
 start=m.start(); brace=old.index('{',m.start()); depth=0; end=None
 for i,ch in enumerate(old[brace:],brace):
  if ch=='{': depth+=1
  elif ch=='}':
   depth-=1
   if depth==0: end=i+1; break
 if end is None: raise SystemExit(f'unclosed function in {source}')
 source.write_text(old[:start]+lifted+old[end:],encoding='utf-8')
 return end-start

# Keep the catalog body and both entry-path consumers derived from the same
# exact binary bytes and current Lifter implementation.
sources=[ROOT/'build'/name for name in ('recomp_catalog_100_recursive.c','entry_path_combined.c','entry_path_closure.c')]
old_sizes={str(source.relative_to(ROOT)):replace_body(source) for source in sources}
print(json.dumps({'address':hex(TARGET),'end':hex(f.end),'instructions':sum(len(b.instructions) for b in f.blocks.values()),'sha256':hashlib.sha256(imgpath.read_bytes()).hexdigest(),'segment_write_emitted':'recomp_write_segment(RECOMP_SEG_ES' in lifted,'old_bytes':old_sizes,'new_bytes':len(lifted),'outputs':[str(s.relative_to(ROOT)) for s in sources]},indent=2))

