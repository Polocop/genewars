import hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter
src=ROOT/'build/entry_path_closure.c'; text=src.read_text(encoding='utf-8')
# Find function definitions with raw direct segment loads; parse brace-balanced C functions.
def defs(tx):
 out=[]
 for m in re.finditer(r'\bvoid\s+([A-Za-z_]\w*)\s*\(void\)\s*\{',tx):
  brace=tx.index('{',m.start()); depth=0
  for j in range(brace,len(tx)):
   depth += (tx[j]=='{')-(tx[j]=='}')
   if depth==0: out.append((m.start(),j+1,m.group(1),tx[m.start():j+1]));break
 return out
functions=defs(text); candidates=[]
for a,b,n,body in functions:
 if re.search(r'_seg_(?:es|ds|ss|fs|gs|cs)\s*=\s*(?:MEM16|POP\d+_VAL)\(',body) or 'seg reg write' in body:
  enter=re.search(r'RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)',body)
  if enter:candidates.append((a,b,n,int(enter.group(1),16)))
img=load_le(ROOT/'evidence/genewars-1_1.exe');obj=img.objects[0];lo=obj.base;hi=lo+obj.virtual_size
code=bytes(img.mem[lo-img.mem_base:hi-img.mem_base]);sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
dis=Disassembler(code,0,[sec]);lift=Lifter(); updates=[]
for a,b,n,va in candidates:
 f=dis.disassemble_function(va)
 if f is None: raise SystemExit(f'cannot recover function {va:08x}')
 f.name=n; new=lift.lift_function(f)
 if re.search(r'_seg_(?:es|ds|ss|fs|gs|cs)\s*=\s*(?:MEM16|POP\d+_VAL)\(',new): raise SystemExit(f'raw segment write remains {va:08x}')
 updates.append((a,b,new,va))
for a,b,new,va in reversed(updates): text=text[:a]+new+text[b:]
src.write_text(text,encoding='utf-8')
print(json.dumps({'target_sha256':hashlib.sha256((ROOT/'evidence/genewars-1_1.exe').read_bytes()).hexdigest(),'refreshed_functions':[f'0x{x[3]:08X}' for x in updates],'count':len(updates),'closure_sha256':hashlib.sha256(src.read_bytes()).hexdigest()},indent=2))
