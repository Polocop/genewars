import hashlib, json, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
exe=ROOT/'evidence'/'genewars-1_1.exe'; map_path=ROOT/'evidence'/'genewars-1_1.map'
image=load_le(exe); obj=image.objects[0]; lo=obj.base; hi=lo+obj.virtual_size
icall_path=ROOT/'evidence'/'icall_dispatch_table.json'; icall=json.loads(icall_path.read_text(encoding='utf-8'))
rows=[]; by_addr={}
for line in map_path.read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: addr=int(p[0].split(':')[1],16)
  except ValueError: continue
  rows.append((addr,p[1])); by_addr.setdefault(addr,[]).append(p[1])
missing=[r for r in icall['records'] if r.get('resolved_class')=='not_lifted_in_range']
targets=sorted({int(r['slot_static_ptr'],16) for r in missing})
code=bytes(image.mem[lo-image.mem_base:hi-image.mem_base]); sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
funcs=Disassembler(code,0,[sec]).find_functions(lo,hi,seeds=targets)
source=(ROOT/'build'/'recomp_282.c').read_text(encoding='utf-8',errors='replace')
compiled={int(x,16) for x in re.findall(r'RECOMP_ENTER\(0x([0-9A-Fa-f]{8})u\)',source)}
items=[]; all_exact=True
for va in targets:
 f=funcs.get(va); containing=[]
 if f is None:
  containing=[f'0x{o:08X}' for o,g in funcs.items() if any(i.address==va for b in g.blocks.values() for i in b.instructions)]
  all_exact=False
  items.append({'va':f'0x{va:08X}','map_names':by_addr.get(va,[]),'exact_boundary':False,'containing_cfgs':containing,'already_in_closure':va in compiled})
  continue
 insns=[i for b in f.blocks.values() for i in b.instructions]
 exact=bool(insns) and insns[0].address==va and all(lo<=i.address<hi for i in insns) and f.end<=hi
 if not exact: all_exact=False
 raw_start=va-image.mem_base; raw_end=f.end-image.mem_base
 items.append({'va':f'0x{va:08X}','map_names':by_addr.get(va,[]),'exact_boundary':exact,
   'end':f'0x{f.end:08X}','size':f.end-va,'blocks':len(f.blocks),'instructions':len(insns),
   'first_instruction':f'0x{insns[0].address:08X}' if insns else None,
   'bytes_sha256':hashlib.sha256(image.mem[raw_start:raw_end]).hexdigest(),
   'already_in_closure':va in compiled})
out={'task':'L-ICALL-LIFT7','target_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
 'map_sha256':hashlib.sha256(map_path.read_bytes()).hexdigest(),
 'icall_table_sha256':hashlib.sha256(icall_path.read_bytes()).hexdigest(),
 'icall_unlifted_records':len(missing),'unique_target_vas':len(targets),
 'closure_function_bodies_before':len(compiled),'all_targets_exact_boundaries':all_exact,
 'targets':items,'passed':all_exact and len(missing)==7 and len(targets)==5}
(ROOT/'evidence'/'icall_targets_boundary_work1.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(out,indent=2))
if not out['passed']: raise SystemExit(1)
