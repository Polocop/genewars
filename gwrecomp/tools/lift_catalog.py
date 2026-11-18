"""Recover map-matched function CFGs and emit a compilable 100-function lift sample."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter
root=Path(__file__).resolve().parents[1]; t=time.time(); im=load_le(root/'evidence'/'genewars-1_1.exe'); obj=im.objects[0]; start=obj.base; end=start+obj.virtual_size; code=bytes(im.mem[start-im.mem_base:end-im.mem_base])
rows=[]
for line in (root/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: rows.append((int(p[0].split(':')[1],16),p[1]))
  except ValueError: pass
sym={a:n for a,n in rows}; seeds=sorted({a for a,n in rows if start<=a<end and (n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_')))})
sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020); ds=Disassembler(code,0,[sec]); funcs=ds.find_functions(start,end,seeds=seeds)
matched=[f for a,f in funcs.items() if a in sym and not sym[a].startswith(('jpt_','def_'))]
matched.sort(key=lambda f:(sum(len(b.instructions) for b in f.blocks.values()),f.address))
N=int(sys.argv[1]) if len(sys.argv)>1 else 100
picked=matched[:N]
oracle=json.loads((root/'evidence'/'batch_10.json').read_text(encoding='utf-8'))
oracle_addrs={int(x['address'],16) for x in oracle.get('functions',[])}
prioritized=[f for f in matched if f.address in oracle_addrs]
picked=prioritized+[f for f in matched if f.address not in oracle_addrs]
picked=picked[:N]
if len(picked)<N: raise SystemExit(f'only {len(picked)} map-matched functions')
lines=['#define RECOMP_GENERATED_CODE','#include "recomp_types.h"','']
records=[]; lift=Lifter()
for i,f in enumerate(picked):
 original_name=sym[f.address]; f.name=f'gw_lift_{i:04d}'; code=lift.lift_function(f); lines.append(code); lines.append('')
 raw=bytes(im.mem[f.address-im.mem_base:f.end-im.mem_base])
 records.append({'lift_name':f.name,'map_name':original_name,'address':f'0x{f.address:08X}','end':f'0x{f.end:08X}','size':f.end-f.address,'bytes':raw.hex(),'blocks':len(f.blocks),'instructions':sum(len(b.instructions) for b in f.blocks.values())})
out=root/'build'/f'recomp_catalog_{N}.c'; out.write_text('\n'.join(lines))
defined=set(__import__('re').findall(r'void\s+(\w+)\s*\(', '\n'.join(lines)))
called=set(__import__('re').findall(r'RECOMP_CALL\((\w+)\)', '\n'.join(lines)))
external=sorted(called-defined)
(root/'build'/f'recomp_catalog_{N}_externs.h').write_text('\n'.join(f'extern void {name}(void);' for name in external)+'\n')
meta={'target_sha256':'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f','map_seed_count':len(seeds),'discovered_functions':len(funcs),'map_matched_functions':len(matched),'lifted_functions':len(records),'elapsed_seconds':round(time.time()-t,2),'functions':records}
meta['external_symbols']=external
(root/'evidence'/f'catalog_lift_{N}.json').write_text(json.dumps(meta,indent=2)+'\n')
print(json.dumps({k:v for k,v in meta.items() if k!='functions'},indent=2))
