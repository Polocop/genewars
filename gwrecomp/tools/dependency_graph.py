"""Recover direct callees referenced by the current 100-function lift sample."""
import json, re, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src')); sys.path.insert(0,str(ROOT/'third_party'/'pcrecomp'))
from le_loader import load_le
from tools.disasm.disasm32 import Disassembler
from tools.pe.pe_analyze import Section
from tools.lift.lift32 import Lifter

src=(ROOT/'build'/'recomp_catalog_100.c').read_text(encoding='utf-8')
meta=json.loads((ROOT/'evidence'/'catalog_lift_100.json').read_text(encoding='utf-8'))
selected={int(x['address'],16):x for x in meta['functions']}
map_syms={}
for line in (ROOT/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
    p=line.split()
    if len(p)>=2 and p[0].startswith('0001:'):
        try: map_syms[int(p[0].split(':')[1],16)]=p[1]
        except ValueError: pass

current=None; raw_edges=[]
for line in src.splitlines():
    m=re.search(r'RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)',line)
    if m: current=int(m.group(1),16)
    m=re.search(r'RECOMP_CALL\(([A-Za-z0-9_]+)\).*?0x([0-9A-Fa-f]+): call 0x([0-9A-Fa-f]+)',line)
    if m and current is not None:
        raw_edges.append({'caller':current,'call_site':int(m.group(2),16),'target':int(m.group(3),16),'generated_symbol':m.group(1)})
targets=sorted({x['target'] for x in raw_edges})

t0=time.time(); image=load_le(ROOT/'evidence'/'genewars-1_1.exe'); obj=image.objects[0]
start=obj.base; end=start+obj.virtual_size
code=bytes(image.mem[start-image.mem_base:end-image.mem_base])
sec=Section('.text',obj.base,obj.virtual_size,0,obj.virtual_size,0x20000020)
base_seeds={a for a,n in map_syms.items() if start<=a<end and (n.startswith(('W?','Lb')) or n.endswith('_') and not n.startswith(('jpt_','def_')))}
dis=Disassembler(code,0,[sec]); funcs=dis.find_functions(start,end,seeds=sorted(base_seeds|set(targets)))

recovered=[]; missing=[]; lifted_addrs=set(selected); queue=list(targets); edge_seen=set()
lift=Lifter()
while queue and len(lifted_addrs)<3000:
    a=queue.pop(0)
    if a in lifted_addrs or a in edge_seen: continue
    edge_seen.add(a)
    f=funcs.get(a)
    if f is None:
        missing.append(a); continue
    f.name=f'sub_{a:08X}'
    text=lift.lift_function(f)
    record={'address':a,'symbol':map_syms.get(a),'end':f.end,'instructions':sum(len(b.instructions) for b in f.blocks.values()),'blocks':len(f.blocks),'code':text}
    recovered.append(record); lifted_addrs.add(a)
    for m in re.finditer(r'RECOMP_CALL\(([A-Za-z0-9_]+)\).*?call 0x([0-9A-Fa-f]+)',text):
        target=int(m.group(2),16)
        if target not in lifted_addrs and target not in edge_seen and start<=target<end: queue.append(target)

by_addr={x['address']:x for x in recovered}
edges=[]
for x in raw_edges:
    edges.append({**{k:(f'0x{v:08X}' if isinstance(v,int) else v) for k,v in x.items()},
       'caller_symbol':map_syms.get(x['caller']) or selected.get(x['caller'],{}).get('map_name'),
       'target_symbol':map_syms.get(x['target']),'target_recovered':x['target'] in by_addr,
       'target_selected_before':x['target'] in selected})

lifted='\n\n'.join(x['code'] for x in recovered)
all_src=src+'\n\n'+lifted+'\n'
called=set(re.findall(r'RECOMP_CALL\(([A-Za-z0-9_]+)\)',all_src))
selected_aliases={f'sub_{a:08X}':x['lift_name'] for a,x in selected.items()}
used_aliases={k:v for k,v in selected_aliases.items() if k in called}
defined=set(re.findall(r'void\s+([A-Za-z0-9_]+)\s*\(',lifted))
remaining=sorted(called-defined-set(used_aliases))
all_lifted_names={f'sub_{x["address"]:08X}' for x in recovered}
prelude='\n'.join([*(f'#define {alias} {fn}' for alias,fn in sorted(used_aliases.items())),*(f'extern void {n}(void);' for n in sorted(set(remaining)|all_lifted_names))])
out=ROOT/'build'/'recomp_catalog_100_recursive.c'
out.write_text('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'+prelude+'\n'+all_src,encoding='utf-8')
report={'target_sha256':meta['target_sha256'],'seed_map_functions':len(base_seeds),'selected_functions':len(selected),'call_edges':len(edges),'unique_direct_callees':len(targets),
 'callee_recovered':len(recovered),'total_functions_after_recursive_lift':len(lifted_addrs),'callee_missing_boundary':len(missing),'remaining_external_symbols':remaining,
 'selected_call_aliases':{k:v for k,v in sorted(used_aliases.items())},
 'elapsed_seconds':round(time.time()-t0,2),'edges':edges,'recovered_callees':[{'address':f'0x{x["address"]:08X}','symbol':x['symbol'],'end':f'0x{x["end"]:08X}','instructions':x['instructions'],'blocks':x['blocks']} for x in recovered],
 'missing_addresses':[f'0x{x:08X}' for x in missing]}
(ROOT/'evidence'/'dependency_graph_va_corrected.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k not in ('edges','recovered_callees','missing_addresses')},indent=2))
