"""Produce a complete edge inventory for the generated recursive lift unit."""
import json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
srcp=ROOT/'build'/'recomp_catalog_100_recursive.c'
src=srcp.read_text(encoding='utf-8')
base=json.loads((ROOT/'evidence'/'catalog_lift_100.json').read_text(encoding='utf-8'))
map_syms={}
for line in (ROOT/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: map_syms[int(p[0].split(':')[1],16)]=p[1]
  except ValueError: pass
image=json.loads((ROOT/'evidence'/'function_catalog.json').read_text(encoding='utf-8'))
lo,hi=(int(x,16) for x in image['code_range'])
functions=[]; edges=[]; current=None
aliases=dict(re.findall(r'(?m)^#define\s+(sub_[A-Fa-f0-9]+)\s+(gw_lift_\d+)',src))
definitions=set(re.findall(r'(?m)^void\s+([A-Za-z0-9_]+)\s*\(',src))
for line in src.splitlines():
 m=re.search(r'RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)',line)
 if m:
  current=int(m.group(1),16); functions.append(current)
 m=re.search(r'RECOMP_CALL\(([A-Za-z0-9_]+)\).*?0x([0-9A-Fa-f]+): call 0x([0-9A-Fa-f]+)',line)
 if m and current is not None:
  a=int(m.group(2),16); b=int(m.group(3),16)
  edges.append({'caller':f'0x{current:08X}','caller_symbol':map_syms.get(current),
    'call_site':f'0x{a:08X}','target':f'0x{b:08X}','target_symbol':map_syms.get(b),
    'generated_target':m.group(1),'target_in_code_object':lo<=b<hi})
lifted=set(functions); unique_targets=sorted({int(e['target'],16) for e in edges})
unresolved=[]
for target in unique_targets:
 names={e['generated_target'] for e in edges if int(e['target'],16)==target}
 if not any(aliases.get(n,n) in definitions for n in names): unresolved.append(target)
obj=ROOT/'build'/'recomp_catalog_100_recursive_corrected.o'
result={'target_sha256':base['target_sha256'],'code_range':[f'0x{lo:08X}',f'0x{hi:08X}'],
 'selected_seed_lifts':base['lifted_functions'],'recursive_lifts':max(0,len(lifted)-base['lifted_functions']),
 'total_lifted_functions':len(lifted),'direct_call_edges':len(edges),'unique_direct_targets':len(unique_targets),
 'unique_targets_unresolved':len(unresolved),'unresolved_target_addresses':[f'0x{x:08X}' for x in unresolved],
 'generated_call_aliases':len(aliases),'unresolved_link_symbols':sorted({n for e in edges if int(e['target'],16) in unresolved for n in [e['generated_target']] if aliases.get(n,n) not in definitions}),
 'unresolved_targets_in_code_object':[f'0x{x:08X}' for x in unresolved if lo<=x<hi],
 'compiled_object_exists':obj.exists(),'compiled_object_bytes':obj.stat().st_size if obj.exists() else 0,
 'edges':edges}
out=ROOT/'evidence'/'dependency_closure_va_corrected.json'; out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
lines=['# Dependency closure result','',f"Target SHA-256: `{result['target_sha256']}`.",
 f"The original 100 lifts have {result['direct_call_edges']} direct call edges across {result['unique_direct_targets']} unique targets in the recursive generated unit.",
 f"Recovered {result['recursive_lifts']} additional functions; total lifted: {result['total_lifted_functions']}.",
 f"The x86-32 object exists: `{result['compiled_object_exists']}` ({result['compiled_object_bytes']} bytes).",
 f"{result['unique_targets_unresolved']} direct targets are still unresolved: {', '.join(result['unresolved_target_addresses'])}.",
 'A target counts as resolved only when its generated function body is present. Forward declarations are not counted as implementations.', '',
 '| Caller | Call site | Target | MAP symbol | Target in code object |','|---|---:|---:|---|---|']
for e in edges: lines.append(f"| `{e['caller']}` {e['caller_symbol'] or ''} | `{e['call_site']}` | `{e['target']}` | {e['target_symbol'] or ''} | {e['target_in_code_object']} |")
(ROOT/'reports'/'coordination'/'dependency_closure_va_corrected.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='edges'},indent=2))
