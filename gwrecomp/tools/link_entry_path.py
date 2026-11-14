"""Combine the entry/game roots with the VA-corrected recursive closure and audit call targets."""
import json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
closure=(ROOT/'build'/'recomp_catalog_100_recursive.c').read_text(encoding='utf-8')
entry=(ROOT/'build'/'entry_path.c').read_text(encoding='utf-8')
parts=[]
for source in (closure,entry):
 lines=[x for x in source.splitlines() if x.strip() not in ('#define RECOMP_GENERATED_CODE','#include "recomp_types.h"')]
 parts.append('\n'.join(lines))
combined='#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'+'\n\n'.join(parts)+'\n'
out=ROOT/'build'/'entry_path_combined.c'; out.write_text(combined,encoding='utf-8')
defs=set(re.findall(r'\bvoid\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{',combined))
aliases=dict(re.findall(r'^#define\s+(sub_[A-Fa-f0-9]+)\s+(\w+)\s*$',combined,re.M))
map_syms={}
for line in (ROOT/'evidence'/'genewars-1_1.map').read_text(errors='replace').splitlines():
 p=line.split()
 if len(p)>=2 and p[0].startswith('0001:'):
  try: map_syms[int(p[0].split(':')[1],16)]=p[1]
  except ValueError: pass
caller=None; targets={}
for line in combined.splitlines():
 m=re.search(r'RECOMP_ENTER\(0x([0-9A-Fa-f]+)u\)',line)
 if m: caller=int(m.group(1),16)
 m=re.search(r'RECOMP_CALL\(([A-Za-z_]\w*)\).*?0x([0-9A-Fa-f]+):\s*call\s+0x([0-9A-Fa-f]+)',line)
 if m:
  name,site,target=m.group(1),int(m.group(2),16),int(m.group(3),16)
  targets.setdefault(name,{'symbol':name,'target_va':f'0x{target:08X}','map_name':map_syms.get(target),'call_sites':[]})['call_sites'].append({'caller':f'0x{caller:08X}' if caller is not None else None,'site':f'0x{site:08X}'})
resolved=[]; unresolved=[]
for name,item in sorted(targets.items()):
 if name in defs or (name in aliases and aliases[name] in defs): resolved.append(item); continue
 addr=int(item['target_va'],16); item['class']='dos4gw_dpmi_or_pre_code' if addr<0x10000 else ('watcom_crt_candidate' if (item['map_name'] or '').startswith(('__','_')) else 'missing_in_combined_lifts')
 unresolved.append(item)
rep={'target_sha256':json.loads((ROOT/'evidence'/'entry_path_lifts.json').read_text())['target_sha256'],'entry_roots':json.loads((ROOT/'evidence'/'entry_path_lifts.json').read_text())['roots'],'closure_functions':250,'combined_function_definitions':len(defs),'direct_call_symbols':len(targets),'resolved_direct_targets':len(resolved),'unresolved_direct_targets':len(unresolved),'resolved':resolved,'unresolved':unresolved,'object_source':str(out.relative_to(ROOT)),'guest_entry_executed':False}
(ROOT/'evidence'/'entry_path_link.json').write_text(json.dumps(rep,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in rep.items() if k not in ('resolved','unresolved','entry_roots')},indent=2))
