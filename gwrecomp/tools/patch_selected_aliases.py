"""Bind generated `sub_<VA>` direct calls to selected gw_lift_<n> bodies."""
import json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
srcp=ROOT/'build'/'recomp_catalog_100_recursive.c'
src=srcp.read_text(encoding='utf-8')
meta=json.loads((ROOT/'evidence'/'catalog_lift_100.json').read_text(encoding='utf-8'))
by_addr={int(x['address'],16):x['lift_name'] for x in meta['functions']}
calls=set(re.findall(r'RECOMP_CALL\((sub_[A-Fa-f0-9]+)\)',src))
aliases={name:by_addr[int(name[4:],16)] for name in calls if int(name[4:],16) in by_addr}
src=re.sub(r'/\* GW_SELECTED_CALL_ALIASES_BEGIN \*/.*?/\* GW_SELECTED_CALL_ALIASES_END \*/\s*','',src,flags=re.S)
block='/* GW_SELECTED_CALL_ALIASES_BEGIN */\n'+'\n'.join(f'#define {a} {b}' for a,b in sorted(aliases.items()))+'\n/* GW_SELECTED_CALL_ALIASES_END */\n'
srcp.write_text(block+src,encoding='utf-8')
out={'alias_count':len(aliases),'aliases':aliases}
(ROOT/'evidence'/'selected_call_aliases.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
gp=ROOT/'evidence'/'dependency_graph_va_corrected.json'
if gp.exists():
 graph=json.loads(gp.read_text(encoding='utf-8'))
 graph['selected_call_aliases']=aliases
 graph['remaining_external_symbols']=[x for x in graph.get('remaining_external_symbols',[]) if x not in aliases]
 graph['remaining_after_aliases']=len(graph['remaining_external_symbols'])
 gp.write_text(json.dumps(graph,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'alias_count':len(aliases),'aliases':aliases},indent=2))
