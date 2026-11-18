from __future__ import annotations
import json
from typing import Any
MAX_BYTES=1024*1024; MAX_ROWS=2048
EVENTS={'w3_278_later_play_smk_entry','w3_278_global_load','w3_278_branch_test','w3_278_branch_target'}
def parse(raw:bytes)->list[dict[str,Any]]:
 if len(raw)>MAX_BYTES: raise ValueError('byte cap exceeded')
 lines=raw.splitlines()
 if len(lines)>MAX_ROWS: raise ValueError('row cap exceeded')
 rows=[json.loads(x) for x in lines]
 if any(not isinstance(x,dict) for x in rows): raise ValueError('non-object JSON')
 return rows
def analyze(rows:list[dict[str,Any]])->dict[str,Any]:
 maps=[r for r in rows if r.get('event')=='main_mapping']
 if len(maps)!=1 or maps[0].get('mapping_matches') is not True: raise ValueError('fresh MAIN mapping missing/duplicate')
 base=int(maps[0]['code_rebase']); selected=[]
 for r in rows:
  if r.get('event') not in EVENTS: continue
  link=int(r['link_va']); runtime=int(r['runtime_linear']); rebase=int(r['code_rebase'])
  if rebase!=base or runtime-rebase!=link: raise ValueError('runtime mapping mismatch')
  selected.append({'sequence':int(r['sequence']),'event':r['event'],'link_va':f'0x{link:08X}','runtime_linear':f'0x{runtime:08X}','cs':f"0x{int(r['cs']):04X}",'eax':f"0x{int(r['eax']):08X}",'ebx':f"0x{int(r['ebx']):08X}",'ecx':f"0x{int(r['ecx']):08X}",'edx':f"0x{int(r['edx']):08X}",'esi':f"0x{int(r['esi']):08X}",'edi':f"0x{int(r['edi']):08X}",'ebp':f"0x{int(r['ebp']):08X}",'esp':f"0x{int(r['esp']):08X}",'eflags':f"0x{int(r['eflags']):08X}"})
 if len(selected)>8: raise ValueError('target event cap exceeded')
 entry=next((x for x in selected if x['event']=='w3_278_later_play_smk_entry'),None)
 load=next((x for x in selected if x['event']=='w3_278_global_load'),None)
 branch=next((x for x in selected if x['event']=='w3_278_branch_test'),None)
 dest=next((x for x in selected if x['event']=='w3_278_branch_target'),None)
 order=bool(entry and load and branch and dest and entry['sequence']<load['sequence']<branch['sequence']<dest['sequence'])
 path='via_buffer' if dest and dest['link_va']=='0x000AE2E8' else 'direct' if dest and dest['link_va']=='0x000AE2E3' else 'unknown'
 expected=['w3_278_later_play_smk_entry','w3_278_global_load','w3_278_branch_test','w3_278_branch_target']
 seen={x['event'] for x in selected}
 last=rows[-1] if rows else {}
 return {'code_rebase':f'0x{base:08X}','runtime_mapping_validated':True,'later_entry_seen':entry is not None,'global_value_ecx':load['ecx'] if load else None,'test_flags':branch['eflags'] if branch else None,'branch_destination':dest['link_va'] if dest else None,'branch_path':path,'ordered':order,'branch_capture_complete':order,'missing_events':[name for name in expected if name not in seen],'selected_events':selected,'last_trace_record':{'sequence':last.get('sequence'),'event':last.get('event'),'link_va':f"0x{int(last['link_va']):08X}" if 'link_va' in last else None},'game_call_94347_seen':any(r.get('event')=='w3_269_game_transition_checkpoint' and int(r.get('link_va',-1))==0x94347 for r in rows),'game_entry_92710_seen':any(r.get('event')=='w3_269_game_transition_checkpoint' and int(r.get('link_va',-1))==0x92710 for r in rows),'menu_verified':False,'gameplay_verified':False}
