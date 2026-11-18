from __future__ import annotations
import json
from typing import Any
MAX_BYTES=1024*1024; MAX_ROWS=2048
EVENTS={'w3_277_play_smk_entry','w3_277_second_global_load','w3_277_branch_test','w3_277_branch_target'}
def parse(raw:bytes)->list[dict[str,Any]]:
 if len(raw)>MAX_BYTES: raise ValueError('byte cap exceeded')
 lines=raw.splitlines()
 if len(lines)>MAX_ROWS: raise ValueError('row cap exceeded')
 rows=[json.loads(x) for x in lines]
 if any(not isinstance(x,dict) for x in rows): raise ValueError('non-object JSON')
 return rows
def analyze(rows:list[dict[str,Any]])->dict[str,Any]:
 maps=[x for x in rows if x.get('event')=='main_mapping']
 if len(maps)!=1 or maps[0].get('mapping_matches') is not True: raise ValueError('fresh mapping missing/duplicate')
 base=int(maps[0]['code_rebase']); selected=[]
 for x in rows:
  if x.get('event') not in EVENTS: continue
  link=int(x['link_va']); runtime=int(x['runtime_linear']); rebase=int(x['code_rebase'])
  if rebase!=base or runtime-rebase!=link: raise ValueError('runtime mapping mismatch')
  selected.append({'sequence':int(x['sequence']),'event':x['event'],'ordinal':int(x.get('ordinal',0)),'link_va':f'0x{link:08X}','runtime_linear':f'0x{runtime:08X}','cs':f"0x{int(x['cs']):04X}",'eax':f"0x{int(x['eax']):08X}",'ebx':f"0x{int(x['ebx']):08X}",'ecx':f"0x{int(x['ecx']):08X}",'edx':f"0x{int(x['edx']):08X}",'esi':f"0x{int(x['esi']):08X}",'edi':f"0x{int(x['edi']):08X}",'ebp':f"0x{int(x['ebp']):08X}",'esp':f"0x{int(x['esp']):08X}",'eflags':f"0x{int(x['eflags']):08X}"})
 if len(selected)>8: raise ValueError('one-shot event cap exceeded')
 entries=[x for x in selected if x['event']=='w3_277_play_smk_entry']
 load=next((x for x in selected if x['event']=='w3_277_second_global_load'),None)
 branch=next((x for x in selected if x['event']=='w3_277_branch_test'),None)
 dest=next((x for x in selected if x['event']=='w3_277_branch_target'),None)
 return {'code_rebase':f'0x{base:08X}','play_smk_entries':entries,'second_global_load':load,'branch_test':branch,'branch_destination':dest,'second_invocation_path_complete':bool(load and branch and dest and entries and entries[-1]['ordinal']==2 and entries[-1]['sequence']<load['sequence']<branch['sequence']<dest['sequence']),'branch_taken_path':('via_buffer' if dest and dest['link_va']=='0x000AE2E8' else 'direct' if dest and dest['link_va']=='0x000AE2E3' else 'unknown'),'menu_verified':False,'gameplay_verified':False}
