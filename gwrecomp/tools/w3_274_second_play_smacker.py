from __future__ import annotations
import json
from typing import Any
MAX_BYTES=1024*1024
MAX_ROWS=2048
TARGETS={0x92996,0x929D0,0x92AE2,0x94347,0x92710}
def parse_bounded(raw:bytes)->list[dict[str,Any]]:
 if len(raw)>MAX_BYTES: raise ValueError('trace exceeds byte cap')
 lines=raw.splitlines()
 if len(lines)>MAX_ROWS: raise ValueError('trace exceeds row cap')
 rows=[]
 for n,line in enumerate(lines,1):
  row=json.loads(line)
  if not isinstance(row,dict): raise ValueError(f'row {n} is not an object')
  rows.append(row)
 return rows
def analyze(rows:list[dict[str,Any]])->dict[str,Any]:
 mappings=[r for r in rows if r.get('event')=='main_mapping']
 markers=[r for r in rows if r.get('event')=='w3_269_first_guest_checkpoint_after_present']
 if len(mappings)>1 or len(markers)>1: raise ValueError('duplicate mapping or present marker')
 mapping=mappings[0] if mappings else None
 base=int(mapping['code_rebase']) if mapping else None
 if mapping and mapping.get('mapping_matches') is not True: raise ValueError('MAIN mapping invalid')
 checkpoints=[]
 for row in rows:
  if row.get('event')!='w3_269_game_transition_checkpoint': continue
  link=int(row['link_va']); runtime=int(row['runtime_linear']); rebase=int(row['code_rebase'])
  if link not in TARGETS: continue
  if base is None or rebase!=base or runtime-rebase!=link: raise ValueError('target runtime mapping mismatch')
  checkpoints.append({'sequence':int(row['sequence']),'link_va':f'0x{link:08X}','runtime_linear':f'0x{runtime:08X}','cs':f"0x{int(row['cs']):04X}",'eflags':f"0x{int(row['eflags']):08X}"})
 unique=[x['link_va'] for x in checkpoints]
 return {'main_mapping_seen':mapping is not None,'code_rebase':f'0x{base:08X}' if base is not None else None,'post_present_checkpoint_seen':markers!=[],'target_checkpoints':checkpoints,'callsite_92996_seen':'0x00092996' in unique,'play_smacker_entry_929d0_seen':'0x000929D0' in unique,'external_call_return_92ae2_seen':'0x00092AE2' in unique,'game_call_94347_seen':'0x00094347' in unique,'game_entry_92710_seen':'0x00092710' in unique,'menu_verified':False,'gameplay_verified':False}
