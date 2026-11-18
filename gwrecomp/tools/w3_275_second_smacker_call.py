from __future__ import annotations
import json
from typing import Any
MAX_BYTES=1024*1024
MAX_ROWS=2048
REQUIRED=('0x000929D0','0x00092ADD','0x000AE2D0','0x00092AE2')
def parse_bounded(raw:bytes)->list[dict[str,Any]]:
 if len(raw)>MAX_BYTES: raise ValueError('trace exceeds byte cap')
 lines=raw.splitlines()
 if len(lines)>MAX_ROWS: raise ValueError('trace exceeds row cap')
 out=[]
 for n,line in enumerate(lines,1):
  row=json.loads(line)
  if not isinstance(row,dict): raise ValueError(f'row {n} is not an object')
  out.append(row)
 return out
def analyze(rows:list[dict[str,Any]])->dict[str,Any]:
 mappings=[r for r in rows if r.get('event')=='main_mapping']
 if len(mappings)!=1 or mappings[0].get('mapping_matches') is not True: raise ValueError('fresh MAIN mapping missing or duplicate')
 base=int(mappings[0]['code_rebase'])
 selected=[]
 names={'w3_269_game_transition_checkpoint','w3_275_second_smacker_entry','w3_275_second_smacker_callsite','w3_275_second_smacker_media_entry','w3_275_second_smacker_return'}
 for r in rows:
  if r.get('event') not in names: continue
  link=int(r['link_va']); runtime=int(r.get('runtime_linear',r.get('eip',-1))); rebase=int(r.get('code_rebase',base))
  if rebase!=base or runtime-rebase!=link: raise ValueError('runtime mapping mismatch')
  selected.append({'sequence':int(r['sequence']),'event':r['event'],'link_va':f'0x{link:08X}','runtime_linear':f'0x{runtime:08X}','cs':f"0x{int(r['cs']):04X}",'eflags':f"0x{int(r['eflags']):08X}"})
 if len(selected)>16: raise ValueError('target event cap exceeded')
 entry=next((x for x in selected if x['event']=='w3_269_game_transition_checkpoint' and x['link_va']=='0x000929D0'),None)
 call=next((x for x in selected if x['event']=='w3_275_second_smacker_callsite'),None)
 media=next((x for x in selected if x['event']=='w3_275_second_smacker_media_entry'),None)
 ret=next((x for x in selected if x['event']=='w3_275_second_smacker_return'),None)
 order=bool(entry and call and entry['sequence']<call['sequence'] and (not media or call['sequence']<media['sequence']) and (not ret or media and media['sequence']<ret['sequence']))
 return {'code_rebase':f'0x{base:08X}','entry_929d0_seen':entry is not None,'second_callsite_92add_seen':call is not None,'second_external_entry_ae2d0_seen':media is not None,'second_return_92ae2_seen':ret is not None,'ordered':order,'selected_events':selected,'game_call_94347_seen':any(x['link_va']=='0x00094347' for x in selected),'game_entry_92710_seen':any(x['link_va']=='0x00092710' for x in selected),'menu_verified':False,'gameplay_verified':False}
