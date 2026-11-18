from __future__ import annotations
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MAP=ROOT/'evidence/genewars-1_1.map'
SOURCE=ROOT/'evidence/w3_272_post_media_static_followthrough.json'
OUTPUT=ROOT/'evidence/w3_273_post_media_symbol_context.json'
REPORT=ROOT/'reports/coordination/w3_273_post_media_symbol_context.md'
EXPECTED_MAP_SHA256='30e06c203154904740c4ff3f1fcc4971fb6c0ef10ace2f4f9dc63367d45b99b3'
TARGETS=(0x5B880,0x92996,0x929D0,0x92ADD,0x92AE2)

def parse_publics(text:str)->dict[int,str]:
 out={}
 for line in text.splitlines():
  fields=line.split()
  if len(fields)>=2 and fields[0].startswith('0001:'):
   try: out[int(fields[0].split(':',1)[1],16)]=fields[1]
   except ValueError: pass
 return out

def nearest(publics:dict[int,str],target:int)->dict:
 keys=sorted(publics)
 lower=[x for x in keys if x<=target]
 upper=[x for x in keys if x>target]
 return {'exact_symbol':publics.get(target),'nearest_lower':{'link_va':f'0x{lower[-1]:08X}','name':publics[lower[-1]]} if lower else None,'nearest_upper':{'link_va':f'0x{upper[0]:08X}','name':publics[upper[0]]} if upper else None}

def build()->dict:
 raw=MAP.read_bytes(); digest=hashlib.sha256(raw).hexdigest()
 if digest!=EXPECTED_MAP_SHA256: raise ValueError('MAP hash mismatch')
 publics=parse_publics(raw.decode('utf-8',errors='replace'))
 source=json.loads(SOURCE.read_text(encoding='utf-8'))
 locations={f'0x{x:08X}':nearest(publics,x) for x in TARGETS}
 return {'schema':'w3-273-post-media-symbol-context/v1','task':'W3-273','evidence_level':'ORIGINAL_OBSERVED_AND_STATIC_ONLY','map_sha256':digest,'source_task':'W3-272','source_trace_sha256':source['trace_sha256'],'dynamic_checkpoints':source['original_observed_order'],'map_locations':locations,'static_calls':{'0x00092AE2':'CALL 0x0005B880','0x00092996':'CALL 0x000929D0','0x000929A9':'CALL 0x000929D0','0x00094347':'CALL 0x00092710'},'limits':['MAP labels identify public symbols only; nearest public does not prove function extent.','Static direct calls are not evidence that the callee executed in the original run.','The 0x92AE2 checkpoint is a call-return boundary; media completion, menu, gameplay, and native parity remain unproven.']}

def main():
 d=build(); OUTPUT.write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
 lines=['# W3-273 — MAP labels around the observed post-present checkpoints','','Evidence level: ORIGINAL_OBSERVED_AND_STATIC_ONLY. No Oracle execution.','',f"- MAP SHA-256: `{d['map_sha256']}`.",f"- Source trace SHA-256: `{d['source_trace_sha256']}`.",'','## Dynamic checkpoints (from W3-271)']
 for x in d['dynamic_checkpoints']: lines.append(f"- seq {x['sequence']}: {x['link_va']} runtime {x['runtime_linear']}, CS {x['cs']}, EFLAGS {x['eflags']}.")
 lines += ['', '## Public symbol context']
 for address,info in d['map_locations'].items(): lines.append(f"- {address}: exact MAP label `{info['exact_symbol']}`; nearest lower/upper publics are naming context only: {info['nearest_lower']} / {info['nearest_upper']}.")
 lines += ['', '## Static call observations']
 for a,b in d['static_calls'].items(): lines.append(f'- `{a}` decodes as `{b}` in the bounded exact-target byte window.')
 lines += ['', '## Limits']+[f'- {x}' for x in d['limits']]+['']
 REPORT.parent.mkdir(parents=True,exist_ok=True); REPORT.write_text('\n'.join(lines),encoding='utf-8')
 print(json.dumps({'evidence':str(OUTPUT),'report':str(REPORT),'map_sha256':d['map_sha256']},indent=2))
if __name__=='__main__':main()
