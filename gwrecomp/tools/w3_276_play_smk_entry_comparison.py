from __future__ import annotations
import hashlib,json
from pathlib import Path
from tools.w3_270_post_present_static_frontier import map_le_link_va
ROOT=Path(__file__).resolve().parents[1]
EXE=ROOT/'build/dosboxx_oracle/C/GENEWARS/GW.EXE'
MAP=ROOT/'evidence/genewars-1_1.map'
TRACE_FIRST=ROOT/'build/dosboxx_oracle/C/W3_118_PLAYSMACKER_CALL_20261009_01.jsonl'
TRACE_SECOND=ROOT/'build/dosboxx_oracle/C/W3_275_SECOND_SMACKER_20261009_01.jsonl'
FIRST_SHA='df994f6495c7f8d0f55e78096d7eec9f98f34dd5050711f8d41069a33c8da6ef'
SECOND_SHA='0233d201a94e335381a053f57be200fcd261a64b29f11912f63c70f4d21ac4c3'
TARGET_SHA='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
OUTPUT=ROOT/'evidence/w3_276_play_smk_entry_comparison.json'
REPORT=ROOT/'reports/coordination/w3_276_play_smk_entry_comparison.md'
def read_rows(path,expected):
 raw=path.read_bytes()
 if len(raw)>1024*1024 or len(raw.splitlines())>2048 or hashlib.sha256(raw).hexdigest()!=expected: raise ValueError(f'bounded trace hash/size invalid: {path.name}')
 return [json.loads(x) for x in raw.splitlines()]
def compare(first:dict,second:dict)->dict:
 fields=('eax','ebx','ecx','edx','esi','edi','ebp','esp','eflags','cs')
 common={k:{'first':first[k],'second':second[k],'equal':first[k]==second[k]} for k in fields if k in first and k in second}
 return {'common_fields':common,'different_fields':[k for k,v in common.items() if not v['equal']]}
def build():
 if hashlib.sha256(EXE.read_bytes()).hexdigest()!=TARGET_SHA: raise ValueError('exact target hash mismatch')
 first_rows=read_rows(TRACE_FIRST,FIRST_SHA); second_rows=read_rows(TRACE_SECOND,SECOND_SHA)
 first=next(r for r in first_rows if r.get('event')=='target_runtime_checkpoint' and r.get('checkpoint')=='W3_117_PLAYSMACKER_CALLEE_ENTRY')
 second=next(r for r in second_rows if r.get('event')=='w3_275_second_smacker_media_entry')
 if first.get('link_va')!=0xAE2D0 or second.get('link_va')!=0xAE2D0: raise ValueError('observed callee entry VA differs')
 static=EXE.read_bytes(); start=0xAE2D0; end=0xAE308; mapping=map_le_link_va(static,start); chunk=static[mapping['file_offset']:mapping['file_offset']+end-start]
 import capstone
 decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
 decoded=[{'link_va':f'0x{i.address:08X}','bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in decoder.disasm(chunk,start)]
 return {'schema':'w3-276-play-smk-entry-comparison/v1','task':'W3-276','evidence_level':'ORIGINAL_OBSERVED_AND_STATIC_ONLY','target_sha256':TARGET_SHA,'map_sha256':hashlib.sha256(MAP.read_bytes()).hexdigest(),'first_trace_sha256':FIRST_SHA,'second_trace_sha256':SECOND_SHA,'first_entry':{k:first.get(k) for k in ('sequence','link_va','eip','cs','eax','ebx','ecx','edx','esi','edi','ebp','esp','eflags','stack_words_u32','elapsed_ms') if k in first},'second_entry':{k:second.get(k) for k in ('sequence','link_va','runtime_linear','code_rebase','cs','eax','ebx','ecx','edx','esi','edi','ebp','esp','eflags') if k in second},'register_comparison':compare(first,second),'static_entry_bytes':{'start':f'0x{start:08X}','end_exclusive':f'0x{end:08X}','file_offset':f"0x{mapping['file_offset']:X}",'bytes':chunk.hex(),'disassembly':decoded},'limits':['Only common captured registers are compared; second entry has no stack sample.','Register differences do not prove which argument or memory field controls the timeout.','The later call return was not observed; no media completion or game-entry claim.']}
def main():
 d=build(); OUTPUT.write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')
 lines=['# W3-276 — compare first and later play_smk_ entries','','Evidence level: ORIGINAL_OBSERVED_AND_STATIC_ONLY. No Oracle replay.','',f"- Exact target SHA-256: `{d['target_sha256']}`.",f"- First trace SHA-256: `{d['first_trace_sha256']}`.",f"- Later trace SHA-256: `{d['second_trace_sha256']}`.",'', '## Entry register comparison']
 for k,v in d['register_comparison']['common_fields'].items(): lines.append(f"- {k.upper()}: first `{v['first']}`; later `{v['second']}`; equal `{v['equal']}`.")
 lines += ['', '## Static bytes at play_smk_ entry']
 for ins in d['static_entry_bytes']['disassembly']: lines.append(f"- `{ins['link_va']}` `{ins['bytes']}`: `{ins['mnemonic']} {ins['operands']}`")
 lines += ['', '## Limits']+[f'- {x}' for x in d['limits']]+['']
 REPORT.parent.mkdir(parents=True,exist_ok=True); REPORT.write_text('\n'.join(lines),encoding='utf-8')
 print(json.dumps({'evidence':str(OUTPUT),'report':str(REPORT),'different_fields':d['register_comparison']['different_fields']},indent=2))
if __name__=='__main__':main()
