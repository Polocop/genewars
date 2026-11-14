from __future__ import annotations
import hashlib,json,re
from pathlib import Path
import capstone
from tools.w3_270_post_present_static_frontier import map_le_link_va
ROOT=Path(__file__).resolve().parents[1]
EXE=ROOT/'build/dosboxx_oracle/C/GENEWARS/GW.EXE'; MAP=ROOT/'evidence/genewars-1_1.map'; ASM=ROOT/'evidence/genewars-1_1-le_disasm.s'
FIXTURE=ROOT/'build/dosboxx_oracle/C/GENEWARS'
CLONE=ROOT/'evidence/w3_067_functional_clone_20261008.json'; VALID=ROOT/'evidence/w3_067_staging_functional_validation_20261008.json'
E294=ROOT/'evidence/w3_294_pit_port_capture.json'
TARGET_SHA='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'; MAP_SHA='30e06c203154904740c4ff3f1fcc4971fb6c0ef10ace2f4f9dc63367d45b99b3'; ASM_SHA='dcad6dc4e0f836dba0fa0a63664b1e350c05592dc02b2ceeaa4c6788f68d5271'
OUTPUT=ROOT/'evidence/w3_297_sound_gate_static.json'; REPORT=ROOT/'reports/coordination/w3_297_sound_gate_static.md'
INI_PATHS={'CONFIG.INI':FIXTURE/'CONFIG.INI','SOUND.INI':FIXTURE/'SOUND.INI','DIG.INI':FIXTURE/'SOUND/DIG.INI','MDI.INI':FIXTURE/'SOUND/MDI.INI'}

def decode(image:bytes,start:int,end:int,required:tuple[int,...]=())->dict:
 if not start<end or end-start>0x200: raise ValueError('decode window must be <=512 bytes')
 m=map_le_link_va(image,start); raw=image[m['file_offset']:m['file_offset']+end-start]
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
 ins=[{'link_va':i.address,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(raw,start)]
 if any(not any(x['link_va']==v for x in ins) for v in required): raise ValueError('required VA not decoded')
 return {'start_link_va':start,'end_link_va_exclusive':end,'mapping':m,'instructions':ins,'raw_bytes':raw.hex()}

def gate_predicate(local_flag:int,driver_eax:int)->str:
 if local_flag&1: return 'take local-bit-0 setup-skip branch before GetSoundDriver_'
 if driver_eax==0: return 'take setup-skip branch after GetSoundDriver_ returns zero'
 return 'fall through to second GetSoundDriver_ and SMACKSOUNDUSEMSS call'

def build_evidence()->dict:
 image=EXE.read_bytes(); map_raw=MAP.read_bytes(); asm_raw=ASM.read_bytes()
 hs={'target_sha256':hashlib.sha256(image).hexdigest(),'map_sha256':hashlib.sha256(map_raw).hexdigest(),'disassembly_sha256':hashlib.sha256(asm_raw).hexdigest()}
 if hs!={'target_sha256':TARGET_SHA,'map_sha256':MAP_SHA,'disassembly_sha256':ASM_SHA}: raise ValueError('hash-bound input mismatch')
 clone=json.loads(CLONE.read_text(encoding='utf-8')); valid=json.loads(VALID.read_text(encoding='utf-8')); run=json.loads(E294.read_text(encoding='utf-8'))
 if clone['clone']['all_source_paths_sizes_hashes_match'] is not True or clone['source_copy']['all_source_paths_sizes_hashes_match'] is not True: raise ValueError('W3-067 fixture provenance manifest failed')
 if valid['runtime']['guest_errors']['CONFIG_INI_sha256']!='e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798' or valid['runtime']['guest_errors']['SOUND_INI_sha256']!='339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3': raise ValueError('W3-067 key INI fixture hashes changed')
 ini={}
 for name,path in INI_PATHS.items():
  b=path.read_bytes(); ini[name]={'path':str(path.relative_to(ROOT)).replace('\\','/'),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'source_identity_basis':'W3-067 complete path/size/hash clone manifest'}
 expected={'CONFIG.INI':valid['runtime']['guest_errors']['CONFIG_INI_sha256'],'SOUND.INI':valid['runtime']['guest_errors']['SOUND_INI_sha256']}
 for n,h in expected.items():
  if ini[n]['sha256']!=h: raise ValueError(f'{n} hash mismatch against functional fixture evidence')
 ini['CONFIG.INI']['text']=INI_PATHS['CONFIG.INI'].read_text(encoding='ascii')
 ini['SOUND.INI']['interpretation']='11-byte binary-like content; not treated as text or parsed as a sound toggle'
 ini['DIG.INI']['selected_text']=INI_PATHS['DIG.INI'].read_text(encoding='ascii',errors='replace')
 ini['MDI.INI']['selected_text']=INI_PATHS['MDI.INI'].read_text(encoding='ascii',errors='replace')
 windows={
  'play_smk_direct':decode(image,0xAE308,0xAE368,(0xAE32D,0xAE32F,0xAE339)),
  'play_smk_via_buffer':decode(image,0xAE4D8,0xAE538,(0xAE4FD,0xAE4FF,0xAE509)),
  'smack_sound_use_mss':decode(image,0xC4050,0xC4130,(0xC4050,0xC4057,0xC40D0)),
  'first_callback_use':decode(image,0xC4600,0xC4640,(0xC4600,0xC460A))
 }
 asm=asm_raw.decode('utf-8'); refs={name:[i+1 for i,l in enumerate(asm.splitlines()) if name in l] for name in ('SMACKSOUNDUSEMSS','data_10c82c','data_10c830')}
 # Precise disassembly clauses are reconciled with the target bytes by bounded Capstone windows.
 gate={'tested_register':'EAX','producer':'first GetSoundDriver_ call at each play_smk entry','zero_branch':'JE to local setup-skip block','nonzero_path':'second GetSoundDriver_ call then SMACKSOUNDUSEMSS','additional_condition':'local byte bit 0 set branches to setup-skip before GetSoundDriver_','meaning_of_nonzero':'UNKNOWN; no semantic interpretation assigned'}
 if run['analysis']['port_event_count']!=0 or run['guard']['cause']!='TIMEOUT': raise ValueError('W3-294 negative boundary changed')
 return {'schema':'w3-297-sound-gate-static/v1','task':'W3-297','evidence_level':'STATIC_ONLY_WITH_ORIGINAL_OBSERVED_LIMIT',
  'input_hashes':hs,
  'fixture_ini':{'manifest_path':'evidence/w3_067_functional_clone_20261008.json','manifest_sha256':hashlib.sha256(CLONE.read_bytes()).hexdigest(),'all_source_path_size_hashes_match':True,'files':ini},
  'static_only':{'windows':windows,'asm_reference_line_numbers':refs,'gate':gate,
   'findings':{'play_smk_direct_calls_sound_setup':True,'play_smk_via_buffer_calls_sound_setup':True,'sound_setup_stores_func_c4270_callback':True,'func_c4600_indirectly_calls_data_10c82c':True,'callback_runtime_invocation_proven':False},
   'hypothesis':'A natural PIT callback capture should be armed at the existing GetSoundDriver_ gate and SMACKSOUNDUSEMSS store, then at func_c4600 call *data_10c82c; these points distinguish sound setup from later callback use. This is a new target plan, not evidence that the path ran.',
   'limitations':['CONFIG.INI Sounds=All is an observed setting, not proof GetSoundDriver_ returns nonzero.','SOUND.INI is binary-like and no semantics are assigned.','DIG/MDI profiles and loaded SOUND.DAT do not prove SMACKSOUNDUSEMSS or func_c4270 executed.','No W3-294 PIT port/branch events occurred before timeout.']},
  'original_observed_reconciliation':{'source_task':'W3-294','run_id':run['run_id'],'pit_event_count':run['analysis']['port_event_count'],'branch_event_count':run['analysis']['branch_event_count'],'guard_cause':run['guard']['cause'],'last_checkpoint':run['analysis']['supplemental_observations']['last_target_runtime_checkpoint']['checkpoint'],'last_checkpoint_link_va':run['analysis']['supplemental_observations']['last_target_runtime_checkpoint']['link_va_hex']},
  'conclusion':{'sound_gate_result_original':'NOT_CAPTURED','callback_invocation_original':'NOT_CAPTURED','new_bounded_hypothesis':'Capture both play_smk setup gate and first indirect data_10c82c call in one future guarded run; only if a distinct new task and available oracle locks permit.','no_replay_performed':True}}

def write(data:dict)->None:
 OUTPUT.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 s=data['static_only']; i=data['fixture_ini']['files'];g=s['gate']
 lines=['# W3-297 — Smacker sound gate and PIT callback registration','',
  'Status: static-only; no game replay, build, guest modification, or sound-contract claim.','',
  '## Fixture and hashes','',
  f"- Target GW.EXE SHA-256 `{data['input_hashes']['target_sha256']}`; MAP `{data['input_hashes']['map_sha256']}`; disassembly `{data['input_hashes']['disassembly_sha256']}`.",
  f"- Fixture clone manifest confirms all source paths/sizes/hashes matched. CONFIG.INI SHA-256 `{i['CONFIG.INI']['sha256']}`; SOUND.INI `{i['SOUND.INI']['sha256']}`; DIG.INI `{i['DIG.INI']['sha256']}`; MDI.INI `{i['MDI.INI']['sha256']}`.",
  '- CONFIG.INI says `Sounds="All"`. SOUND.INI is 11 bytes and binary-like; DIG.INI and MDI.INI are preserved as text observations, not interpreted as proof of runtime callback use.','',
  '## Static control/data flow','',
  '- Both `play_smk_direct` (0xAE308) and `play_smk_via_buffer` (0xAE4D8) test a local byte bit 0, call `GetSoundDriver_`, test EAX, and skip sound setup on zero. A nonzero value leads to a second `GetSoundDriver_` call and `SMACKSOUNDUSEMSS`. The local bit meaning is not assigned.',
  '- The meaning of nonzero is not inferred. The path is static; no dynamic branch state was captured.',
  '- `SMACKSOUNDUSEMSS` stores `func_c4270` in `data_10c82c`. `func_c4600` later calls `data_10c82c` indirectly. The original callback invocation remains unobserved.',
  '- W3-294 recorded zero PIT events before the guard timeout, so these branches are a new, narrower target hypothesis, not a reinterpretation of that run.','',
  '## Next exact observation','',
  'In one future protected run, capture the first natural `play_smk_direct`/`play_smk_via_buffer` gate, the actual `SMACKSOUNDUSEMSS` store, and first `func_c4600` indirect call; arm PIT I/O capture only after proving the callback value and fresh MAIN mapping. This requires a separately authorized bounded task.','']
 REPORT.write_text('\n'.join(lines),encoding='utf-8')

if __name__=='__main__':
 e=build_evidence();write(e);print(json.dumps({'evidence':str(OUTPUT),'report':str(REPORT),'ini_hashes':{k:v['sha256'] for k,v in e['fixture_ini']['files'].items()},'gate':e['static_only']['gate']},ensure_ascii=False))
