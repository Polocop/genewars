from __future__ import annotations
import hashlib, json, re, os, tempfile
from pathlib import Path
import capstone
from tools.w3_270_post_present_static_frontier import map_le_link_va

ROOT=Path(__file__).resolve().parents[1]
EXE=ROOT/'build/dosboxx_oracle/C/GENEWARS/GW.EXE'
MAP=ROOT/'evidence/genewars-1_1.map'
DISASM=ROOT/'evidence/genewars-1_1-le_disasm.s'
E294=ROOT/'evidence/w3_294_pit_port_capture.json'
E295=ROOT/'evidence/w3_295_video_pit_reconciliation.json'
TARGET_SHA='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
MAP_SHA='30e06c203154904740c4ff3f1fcc4971fb6c0ef10ace2f4f9dc63367d45b99b3'
DISASM_SHA='dcad6dc4e0f836dba0fa0a63664b1e350c05592dc02b2ceeaa4c6788f68d5271'
OUTPUT=ROOT/'evidence/w3_296_pit_routine_static.json'
REPORT=ROOT/'reports/coordination/w3_296_pit_routine_static.md'

def decode(image:bytes,start:int,end:int,required:tuple[int,...]=())->dict:
    if end<=start or end-start>0x200: raise ValueError('static decode window must be <=512 bytes')
    m=map_le_link_va(image,start); raw=image[m['file_offset']:m['file_offset']+end-start]
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    ins=[{'link_va':i.address,'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in cs.disasm(raw,start)]
    if any(not any(x['link_va']==target for x in ins) for target in required): raise ValueError('required target absent from bounded decode')
    return {'start_link_va':start,'end_link_va_exclusive':end,'mapping':m,'raw_bytes':raw.hex(),'instructions':ins}

def named_block(text:str,label:str,stop_labels:tuple[str,...])->list[str]:
    lines=text.splitlines(); start=next((i for i,l in enumerate(lines) if re.match(rf'^\s*{re.escape(label)}:\s*(?:/\*.*)?$',l)),None)
    if start is None: raise ValueError(f'missing label {label}')
    ends=[i for i,l in enumerate(lines[start+1:],start+1) if any(re.match(rf'^\s*{re.escape(stop)}:\s*(?:/\*.*)?$',l) for stop in stop_labels)]
    if not ends: raise ValueError(f'missing end label for {label}')
    return lines[start:ends[0]]

def classify_refs(text:str,name:str)->list[dict]:
    lines=text.splitlines(); out=[]
    for i,line in enumerate(lines):
        if name not in line: continue
        stripped=line.strip()
        if stripped.startswith(name+':'):
            kind='definition'
        elif re.search(r'\bcall\s+\$?'+re.escape(name)+r'\b',stripped,re.I):
            kind='direct_call'
        elif re.search(r'\bpush\s+\$?'+re.escape(name)+r'\b',stripped,re.I):
            kind='address_argument'
        elif re.search(r'\bmov\s+\$?'+re.escape(name)+r'\s*,',stripped,re.I):
            kind='address_load'
        else: kind='other_reference'
        context=' | '.join(x.strip() for x in lines[max(0,i-1):min(len(lines),i+3)])
        out.append({'line_1based':i+1,'text':stripped,'kind':kind,'context':context})
    return out

def build_evidence()->dict:
    image=EXE.read_bytes(); map_raw=MAP.read_bytes(); asm_raw=DISASM.read_bytes()
    hashes={'target_sha256':hashlib.sha256(image).hexdigest(),'map_sha256':hashlib.sha256(map_raw).hexdigest(),'disassembly_sha256':hashlib.sha256(asm_raw).hexdigest()}
    if hashes['target_sha256']!=TARGET_SHA or hashes['map_sha256']!=MAP_SHA or hashes['disassembly_sha256']!=DISASM_SHA: raise ValueError('input hash mismatch')
    asm=asm_raw.decode('utf-8',errors='strict')
    window=decode(image,0xC4180,0xC42F0,(0xC427A,0xC427E,0xC4282,0xC4293,0xC42E0))
    pit_eip_mapping=map_le_link_va(image,0xC427E)
    blocks={}
    stops={'SMACKSOUNDUSEMSS':('func_c4110',),'func_c41c0':('func_c4270',),'func_c4270':('func_c42e0',),'func_c42e0':('func_c42f0',)}
    for label,end_labels in stops.items(): blocks[label]=named_block(asm,label,end_labels)
    refs=classify_refs(asm,'func_c4270')
    smacks='\n'.join(blocks['SMACKSOUNDUSEMSS'])
    init='\n'.join(blocks['func_c41c0'])
    poll='\n'.join(blocks['func_c4270'])
    tick='\n'.join(blocks['func_c42e0'])
    required_patterns={
      'sound_function_stores_poll_pointer':bool(re.search(r'mov\s+%esi,data_10c82c',smacks)) and bool(re.search(r'mov\s+\$func_c4270,%esi',smacks)),
      'timer_registers_tick_function':bool(re.search(r'push\s+\$func_c42e0\s+call\s+_AIL_register_timer',init,re.S)),
      'timer_frequency_and_start':bool(re.search(r'call\s+_AIL_set_timer_frequency',init)) and bool(re.search(r'call\s+_AIL_start_timer',init)),
      'timer_tick_increments_global':bool(re.search(r'incl\s+data_10b974',tick)),
      'poll_function_reads_pit':bool(re.search(r'in\s+\$0x40,%al',poll)) and bool(re.search(r'out\s+%al,\$0x43',poll)),
      'direct_call_reference_absent':not any(x['kind']=='direct_call' for x in refs)
    }
    if not all(required_patterns.values()): raise ValueError(f'static pattern check failed: {required_patterns}')
    recent=json.loads(E294.read_text(encoding='utf-8')); audit=json.loads(E295.read_text(encoding='utf-8'))
    if recent['analysis']['port_event_count']!=0 or recent['guard']['cause']!='TIMEOUT': raise ValueError('W3-294 no longer matches the documented bounded result')
    refs_source=[r for r in refs if r['kind']!='definition']
    return {
      'schema':'w3-296-pit-routine-static/v1','task':'W3-296','evidence_level':'STATIC_ONLY_WITH_ORIGINAL_OBSERVED_LIMIT',
      'input_hashes':hashes,
      'static_only':{
        'target':TARGET_SHA,'map_public_context':{
          'func_c41c0_nearest_public':'SMACKSOUNDUSEMSS at 0xC4050 (naming context only)',
          'func_c4270_nearest_public':'SMACKSOUNDUSEMSS at 0xC4050; SMACKWAIT at 0xC47F0 (naming context only)',
          'function_extent_from_public_map_proven':False},
        'bounded_le_window':window,
        'pit_instruction_mapping':{'link_va':0xC427E,**pit_eip_mapping},
        'labels_and_roles':{
          'SMACKSOUNDUSEMSS':{'label_context':'public MAP symbol at 0xC4050','observations':['sets data_10c82c from address func_c4270','sets data_10c830 from address func_c41c0','per disassembly, function returns after setting these globals']},
          'func_c41c0':{'observations':['passes func_c42e0 to _AIL_register_timer','calls _AIL_set_timer_frequency then _AIL_start_timer','programs PIT through OUT 0x43 and OUT 0x40','polls data_10b974 in a local busy-wait before return']},
          'func_c4270':{'observations':['reads PIT through OUT 0x43 and IN 0x40 at 0xC427E/0xC4282','compares global data_10b974 and branches back to 0xC4272 at 0xC4293','is stored as data_10c82c by SMACKSOUNDUSEMSS; no direct CALL func_c4270 found in checked-in disassembly']},
          'func_c42e0':{'observations':['reads then increments data_10b974 and returns']}
        },
        'func_c4270_references':refs_source,
        'checks':required_patterns,
        'limitations':['This is static disassembly only; no runtime invocation of SMACKSOUNDUSEMSS, func_c41c0, func_c4270, or func_c42e0 is established.','MAP publics are naming context; private function extents and callback ABI are not independently proven.','No original port values, PIT contract, call timing, pixel buffer contents, menu, or gameplay claim.']
      },
      'original_observed_reconciliation':{
        'source_task':'W3-294','run_id':recent['run_id'],'pit_port_event_count':recent['analysis']['port_event_count'],
        'branch_event_count':recent['analysis']['branch_event_count'],'guard_cause':recent['guard']['cause'],
        'last_checkpoint':audit['original_observed']['last_target_runtime_checkpoint']['checkpoint'],
        'last_checkpoint_link_va':hex(audit['original_observed']['last_target_runtime_checkpoint']['link_va']),
        'meaning':'No dynamic evidence that the statically described PIT routines ran before timeout.'
      },
      'conclusion':{'pit_contract_measured':False,'caller_runtime_observed':False,'next_action':'If the original naturally invokes the registered callback, capture the indirect function-pointer call site and its arguments first; do not repeat W3-294 without a new target/seed hypothesis.'}
    }

def write_outputs(data:dict)->None:
    OUTPUT.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    s=data['static_only']; refs=s['func_c4270_references']
    lines=['# W3-296 — static PIT routine context','',
      'Status: static-only analysis complete. It does not provide a measured PIT response or runtime caller.', '',
      '## Hash-bound inputs','',
      f"- GW.EXE SHA-256 `{data['input_hashes']['target_sha256']}`; map SHA-256 `{data['input_hashes']['map_sha256']}`; disassembly SHA-256 `{data['input_hashes']['disassembly_sha256']}`.",
      f"- Bounded LE decode covers 0xC4180-0xC42F0; link 0xC427E maps to file offset `0x{s['pit_instruction_mapping']['file_offset']:X}`.", '',
      '## Static-only findings','',
      '- `SMACKSOUNDUSEMSS` stores address `func_c4270` to `data_10c82c` and `func_c41c0` to `data_10c830` in the disassembly.',
      '- `func_c41c0` registers `func_c42e0` with `_AIL_register_timer`, sets frequency, starts it, programs PIT ports 0x43/0x40, then polls `data_10b974`.',
      '- `func_c42e0` increments `data_10b974`. `func_c4270` reads PIT ports and compares that global, looping at 0xC4293 to 0xC4272.',
      '- Checked disassembly references to `func_c4270` are address storage and VMM lock/unlock range arguments; no direct CALL reference was found. Public MAP labels do not establish private extents or indirect caller.', '',
      '## Original observation boundary','',
      '- W3-294 had zero targeted PIT I/O/branch events and ended at the 45-second guard timeout. Its last captured runtime checkpoint was `VIDEO_FRAMEBUFFER_ASSIGN_AFTER` at 0x9FDF9.',
      '- This does not establish whether the PIT routines ran; no measured PIT contract, pixels, menu, or gameplay follows from this audit.', '',
      '## Next action','',
      data['conclusion']['next_action'],'']
    REPORT.write_text('\n'.join(lines),encoding='utf-8')

if __name__=='__main__':
    e=build_evidence();write_outputs(e);print(json.dumps({'evidence':str(OUTPUT),'report':str(REPORT),'refs':e['static_only']['func_c4270_references'],'checks':e['static_only']['checks']},ensure_ascii=False))
