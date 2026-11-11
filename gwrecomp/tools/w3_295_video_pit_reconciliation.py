from __future__ import annotations
import hashlib, json
from pathlib import Path
from tools.w3_270_post_present_static_frontier import map_le_link_va
import capstone

ROOT=Path(__file__).resolve().parents[1]
EXE=ROOT/'build/dosboxx_oracle/C/GENEWARS/GW.EXE'
TRACE=ROOT/'build/dosboxx_oracle/C/W3_294_PIT_PORT_20261010_01.jsonl'
TRACE269=ROOT/'build/dosboxx_oracle/C/W3_269_POST_PRESENT_20261009_01.jsonl'
E294=ROOT/'evidence/w3_294_pit_port_capture.json'
E269=ROOT/'evidence/w3_269_post_present_checkpoint.json'
E270=ROOT/'evidence/w3_270_post_present_static_frontier.json'
GUARD294=ROOT/'evidence/oracle_runs/oracle_runs_w3-294-pit-port-20261010-01.json'
TARGET_SHA='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
OUTPUT=ROOT/'evidence/w3_295_video_pit_reconciliation.json'
REPORT=ROOT/'reports/coordination/w3_295_video_pit_reconciliation.md'
MAX_TRACE_BYTES=1024*1024
MAX_TRACE_ROWS=4096

def decode_window(image: bytes, start: int, end: int, required: tuple[int,...]=()) -> dict:
    if end <= start or end-start > 0x200:
        raise ValueError('decode window must be positive and <=512 bytes')
    mapping=map_le_link_va(image,start)
    raw=image[mapping['file_offset']:mapping['file_offset']+end-start]
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    rows=[{'link_va':ins.address,'bytes':ins.bytes.hex(),'mnemonic':ins.mnemonic,'operands':ins.op_str} for ins in decoder.disasm(raw,start)]
    if not rows or any(not any(r['link_va']==va for r in rows) for va in required):
        raise ValueError('required target not decoded')
    return {'start_link_va':start,'end_link_va_exclusive':end,'mapping':mapping,'bytes':raw.hex(),'instructions':rows}

def parse_trace(raw: bytes, max_bytes: int=MAX_TRACE_BYTES, max_rows: int=MAX_TRACE_ROWS) -> list[dict]:
    if len(raw)>max_bytes:
        raise ValueError('trace byte cap exceeded')
    rows=[]
    for line in raw.splitlines():
        if not line.strip(): continue
        rows.append(json.loads(line))
        if len(rows)>max_rows: raise ValueError('trace row cap exceeded')
    return rows

def summarize(rows: list[dict]) -> dict:
    mappings=[r for r in rows if r.get('event')=='main_mapping']
    checkpoints=[r for r in rows if r.get('event')=='target_runtime_checkpoint']
    port_events=[r for r in rows if r.get('event')=='W3_294_PIT_PORT']
    branch_events=[r for r in rows if r.get('event')=='W3_294_PIT_BRANCH']
    api=[r for r in rows if r.get('event')=='setup_dos_api']
    if len(mappings)!=1: raise ValueError('expected one fresh MAIN mapping')
    last=rows[-1] if rows else None
    return {'mapping':mappings[0], 'checkpoint_count':len(checkpoints),
            'last_runtime_checkpoint':checkpoints[-1] if checkpoints else None,
            'port_events':port_events,'branch_events':branch_events,
            'api_event_count':len(api),'last_api_event':api[-1] if api else None,
            'last_trace_event':last}

def build_evidence() -> dict:
    image=EXE.read_bytes()
    sha=hashlib.sha256(image).hexdigest()
    if sha!=TARGET_SHA: raise ValueError('target hash mismatch')
    run=json.loads(E294.read_text(encoding='utf-8'))
    post=json.loads(E269.read_text(encoding='utf-8'))
    frontier=json.loads(E270.read_text(encoding='utf-8'))
    raw=TRACE.read_bytes()
    rows=parse_trace(raw)
    trace_sha=hashlib.sha256(raw).hexdigest()
    if trace_sha!=run['trace']['sha256'] or len(rows)!=run['trace']['row_count']:
        raise ValueError('W3-294 raw trace differs from its capture manifest')
    if run['provenance']['target_sha256']!=sha or run['analysis']['fresh_main_mapping']['mapping_matches'] is not True:
        raise ValueError('capture target/mapping provenance invalid')
    summary=summarize(rows)
    raw269=TRACE269.read_bytes()
    if hashlib.sha256(raw269).hexdigest()!=post['trace']['sha256']:
        raise ValueError('W3-269 raw trace differs from its capture manifest')
    guard294=json.loads(GUARD294.read_text(encoding='utf-8'))
    stderr294=guard294.get('stderr_tail','')
    if 'VESA 640x480 256-colour graphics mode 101h' not in stderr294:
        raise ValueError('W3-294 Staging log does not contain the recorded VESA mode line')
    mapping=summary['mapping']
    if mapping['link_va'] != 0xAF96C or mapping['code_rebase'] != 0x1EB000:
        raise ValueError('unexpected fresh MAIN mapping')
    pit=decode_window(image,0xC4270,0xC4295,(0xC427A,0xC427E,0xC4282,0xC4293))
    video=decode_window(image,0x9FDC0,0x9FE20,(0x9FDF9,))
    next_guest=post.get('analysis',{}).get('first_guest_link_va')
    if next_guest!='0x000C427E': raise ValueError('W3-269 successor checkpoint changed')
    w270=frontier.get('static_only',{})
    if w270.get('target_sha256')!=sha or w270.get('link_va')!='0x000C427E':
        raise ValueError('W3-270 static evidence target mismatch')
    if summary['port_events'] or summary['branch_events']:
        loop='PIT targeted event appeared; reconcile event schema before classifying'
    else:
        loop='No W3-294 PIT port or branch event in the bounded trace; loop not dynamically observed'
    fb=summary['last_runtime_checkpoint']
    return {
      'schema':'w3-295-video-pit-reconciliation/v1','task':'W3-295','evidence_level':'ORIGINAL_OBSERVED_AND_STATIC_ONLY',
      'original_observed':{
        'run_id':run['run_id'],'guard':run['guard'],'target_sha256':sha,
        'fixture_sha256':run['provenance']['target_sha256'],'config_sha256':run['provenance']['config_sha256'],
        'cue_sha256':run['provenance']['cue_sha256'],'cue_read_only':run['provenance']['cue_read_only'],
        'instrumented_binary_sha256':run['provenance']['instrumented_binary_sha256'],
        'trace':{'path':str(TRACE.relative_to(ROOT)).replace('\\','/'),'bytes':len(raw),'rows':len(rows),'sha256':trace_sha},
        'staging_log':{'source_path':str(GUARD294.relative_to(ROOT)).replace('\\','/'),'guard_json_sha256':hashlib.sha256(GUARD294.read_bytes()).hexdigest(),'stderr_tail_sha256':hashlib.sha256(stderr294.encode('utf-8')).hexdigest(),'vesa_101_line_verified':True},
        'fresh_main_mapping':mapping,'last_target_runtime_checkpoint':fb,
        'setup_dos_api_count':summary['api_event_count'],'last_setup_dos_api':summary['last_api_event'],
        'last_emitted_trace_event':summary['last_trace_event'],
        'pit_event_count':len(summary['port_events']),'branch_event_count':len(summary['branch_events']),
        'display_log':'VESA 640x480 256-colour mode 101h logged by Staging; no pixel sample in this run',
        'guest_pixels_verified':False,'menu_verified':False,'gameplay_verified':False,
        'interpretation':loop
      },
      'cross_run_comparison':{
        'w3_269_run_id':post['run_id'],'w3_269_trace_sha256':post['trace']['sha256'],
        'w3_269_raw_trace_sha256_revalidated':hashlib.sha256(raw269).hexdigest(),
        'w3_269_next_guest_checkpoint':next_guest,
        'w3_270_static_frontier':{'link_va':w270['link_va'],'file_offset':w270['le_mapping']['file_offset'],'bytes':w270['file_bytes_at_link_va'],'branch':next(i for i in w270['disassembly_from_0xC4270'] if i['link_va']=='0x000C4293')},
        'same_run':False,'binary_or_source_equivalence_established':False,
        'interpretation':'W3-269 observed the next guest dispatch at C427E in its own run after a completed present. W3-294 instead timed out after its VIDEO_FRAMEBUFFER_ASSIGN_AFTER checkpoint. These separate runs do not establish a causal transition or timing equivalence.'
      },
      'static_only':{
        'video_checkpoint_window':video,
        'pit_loop_window':pit,
        'relation_between_video_checkpoint_and_pit_loop':'UNKNOWN: bounded local decoding shows no proven path between these distant link-VA windows; no function-level or dynamic call-chain proof is present',
        'limitations':['The framebuffer global sample is not proven to be a usable pixel buffer.','VESA mode logging is not pixel-backed output validation.','The W3-294 replay ended by guard timeout; it does not show that DOSBox or GeneWars terminated naturally.','Different replay binaries/runs prevent causal attribution from W3-269 to W3-294.']
      },
      'input_artifact_sha256':{
        'w3_294_evidence':hashlib.sha256(E294.read_bytes()).hexdigest(),
        'w3_269_evidence':hashlib.sha256(E269.read_bytes()).hexdigest(),
        'w3_270_evidence':hashlib.sha256(E270.read_bytes()).hexdigest(),
        'w3_294_raw_trace':trace_sha,
        'w3_269_raw_trace':hashlib.sha256(raw269).hexdigest(),
        'target_image':sha,
        'w3_294_guard_record':hashlib.sha256(GUARD294.read_bytes()).hexdigest()
      },
      'conclusion':{'pit_contract_observed':False,'first_pixel_backed_framebuffer_in_this_run':False,'next_action':'Use only offline call-graph/disassembly evidence to identify the path between the observed 0x9FDF9 checkpoint and the measured C427E loop; any new replay requires a distinct evidence-backed hypothesis.'}
    }

def write_outputs(data: dict) -> None:
    OUTPUT.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    o=data['original_observed'];s=data['static_only']
    lines=['# W3-295 — offline reconciliation of video checkpoint and PIT loop','',
      'Status: bounded offline analysis; no replay, build, guest change, Runtime/Core edit, menu, or gameplay claim.','',
      '## Original-observed facts','',
      f"- W3-294 used target/fixture SHA-256 `{o['target_sha256']}`; instrumented DOSBox SHA-256 `{o['instrumented_binary_sha256']}`.",
      f"- Fresh MAIN mapping: CS `{o['fresh_main_mapping']['cs']:#06x}`, link VA `{o['fresh_main_mapping']['link_va']:#08x}`, code rebase `{o['fresh_main_mapping']['code_rebase']:#x}`.",
      f"- Last target checkpoint: `{o['last_target_runtime_checkpoint']['checkpoint']}` at `{o['last_target_runtime_checkpoint']['link_va']:#08x}`. W3-294 captured {o['pit_event_count']} PIT events and ended after {o['guard']['duration_s']} seconds with guard cause `{o['guard']['cause']}`.",
      f"- DOS API hook emitted {o['setup_dos_api_count']} events; last was `{o['last_setup_dos_api']['operation']}` on `{o['last_setup_dos_api']['resolved_path']}`. Last JSONL event: `{o['last_emitted_trace_event']['event']}` for `{o['last_emitted_trace_event'].get('path')}`.",
      '- Staging logged VESA mode 101, but this capture contains no pixel sample.',
      '', '## Static-only comparison','',
      f"- Exact target image maps 0x9FDF9 to file offset `{s['video_checkpoint_window']['mapping']['file_offset']:#x}` and C427A to `{s['pit_loop_window']['mapping']['file_offset']:#x}`.",
      f"- Bounded local decode relationship: **{s['relation_between_video_checkpoint_and_pit_loop']}**.",
      '- W3-269 separately observed post-present dispatch at C427E; this does not establish the W3-294 run took the same path.',
      '', '## Conclusion','',
      '- No dynamic C427A/C427E/C4282 PIT values or branch were observed in W3-294. No causal explanation is proven for the missing loop event.',
      '- `VIDEO_FRAMEBUFFER_ASSIGN_AFTER` and VESA mode do not establish a pixel-backed framebuffer. Menu and gameplay remain unverified.',
      '- Next action: continue offline call-flow mapping; do not repeat the same replay.', '']
    REPORT.write_text('\n'.join(lines),encoding='utf-8')

if __name__=='__main__':
    result=build_evidence(); write_outputs(result); print(json.dumps({'evidence':str(OUTPUT),'report':str(REPORT),'video_file_offset':result['static_only']['video_checkpoint_window']['mapping']['file_offset'],'pit_file_offset':result['static_only']['pit_loop_window']['mapping']['file_offset'],'relation':result['static_only']['relation_between_video_checkpoint_and_pit_loop']},ensure_ascii=False))
