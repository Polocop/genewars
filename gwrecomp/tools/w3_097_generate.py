#!/usr/bin/env python3
"""Hash-bound reconciliation of W3-095's same-run VESA checkpoints."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
trace=root/'build/dosboxx_oracle/C/W3_095_ORIGINAL_PSP_TAIL_20261009_01.jsonl'
raw=trace.read_bytes(); rows=[json.loads(x) for x in raw.splitlines() if x.strip()]
video=[e for e in rows if e.get('event')=='target_runtime_checkpoint' and str(e.get('checkpoint','')).startswith('VIDEO')]
callsite=[e for e in video if e.get('checkpoint')=='VIDEO_VESA_MODE_CALLSITE']
entries=[e for e in video if e.get('checkpoint')=='VIDEO_VESA_SET_MODE_ENTRY']
assign=[e for e in video if e.get('checkpoint') in ('VIDEO_FRAMEBUFFER_ASSIGN_BEFORE','VIDEO_FRAMEBUFFER_ASSIGN_AFTER')]
page=[e for e in video if 'PAGE' in str(e.get('checkpoint',''))]
int10=[e for e in video if 'INT10' in str(e.get('checkpoint',''))]
assert len(callsite)==2 and len(entries)==1
first=callsite[0]; later=callsite[1]; target=entries[0]
assert (first['sequence'],first['edx'])==(166,0x100)
assert (target['sequence'],target['link_va'])==(167,0xA3A00)
assert (later['sequence'],later['edx'])==(313,0x180)
assert rows[-1]['sequence']==313 and not any(e['sequence']>313 for e in rows)
inputs={
 'evidence/w3_095_original_psp_tail.json':root/'evidence/w3_095_original_psp_tail.json',
 'evidence/w3_073_video_checkpoints_02.json':root/'evidence/w3_073_video_checkpoints_02.json',
 'evidence/w3_083_setup_continuation.json':root/'evidence/w3_083_setup_continuation.json',
 'evidence/w3_094_post_vesa_call_alignment.json':root/'evidence/w3_094_post_vesa_call_alignment.json',
 'trace':trace,
}
hashes={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in inputs.items()}
evidence={k:json.loads(v.read_text(encoding='utf-8')) for k,v in inputs.items() if k!='trace'}
result={
 'schema':'w3-097-vesa-call-alignment/v1','task':'W3-097',
 'target_sha256':evidence['evidence/w3_095_original_psp_tail.json']['target']['sha256'],
 'staging_revision':evidence['evidence/w3_095_original_psp_tail.json']['emulator']['revision'],
 'input_sha256':hashes,
 'trace':{'path':'build/dosboxx_oracle/C/W3_095_ORIGINAL_PSP_TAIL_20261009_01.jsonl','bytes':len(raw),'sha256':hashes['trace'],'event_count':len(rows),'last_event_sequence':rows[-1]['sequence']},
 'same_run':{'first_callsite':first,'first_mode_entry':target,'framebuffer_assignment_events':assign,'later_callsite':later,'page_events':page,'int10_events':int10},
 'analysis':{
  'first_edx_100_callsite_reached_a3a00':True,
  'first_call_assignment_after_value':next((x['framebuffer_global_samples'] for x in assign if x['checkpoint']=='VIDEO_FRAMEBUFFER_ASSIGN_AFTER'),None),
  'later_edx_180_callsite_has_target_entry_after_it':False,
  'later_edx_180_callsite_has_page_or_int10_after_it':False,
  'later_callsite_is_last_persisted_trace_event':True,
  'call_executed_or_returned':None,
  'execution_stopped_vs_slow_or_unrecorded': 'UNKNOWN',
  'first_missing_checkpoint':'VIDEO_VESA_SET_MODE_ENTRY at link VA 0xA3A00 for the later 0x9FDCC invocation with EDX=0x180',
  'framebuffer_write_or_visible_frame_proved':False,
  'interpretation':'The earlier EDX=0x100 call reaches the target and is followed by assignment checkpoints in this run. The later EDX=0x180 site is observed, but no subsequent target/page/write event is persisted. The record cannot determine whether the guest executed the CALL, returned, continued without a recorded hook, or was stopped.'
 },
 'prior_alignment_reference':evidence['evidence/w3_094_post_vesa_call_alignment.json'],
 'scope':{'new_replay':False,'global_trace':False,'guest_or_source_modified':False,'menu_or_frame_claim':False}
}
out=root/'evidence/w3_097_vesa_call_alignment.json'
out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps({'evidence':str(out),'trace_sha256':hashes['trace'],'first_callsite':first['sequence'],'entry':target['sequence'],'later_callsite':later['sequence'],'trace_events':len(rows),'page_events':len(page),'int10_events':len(int10)},indent=2))
