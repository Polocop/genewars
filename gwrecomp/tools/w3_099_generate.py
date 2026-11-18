#!/usr/bin/env python3
"""Reconcile W3-095 VESA events with the instrumented video cap."""
import hashlib,json,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
trace=root/'build/dosboxx_oracle/C/W3_095_ORIGINAL_PSP_TAIL_20261009_01.jsonl'
source=root/'third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp'
prev=root/'evidence/w3_097_vesa_call_alignment.json'
manifest=root/'evidence/w3_095_original_psp_tail.json'
raw=trace.read_bytes(); rows=[json.loads(x) for x in raw.splitlines() if x.strip()]
video=[e for e in rows if e.get('event')=='target_runtime_checkpoint' and str(e.get('checkpoint','')).startswith('VIDEO_')]
callsite=[e for e in video if e.get('checkpoint')=='VIDEO_VESA_MODE_CALLSITE']
assert len(video)==10 and len(callsite)==2 and callsite[-1]['sequence']==313
assert rows[-1]['sequence']==313
text=source.read_text(encoding='utf-8')
condition='video_checkpoint_count < 10' in text
increment='if (video_checkpoint)\n\t\t\t\t\t++video_checkpoint_count;' in text
assert condition and increment
revision=subprocess.run(['git','-C',str(root/'third_party/dosbox-staging-w3-059-instrumented'),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
prior=json.loads(prev.read_text(encoding='utf-8'))
manifest_data=json.loads(manifest.read_text(encoding='utf-8'))
result={
 'schema':'w3-099-vesa-cap-suppression/v1','task':'W3-099',
 'target_sha256':manifest_data['target']['sha256'],
 'staging_revision':revision,
 'instrumented_binary_sha256':manifest_data['emulator']['binary_sha256'],
 'inputs_sha256':{'trace':h(trace),'source':h(source),'w3_097':h(prev),'w3_095_manifest':h(manifest)},
 'trace':{'bytes':len(raw),'event_count':len(rows),'last_event_sequence':rows[-1]['sequence'],'video_event_count':len(video),'video_events':video},
 'instrumentation':{'source_path':'third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp','admission_condition':'(video_checkpoint && video_checkpoint_count < 10)','increment':'video_checkpoint_count increments after an admitted checkpoint is appended','cap':10,'source_condition_verified':condition,'increment_order_verified':increment,'count_after_sequence_313':10},
 'interpretation':{'eleventh_video_checkpoint_would_be_suppressed':True,'suppression_is_confirmed_for_instrumentation':True,'later_a3a00_guest_entry_observed':False,'whether_guest_reached_a3a00':'UNKNOWN; an entry after sequence 313 would have been filtered by the exhausted instrumentation cap','whether_guest_call_executed_or_returned':'UNKNOWN','whether_timeout_contributed':'The guard ended the run at its 30-second timeout; no conclusion about CPU progress after the last record.','page_or_framebuffer_observed':False,'correction':'W3-097 correctly reported no persisted successor but could not account for the counter cap. The missing event is not evidence of guest failure or of call return.'},
 'next_capture_filter':{'callsite_link_va':'0x9FDCC','entry_link_va':'0xA3A00','caller_return_link_va':'0x9FDD1','post_call_jump_link_va':'0x9FDEF','mode_eax':'0x101','edx':'0x180','scope':'Capture only this later invocation and its return-side checkpoints, with a per-target event cap; suppress earlier video events.'},
 'prior_w3_097_sha256':prior['input_sha256']['trace'],
 'scope':{'new_replay':False,'source_modified':False,'guest_or_runtime_modified':False,'framebuffer_claim':False}
}
out=root/'evidence/w3_099_vesa_cap_suppression.json'
out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps({'video_events':len(video),'last_seq':rows[-1]['sequence'],'cap':10,'suppression_verified':condition and increment,'later_call_execution':'UNKNOWN','evidence':str(out),'source_sha256':h(source)},indent=2))
