from __future__ import annotations
import hashlib, json, sqlite3
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FILES={
 'original':ROOT/'evidence/w3_091_ah4400_bx1_caller.json',
 'native':ROOT/'evidence/native_ah44_bx1_callsite_work1.json',
 'seed':ROOT/'evidence/native_address_txt_seed_provenance_work1.json',
}
OUT=ROOT/'evidence/w3_186_ah4400_bx1_provenance.json'

def build_result():
 original=json.loads(FILES['original'].read_text(encoding='utf-8'))
 native=json.loads(FILES['native'].read_text(encoding='utf-8'))
 seed=json.loads(FILES['seed'].read_text(encoding='utf-8'))
 oc=original['verified_contract']; caller=oc['caller']; req=oc['request']; resp=oc['response']
 nreq=native['frontier']['request_registers']
 seed_orig=seed['original']; seed_native=seed['native']; seed_fx=seed['fixture']
 launch=original['preflight']['configured_launch']
 no_tail=any('no launcher tail' in x.lower() for x in launch)
 conn=sqlite3.connect(ROOT/'coordination/tasks.sqlite3')
 statuses={r[0]:r[1] for r in conn.execute("select id,status from tasks where id in ('W3-060','W1-043','W2-086')")}
 conn.close()
 result={
  'schema':'w3-186-ah4400-bx1-provenance/v1','task':'W3-186',
  'classification':'ORIGINAL_BX1_CONTRACT_VALID_BUT_NOT_FULL_RUN_EQUIVALENCE',
  'source_files':{k:{'path':str(v.relative_to(ROOT)).replace('\\','/'),'sha256':hashlib.sha256(v.read_bytes()).hexdigest()} for k,v in FILES.items()},
  'original_observed':{
   'target_sha256':original['preflight']['fixture_sha256'],'staging_revision':original['staging_revision'],
   'runtime_sha256':original['instrumented_runtime_sha256'],'site_link_va':caller['link_va_of_int_instruction'],
   'mapping_valid':caller['mapping_valid'],'int21_bytes_verified':caller['verified_int_bytes']==['0xcd','0x21'],
   'request':req,'response':resp,'context':oc['dos_context'],
   'callback_same_psp_ordinal_correlated':oc['callback_correlation']['same_psp'],
   'configured_launch_has_no_launcher_tail':no_tail,'configured_launch':launch,
   'guest_psp_tail':'NOT CAPTURED IN W3-091; configured launch specifies no launcher tail'
  },
  'native_observed':{
   'target_sha256':native['target_sha256'],'command_tail':native['command_tail'],
   'site_link_va':native['frontier']['guest_eip'],'request':{'eax':nreq['eax'],'ebx':nreq['ebx'],'ecx':nreq['ecx'],'edx':nreq['edx']},'response':'NATIVE_NEXT_TRAP; no response supplied',
   'caller_link_va':seed_native['caller_link_va'],'stream_object_handle':seed_native['caller_eax_handle'],
   'site_and_handle_class_align':True,'same_dynamic_invocation':False
  },
  'seed_provenance':{
   'classification':seed['classification'],'same_fingerprint_claimed_by_w1_051':seed_fx['w1_051_marked_comparable'],
   'address_txt_installed_source_matches':seed_fx['source_address_txt_matches'],
   'address_txt_original_initial_contents_proven':seed_fx['original_initial_file_content_proven'],
   'original_observation':{'caller_link_va':seed_orig['caller_link_va'],'handle':seed_orig['open_event']['entry'],'path':seed_orig['open_event']['requested_path'],'same_invocation_as_native_bx1':seed_orig['same_dynamic_invocation_as_native_bx1']},
   'interpretation':seed_fx['interpretation']
  },
  'comparison':{
   'same_target_hash':original['preflight']['fixture_sha256']==native['target_sha256'],
   'same_callsite_and_bx1':int(caller['link_va_of_int_instruction'],16)==int(native['frontier']['guest_eip'],16) and req['bx']=='0x1' and nreq['ebx']=='00000001',
   'same_console_handle_class':oc['dos_context']['handle']==int(nreq['ebx'],16) and oc['dos_context']['resolved_path']=='CON',
   'full_environment_equivalence':False,
   'differences':['W3-091 configured launch explicitly used GENEWARS.EXE without a launcher tail; its PSP tail was not captured.', 'W1-053 used PSP tail " -k 38928".', 'W1-054 proves ADDRESS.TXT is not an installed source asset and its initial original bytes/first creator are unknown despite equal recorded seed fingerprints.'],
   'reusable_scope':'Original AX=4400/BX=1 response AX=DX=0x80D3, CF=0 for handle 1 resolved as CON in C:\\GENEWARS under the W3-091 run only.',
   'not_reusable_for':'BX=2, regular-file handles, or a claim of whole-run/native seed equivalence.'
  },
  'queue_snapshot':statuses,
  'disposition':{'W3_060':'BLOCKED; its requested BX=2 aligned original frontier remains unmet', 'W1_043':'BLOCKED; matched original/native caller and full seed/first-divergence evidence still insufficient', 'W2_086':'READY record remains dependency-gated by W3-060 and W1-043; no dependencies altered'},
  'new_original_replay_needed':False,
  'next_action':'Obtain a matched original/native launch and pre-call seed fingerprint (especially authenticated ADDRESS.TXT initial state) or a causal first-divergence capture before asserting equivalence; do not repeat the same replay.'
 }
 assert result['comparison']['same_callsite_and_bx1'] and result['comparison']['same_console_handle_class']
 assert result['original_observed']['configured_launch_has_no_launcher_tail']
 assert not result['seed_provenance']['address_txt_original_initial_contents_proven']
 OUT.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 return result

if __name__=='__main__':
 print(json.dumps(build_result(),indent=2))



