from __future__ import annotations
import hashlib, json, re
from pathlib import Path
ROOT=Path(r'E:\GWRecomp')
ORIGINAL=ROOT/'evidence/original_ax4400_bx1_alignment_w3_221.json'
TRACE=ROOT/'build/dosboxx_oracle/C/W3_221_AX4400_BX1_ALIGNMENT_20261009_01.jsonl'
NATIVE=ROOT/'evidence/native_address_ax4400_w1_074.json'
HANDLE5=ROOT/'evidence/w3_085_handle5_lineage.json'
ADDRESS=ROOT/'evidence/w3_086_address_txt_provenance.json'
OUT=ROOT/'evidence/w3_227_ah44_divergence_chronology.json'
REPORT=ROOT/'reports/coordination/w3_227_ah44_divergence_chronology.md'
TARGET='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def load(p): return json.loads(p.read_text(encoding='utf-8'))
def build_contract():
 original,native=load(ORIGINAL),load(NATIVE)
 handle5,address=load(HANDLE5),load(ADDRESS)
 rows=[json.loads(x) for x in TRACE.read_text(encoding='utf-8').splitlines() if x.strip()]
 callbacks=original['ax4400_callbacks']
 o5=next(x for x in callbacks if x['ordinal']==5); o6=next(x for x in callbacks if x['ordinal']==6); o7=next(x for x in callbacks if x['ordinal']==7)
 around=[r for r in rows if o5['sequence']<=r.get('sequence',-1)<=o6['sequence']]
 lifecycle=[]
 for r in around:
  if r.get('event') in {'dos_address_txt_write','dos_handle_close','dos_handle_open'}:
   lifecycle.append({k:r[k] for k in ('sequence','event','process_psp','path','requested_path','entry','internal_handle','offset','requested','written','flags','result') if k in r})
 snapshot=next(x for x in original['handle_table_snapshots'] if x['sequence']<o5['sequence'])
 jft2=next((x for x in snapshot['entries'] if x['entry']==2),None)
 nparsed=[]
 for pos,entry in enumerate(native['ax4400']['requests'],1):
  if isinstance(entry,str):
   f={k.lower():int(v,16) for k,v in re.findall(r'(e(?:ax|bx|cx|dx)_in)=([0-9a-fA-F]{8})',entry)}
   m=re.search(r'\bordinal=(\d+)',entry)
   nparsed.append({'position':pos,'record_ordinal':int(m.group(1)) if m else None,'AX':f.get('eax_in'),'BX':f.get('ebx_in'),'raw':entry})
 n6=nparsed[5] if len(nparsed)>=6 else None
 openerr=next((e for e in lifecycle if e.get('event')=='dos_handle_open' and e.get('path','').upper().endswith('GW.ERR')),None)
 causal_boundary='The captures do not establish why the original opens GW.ERR, prove that this transition caused the changed request, or identify an emulator/Core defect.'
 original_target=original['preflight']['fixture']['GW.EXE']['sha256']; native_target=native['target_sha256']
 result={
  'schema':'gwrecomp.ah44-first-divergence-chronology-w3-227/v1','task':'W3-227',
  'classification':'FIRST_DIVERGENCE_CONTEXT_OBSERVED_CAUSALITY_UNKNOWN',
  'evidence_levels':{'original':'ORIGINAL_OBSERVED','native':'NATIVE_VERIFIED'},
  'provenance':{'original_run_id':original['run_id'],'original_captured_utc':original['captured_utc'],'original_target_sha256':original_target,'native_target_sha256':native_target,'target_hashes_match':original_target==TARGET and native_target==TARGET,'original_staging_revision':original['preflight']['runtime']['staging_revision'],'original_staging_sha256':original['preflight']['runtime']['sha256'],'original_config_sha256':original['preflight']['config']['sha256'],'original_cue_sha256':original['preflight']['cue']['sha256'],'original_cue_read_only':original['preflight']['cue']['read_only_mount'],'original_launch_tail':original['dos_launch_tail'],'tail_minus_k_38928_observed':original['tail_minus_k_38928_observed'],'original_evidence_sha256':digest(ORIGINAL),'original_trace_sha256':digest(TRACE),'native_evidence_sha256':digest(NATIVE),'handle5_evidence_sha256':digest(HANDLE5),'address_provenance_sha256':digest(ADDRESS)},
  'original_sequence':{'bounded_events_from_ordinal5_through_ordinal6':[{'sequence':r.get('sequence'),'event':r.get('event'),'ordinal':r.get('ordinal')} for r in around],'ordinal5':{'sequence':o5['sequence'],'BX':o5['in_bx'],'DX':o5['in_dx'],'AX_out':o5['out_ax'],'DX_out':o5['out_dx'],'CF':o5['cf']},'lifecycle_before_ordinal6':lifecycle,'pre_window_JFT_entry2_snapshot':jft2,'ordinal6':{'sequence':o6['sequence'],'process_psp':o6['process_psp'],'AX':o6['in_ax'],'BX':o6['in_bx'],'CX':o6['in_cx'],'DX':o6['in_dx'],'ESI':o6['in_esi'],'EDI':o6['in_edi'],'EBP':o6['in_ebp'],'EFLAGS':o6['in_eflags'],'AX_out':o6['out_ax'],'DX_out':o6['out_dx'],'CF':o6['cf'],'cwd':o6['cwd']},'ordinal7':{'sequence':o7['sequence'],'BX':o7['in_bx'],'DX':o7['in_dx'],'AX_out':o7['out_ax'],'DX_out':o7['out_dx'],'CF':o7['cf']},'GW_ERR_open_precedes_ordinal6':bool(openerr and openerr['sequence']<o6['sequence']),'direct_caller_ordinal6':'UNKNOWN; W3-221 contains no verified protected-mode CPU-entry record for BX=2 ordinal 6.'},
  'native_comparison':{'native_requests_captured':len(nparsed),'sixth_request_record':n6,'sixth_original_vs_native_BX':{'original':o6['in_bx'],'native':n6['BX'] if n6 else None},'first_sequence_divergence_ordinal':6,'native_address_txt_seed_sha256':native['address_txt']['sha256'],'native_address_txt_initial_visibility':native['address_txt']['virtual_seed_event'],'native_file_lifecycle_coverage':'W1-074 establishes its virtual ADDRESS.TXT seed/open and AX=4400 requests; it does not provide equivalent complete DOS open/close coverage for GW.ERR, so absence is not established.'},
  'cross_run_scope':{'measured':['Original: DOS write/close of ADDRESS.TXT, close of PSP entry 2, then open GW.ERR into entry 2 before original AX=4400 ordinal 6 BX=2.','Native: sixth recorded AX=4400 request is BX=5; ADDRESS.TXT is seeded/opened through the bounded virtual provider.'],'interpretation':causal_boundary,'native_absence_rule':'No claim that GW.ERR was absent from native execution; equivalent full DOS handle lifecycle coverage is not present in W1-074.','same_run_equivalence':False},
  'acceptance_checks':{'input_target_hashes_match_exact_target':original_target==TARGET and native_target==TARGET,'original_requests_5_6_7_reconciled':o5['ordinal']==5 and o6['ordinal']==6 and o7['ordinal']==7,'original_ordinal6_is_bx2_and_success':o6['in_ax']==0x4400 and o6['in_bx']==2 and o6['out_ax']==2 and o6['out_dx']==2 and o6['cf'] is False,'gw_err_opened_entry2_before_ordinal6':bool(openerr and openerr.get('entry')==2 and openerr['sequence']<o6['sequence']),'native_sixth_request_bx5':bool(n6 and n6['BX']==5),'causal_claim_prohibited':'do not establish why' in causal_boundary and 'prove that this transition caused' in causal_boundary},
  'next_action':'WORK1 can inspect the original GW.ERR open/write path as the earliest measured environment-side boundary; causal attribution still requires an aligned before-open state or a controlled provenance-matched seed comparison.'}
 OUT.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 REPORT.parent.mkdir(parents=True,exist_ok=True)
 actions='; '.join(f"seq {e.get('sequence')} {e.get('event')} {e.get('path',e.get('requested_path',''))} entry={e.get('entry','')}" for e in lifecycle)
 REPORT.write_text('# W3-227 — first AX=4400 sequence divergence\n\n'+f"Evidence: [{OUT.name}](../../{OUT.as_posix()})\n\nBoth captures use the exact target hash `{TARGET}`, but are separate runs. In W3-221's original trace, AX=4400 ordinal 5 is BX=5 at sequence {o5['sequence']}. The trace then records: {actions}. Original ordinal 6 at sequence {o6['sequence']} is BX=2 and returns AX=DX=2 with CF clear. The native sixth captured request is BX={n6['BX'] if n6 else 'not captured'}, so this is a measured sequence difference.\n\nThe GW.ERR open into PSP entry 2 occurs before the original ordinal-6 callback. This establishes event order, not cause. W1-074 does not provide complete matching DOS open/close coverage for GW.ERR, so the report does not claim that the file was absent natively. Original ordinal-6 caller remains UNKNOWN, and no Core defect or whole-run parity is claimed.\n",encoding='utf-8')
 return result
if __name__=='__main__': print(json.dumps(build_contract(),indent=2,ensure_ascii=False))

