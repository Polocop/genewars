import hashlib,json,pathlib
from collections import Counter
ROOT=pathlib.Path(__file__).resolve().parents[1]
current=json.loads((ROOT/'evidence/nonmap_overlap_edges_work3.json').read_text(encoding='utf-8'))
old=json.loads((ROOT/'evidence/boundary_revalidation_work3.json').read_text(encoding='utf-8'))['overlap']
oldp={int(k,16):v for k,v in old['per_seed_profiles'].items()}
newp={int(k,16):v for k,v in current['per_seed_profiles'].items()}
changed=[]
for owner in sorted(set(oldp)|set(newp)):
 a=oldp.get(owner,{}).get('nonseed_partner_pairs',0); b=newp.get(owner,{}).get('nonseed_partner_edges',0)
 if b-a==1: changed.append({'owner':f'0x{owner:08X}','old_count':a,'new_count':b,'old_samples':[x['partner'] for x in oldp.get(owner,{}).get('samples',[])],'current_candidates':newp.get(owner,{}).get('nonseed_partners',[])})
assert len(changed)==8 and sum(x['new_count']-x['old_count'] for x in changed)==8
exact=[]; bounded=[]
for x in changed:
 oldset={int(a,16) for a in x['old_samples']}; curset={int(a,16) for a in x['current_candidates']}
 if x['old_count']==0:
  assert len(curset)==1
  exact.append({'owner':x['owner'],'candidate':f'0x{next(iter(curset)):08X}','basis':'old per-seed count was zero; current profile has exactly one edge'})
 elif x['old_count']<=3:
  assert len(oldset)==x['old_count'] and oldset<=curset
  extra=curset-oldset; assert len(extra)==1
  exact.append({'owner':x['owner'],'candidate':f'0x{next(iter(extra)):08X}','basis':'old sample list is complete because old edge count <= 3'})
 else:
  assert x['old_count']==10 and x['new_count']==11 and len(oldset)==3
  pool=sorted(curset-oldset)
  assert len(pool)==8
  bounded.append({'owner':x['owner'],'candidate_pool':[f'0x{a:08X}' for a in pool],'missing_edge_count':1,'basis':'old count was 10 but only 3 samples were retained; any one of the 8 unsampled current candidates could be the omitted historical edge'})
current_by_pair={(e['owner_seed'],e['candidate']):e for e in current['edges']}
for item in exact: item['edge']=current_by_pair[(item['owner'],item['candidate'])]
for item in bounded: item['candidate_edges']=[current_by_pair[(item['owner'],cand)] for cand in item['candidate_pool']]
summary={'target_sha256':current['target_sha256'],'map_sha256':current['map_sha256'],'current_decoder_sha256':hashlib.sha256((ROOT/'third_party/pcrecomp/tools/disasm/disasm32.py').read_bytes()).hexdigest(),'current_audit_sha256':hashlib.sha256((ROOT/'tools/audit_nonmap_overlap_work3.py').read_bytes()).hexdigest(),'previous_audit_script_hash':'not recorded in W3-004 evidence','old_totals':{'unique_nonseed_candidates':old['current_unique_nonseed_partners'],'seed_any_candidate_pairs':old['current_seed_any_candidate_pairs'],'seed_to_seed_pairs':len(old['seed_to_seed_pairs']),'nonseed_edges':old['current_seed_any_candidate_pairs']-len(old['seed_to_seed_pairs'])},'current_totals':{'candidate_universe':current['candidate_universe_count'],'unique_nonseed_candidates':current['unique_nonseed_candidate_count'],'nonseed_edges':current['edge_count']},'deltas':{'unique_nonseed_candidates':current['unique_nonseed_candidate_count']-old['current_unique_nonseed_partners'],'nonseed_edges':current['edge_count']-(old['current_seed_any_candidate_pairs']-len(old['seed_to_seed_pairs']))},'changed_owner_profiles':changed,'exact_additional_edges':exact,'bounded_ambiguous_edge':bounded,'confirmed_function_count_adjustment':0,'conclusion':'Seven exact additional candidate edges recovered. For owner 0x00094AC0, one of eight unsampled candidates is the eighth edge; historical evidence retained only 3 of the previous 10 edges and has no full old edge table or analyzer hash. The old aggregate is non-reproducible at that single-edge membership level; no function boundary is confirmed by these overlaps.'}
(ROOT/'evidence/overlap_delta_work3.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
lines=['# W3-011 — historical overlap delta','',f"Target SHA-256 `{summary['target_sha256']}`; MAIN.MAP SHA-256 `{summary['map_sha256']}`. Current decoder SHA-256 `{summary['current_decoder_sha256']}`; current audit SHA-256 `{summary['current_audit_sha256']}`. The W3-004 evidence recorded no analyzer hash.",'',f"Historical totals: {summary['old_totals']['unique_nonseed_candidates']} unique nonseed candidates and {summary['old_totals']['nonseed_edges']} seed-to-nonseed edges (1038 total pairs less 77 seed-to-seed). Current totals: {summary['current_totals']['unique_nonseed_candidates']} and {summary['current_totals']['nonseed_edges']}. Delta is **+8 candidates / +8 edges**, one added edge in each of eight seed profiles.",'','## Seven exact added edges','']
for x in exact: lines.append(f"- Owner `{x['owner']}` → candidate `{x['candidate']}`. {x['basis']}.")
lines += ['', '## One bounded ambiguous edge', '', 'Owner `0x00094AC0` rose from 10 to 11 edges. The old evidence saved only three candidates for this owner (`0x94F96`, `0x95221`, `0x95235`), leaving seven of the ten historical edges unnamed. Current candidates outside those three are:']
for a in bounded[0]['candidate_pool']: lines.append(f'- `{a}`')
lines += ['', 'Exactly one of those eight candidates is the historical addition; the old evidence cannot identify which one. This is bounded to one owner, one edge, and eight possible VAs. No candidate is treated as a function.','', 'Reproduced source hashes and the full current candidate universe are in `evidence/overlap_delta_work3.json`; exact current edges remain in `evidence/nonmap_overlap_edges_work3.json`. This closes the aggregate delta with one explicitly non-reproducible historical membership detail.','']
(ROOT/'reports/coordination/overlap_delta_work3.md').write_text('\n'.join(lines),encoding='utf-8')
print(json.dumps({'exact_added_edges':exact,'bounded_candidates':bounded[0]['candidate_pool'],'delta':summary['deltas']},indent=2))
