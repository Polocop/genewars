import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
d=json.loads((root/'evidence/overlap_entry_redteam_work3.json').read_text(encoding='utf-8'))
delta=json.loads((root/'evidence/overlap_delta_work3.json').read_text(encoding='utf-8'))
assert hashlib.sha256((root/'evidence/genewars-1_1.exe').read_bytes()).hexdigest()==d['target_sha256']
assert d['target_count']==len(d['entries'])==19
labels=[e for e in d['entries'] if e['classification']=='def_/jpt_ map control-flow label']
assert len(labels)==12 and d['disputed_flow_label_count']==12
assert len(delta['bounded_ambiguous_edge'][0]['candidate_pool'])==8
assert all(e['incoming_direct_control_flow'] for e in d['entries'])
assert all(x['mnemonic']!='call' for e in d['entries'] for x in e['incoming_direct_control_flow'])
assert all(e['instruction_start_in_cfg_count']>0 for e in d['entries'])
assert d['function_count_adjustment']==0
print('PASS: 12 flow-label addresses, 8 ambiguous candidates, branch-only incoming edges, no function promotions')
