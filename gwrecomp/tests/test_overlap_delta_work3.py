import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
d=json.loads((root/'evidence/overlap_delta_work3.json').read_text(encoding='utf-8'))
assert d['deltas']=={'unique_nonseed_candidates':8,'nonseed_edges':8}
assert len(d['exact_additional_edges'])==7
assert len(d['bounded_ambiguous_edge'])==1
b=d['bounded_ambiguous_edge'][0]
assert b['owner']=='0x00094AC0' and b['missing_edge_count']==1 and len(b['candidate_pool'])==8
assert all(x['edge']['classification']=='MAP_control_flow_label' for x in d['exact_additional_edges'])
assert d['confirmed_function_count_adjustment']==0
print('PASS: seven exact additions, one bounded historical membership gap, no function promotions')
