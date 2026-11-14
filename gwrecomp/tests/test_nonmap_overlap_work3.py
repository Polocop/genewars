import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
d=json.loads((root/'evidence/nonmap_overlap_edges_work3.json').read_text(encoding='utf-8'))
p=json.loads((root/'evidence/boundary_revalidation_work3.json').read_text(encoding='utf-8'))['overlap']
assert hashlib.sha256((root/'evidence/genewars-1_1.exe').read_bytes()).hexdigest()==d['target_sha256']
assert d['map_function_like_seed_count']==651 and len(d['seed_addresses'])==651
assert d['edge_count']==len(d['edges'])==969
assert d['unique_nonseed_candidate_count']==len({e['candidate'] for e in d['edges']})==865
assert all(e['owner_seed']!=e['candidate'] for e in d['edges'])
assert all(e['owner_seed'] in set(d['seed_addresses']) for e in d['edges'])
assert d['previous_w3_004_counts']['unique_nonseed_partners']==857
assert d['previous_w3_004_counts']['seed_any_candidate_pairs']==1038
assert len(p['seed_to_seed_pairs'])==77
print('PASS: target hash, exact owner universe, edge completeness, and legacy delta retained')
