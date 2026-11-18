import json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
d=json.loads((ROOT/'evidence'/'map_overlap_ownership_work1.json').read_text())
assert d['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert d['seed_count']==651 and d['reproduced_seed_pairs']==77
assert sum(d['seed_pair_classes'].values())==77
assert d['independent_function_count_adjustment']==0
assert all(x['classification'] in {'shared_tail_or_non_nested_CFG','A_entry_reachable_inside_B_CFG','B_entry_reachable_inside_A_CFG','shared_internal_CFG_blocks'} for x in d['seed_pairs'])
assert len(d['nonmap_candidates_inside_seed_cfgs'])==d['nonmap_candidate_count']
print('MAP overlap evidence PASS: 77/77 seed pairs classified; overlaps excluded from confirmed count')
