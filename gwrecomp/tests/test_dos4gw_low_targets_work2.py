import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
e = json.loads((ROOT / 'evidence' / 'icall_dispatch_table.json').read_text(encoding='utf-8'))
m = e['metrics']
targets = e['unique_abs_targets']
assert m['closure_object'] == '0x00010000-0x000EE930'
assert m['lifted_functions_in_c'] == 1567
assert m['total_icall_sites'] == 553
assert len(targets) == 28
classes = Counter(x['class'] for x in targets)
assert classes == {'above_code_object': 28}, classes
assert m['abs_below_code'] == 0
assert m['abs_not_lifted_in_range'] == 0
assert m['unresolved_sites'] == 0
assert all(int(x['target_va'], 16) >= 0x10000 for x in targets)
assert all(int(x['target_va'], 16) > 0xEE930 for x in targets)
print('PASS W2-056: corrected closure contains zero below-code DOS/4GW stub targets; all 28 unique absolute targets are above the code object')
