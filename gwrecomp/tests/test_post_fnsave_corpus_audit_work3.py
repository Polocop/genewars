import json,hashlib,pathlib
j=json.load(open('evidence/post_fnsave_corpus_audit_work3.json'))
assert j['target_sha256_actual']==j['target_sha256_corpus']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert j['map_sha256_actual']==j['map_sha256_corpus']=='30e06c203154904740c4ff3f1fcc4971fb6c0ef10ace2f4f9dc63367d45b99b3'
assert (j['semantic_cases'],j['cases_completed'],j['patterns_passed'],j['patterns_failed'])==(120,120,120,0)
assert j['function_count']==30 and j['function_pass_count']==30 and j['function_fail_count']==0
assert j['compile_returncode']==0 and j['execution_returncode']==0
assert j['execution_stdout']=='COMPLETED 120 cases; divergences=0'
for f in j['x87_functions']:
 assert f['result']=='PASS' and f['patterns_passed']==4 and f['patterns_failed']==0 and not f['divergences']
assert j['focused_fnsave_oracle']['passed'] is True and j['focused_fnsave_oracle']['patterns']==4
print('PASS: original hashes, 30 functions/120 patterns reconcile; both x87 lifts pass all 8 patterns; focused native FNSAVE 4/4')
