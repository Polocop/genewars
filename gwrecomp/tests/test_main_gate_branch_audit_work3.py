import json
j=json.load(open('evidence/main_gate_branch_audit_work3.json')); g=j['dynamic_game_gate']
assert j['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert j['main_function']['captured_instruction_count']==122 and j['main_function']['last_captured_guest_eip']=='0x0019441c'
assert j['dynamic_final_branch']['bytes']=='0f8e4b020000' and j['dynamic_final_branch']['taken_from_flags']
assert g['guest_eip']=='0x0019432f' and g['local_64']=='01' and g['local_68']=='00'
assert j['runtime_effect'].startswith('No setup_game')
print('PASS: full main_ trace and gate-local values resolve prior capture discrepancy and explain skipped game calls')
