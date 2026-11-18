import json
j=json.load(open('evidence/getconfigs_eof_work3.json'))
assert j['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert j['empty_config_fixture']['size_bytes']==0
assert j['getconfigs']['return_al']=='0x01' and j['getconfigs']['guest_return_eip']=='0x00114f3a'
assert any(x['operation']=='read' and x['result']==0 for x in j['getconfigs']['config_file_attempts'])
assert j['next_stop']['original_bytes']=='cd31' and j['next_stop']['linear_start']=='0x001aff40' and j['next_stop']['size']=='0x00006221'
assert j['next_stop']['map_function']=='_DoINTR_' and j['execution']['process_exit'] is None
assert 'not MENU' in j['result']
print('PASS: original EOF returns AL=1 with default bytes; setup_game proceeds to exact DPMI 0600 lock request')

