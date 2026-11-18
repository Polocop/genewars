import json
j=json.load(open('evidence/getconfigs_file_audit_work3.json'))
assert j['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert j['reference_config_ini_present'] is False and j['staged_config_ini_present'] is False
assert j['staged_gw_err'].endswith('GW.ERR')
assert j['default_no_config_run']['config_open_attempts'][0]['error']==2
assert j['empty_fixture_run']['config_open_attempts'][0]['result'] is True
assert j['empty_fixture_run']['unsupported_service']['function']==63
assert j['empty_fixture_run']['interrupt']['registers']['ebx']=='0x00000006'
assert j['empty_fixture_run']['interrupt']['registers']['ecx']=='0x00001000'
b=j['empty_fixture_run']['caller_function_boundary']
assert b['name']=='__qread_' and b['bytes_at_int']=='cd21' and b['start']=='0x000d2130' and b['next_start']=='0x000d214f'
assert 'does not establish' in j['conclusion']
print('PASS: absent config in source/staged trees; exact __qread_ AH=3F instruction and bounded inference')
