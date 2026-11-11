import json
j=json.load(open('evidence/getconfigs_contract_work3.json'))
assert j['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert j['function']['map_link_va']=='0x00014bf0'
assert j['input_contract']['filename']=='config.ini' and j['input_contract']['mode']=='r'
assert 'return AL=0' in j['input_contract']['missing_file_branch']
assert 'return AL=1' in j['input_contract']['eof_branch']
for key in ('CD','InstallDrive','Language','Intro','Anims','Sounds','Levels','Data'):
 assert key in j['input_contract']['opened_file_behavior']
assert 'static-only' in j['dynamic_limit']
print('PASS: GetConfigs distinguishes open failure from EOF defaults and success; empty file remains dynamically unverified')
