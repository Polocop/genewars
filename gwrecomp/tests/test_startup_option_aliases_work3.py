import json
j=json.load(open('evidence/startup_option_aliases_work3.json'))
assert j['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert [x['command_tail'] for x in j['variants']]==['-k','-K','/k']
for x in j['variants']:
 assert x['target_sha256']==j['target_sha256']
 assert x['gate']['local_64']=='01' and x['gate']['local_68']=='01'
 assert 'setup_game' in x['roots'] and 'PlayIntro' not in x['roots']
 assert x['unsupported_service']['function']==63 and x['process_exit'] is None
print('PASS: -k, -K, /k reach the same original setup_game path and stop at AH=3F')
