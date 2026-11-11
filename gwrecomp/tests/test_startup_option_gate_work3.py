import json
j=json.load(open('evidence/startup_option_gate_work3.json'))
assert j['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert j['option_dispatch']['index']==44 and j['option_dispatch']['handler_link_va']=='0x000941d2'
assert j['command_tail']=='-k' and j['gate']['local_64']=='01' and j['gate']['local_68']=='01'
assert 'setup_game' in j['root_hits'] and 'PlayIntro' not in j['root_hits']
assert j['early_setup_game_exit']['return_address_link']=='0x00094ae9'
assert 'GetConfigs' in j['result'] and '0x94AE4' in j['result']
print('PASS: -k option resolves through original table, enters setup_game, then GetConfigs failure returns status 0 before PlayIntro')
