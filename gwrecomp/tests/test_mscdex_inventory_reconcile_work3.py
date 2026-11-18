import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/'evidence/startup_ah48_sites_work3.json').read_text(encoding='utf-8'))
l=json.loads((ROOT/'evidence/mscdex_inventory.json').read_text(encoding='utf-8'))
base=json.loads((ROOT/'evidence/empty_config_overlay_work2.json').read_text(encoding='utf-8'))
assert w['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert w['command_tail']==base['command_tail']=='-k'
assert w['fixture']['sha256']==base['empty_config_sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert len(w['int2f_services'])==1 and w['int2f_services'][0]['ax']=='0x00001500'
dyn=[x for x in l['dynamic_frames'] if x.get('is_mscdex')]
assert len(dyn)==1 and dyn[0]['mscdex_subfunc']=='0x1500' and dyn[0]['interrupt_eip']=='0x001d23a7'
assert w['int2f_services'][0]['eip']=='0x001d23a7'
assert l['summary']['distinct_mscdex_subfunctions']==['0x1500','0x150C','0x1510']
assert l['current_gate']['eip']=='0x001d23a7'
assert w['first_unsupported']['kind']=='cpu_exception' and w['first_unsupported']['eip']=='0x001c3d42'
assert w['executed_instruction_count']>6_900_000
print('PASS W3-036: LOCAL dynamic AX=1500 record matches one original call; refreshed trace crosses it and reaches #GP at 1c3d42; static 150C/1510 remain outside entry path')
