import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence/startup_continuation_work3.json').read_text(encoding='utf-8'))
base=json.loads((ROOT/'evidence/empty_config_overlay_work2.json').read_text(encoding='utf-8'))
assert e['task']=='W3-031'
assert e['target_sha256']==base['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['command_tail']==base['command_tail']=='-k'
assert e['fixture']['path']==base['empty_config_path']
assert e['fixture']['sha256']==base['empty_config_sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert e['executed_instruction_count']==6904125
assert e['stop_reason']=='emulation_returned_or_stopped_by_hook'
assert e['last_guest_eip']=='0x001c3d21'
assert e['first_unsupported']['kind']=='interrupt_service'
assert e['first_unsupported']['vector']==0x21 and e['first_unsupported']['function']==0x48
r=e['first_unsupported']['registers']
assert r['eax']==0x4800 and r['ebx']==1 and r['ecx']==0x10000
assert r['eip']==0x001c3d23 and r['eflags']&1==0
assert 'no success value was fabricated' in e['first_unsupported']['reason']
assert e['int2f_services']==[{'eip':'0x001d23a7','ax':'0x00001500','service':'int2f.mscdex_install_check','handled':True}]
assert e['executed_instruction_count']>2_000_000
assert e['guest_exception'] is None and e['unsupported_memory'] is None and e['unsupported_port'] is None
print('PASS W3-031: exact fixture; original-byte trace reached unsupported DOS AH=48 with captured AX/BX/CX, no fabricated return; one AX=15xx')
