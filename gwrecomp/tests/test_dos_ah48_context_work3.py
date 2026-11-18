import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence/dos_ah48_context_work3.json').read_text(encoding='utf-8'))
b=json.loads((ROOT/'evidence/empty_config_overlay_work2.json').read_text(encoding='utf-8'))
assert e['target_sha256']==b['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['fixture']['path']==b['empty_config_path'] and e['fixture']['sha256']==b['empty_config_sha256']
assert e['command_tail']=='-k' and e['interrupt_opcode_eip']=='0x001c3d21'
r=e['unsupported_service']['registers']
assert e['unsupported_service']['vector']==0x21 and e['unsupported_service']['function']==0x48
assert r['eax']==0x4800 and r['ebx']==1 and r['ecx']==0x10000 and r['eflags']==0x202
assert e['post_int_eip']=='0x001c3d23' and e['normalized_map_offset']=='0x000c3d23'
assert e['map_public_symbol_predecessor']['name']=='RationalAlloc_' and e['map_public_symbol_successor']['name']=='__CreateNewNHeap_'
assert 'exact function ownership is unresolved' in e['ownership_conclusion']
assert e['branch_after_int'].startswith('unobserved')
print('PASS W3-032: exact -k AH=48 context; post-INT EIP/MAP labels distinguished; no unmeasured return claimed')
