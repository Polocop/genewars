import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence/native_ds_compare_work3.json').read_text(encoding='utf-8'))
b=json.loads((ROOT/'evidence/empty_config_overlay_work2.json').read_text(encoding='utf-8'))
n=json.loads((ROOT/'evidence/native_entry_after_dpmi0006_work1.json').read_text(encoding='utf-8'))
assert e['target_sha256']==b['target_sha256']==n['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['command_tail']==b['command_tail']=='-k'
assert e['fixture']['sha256']==b['empty_config_sha256']
o=e['original_checkpoint']; assert o['eip']=='0x001afb60' and o['bytes']=='8b06' and o['ds']=='0x1100'
assert o['ds_base']=='0x00011000' and o['registers']['esi']==0 and o['linear_ea']=='0x00011000'
assert o['memory_dword']=='00000100'
f=e['native_memory_fault']; assert f['memory_fault_instruction_va']=='0x000AFB60' and f['memory_fault_selector']=='0x0000' and f['memory_fault_linear']=='0x00000000'
assert e['native_instruction_bytes']=='8b06' and e['native_env_slot']=='0x0000' and e['native_psp_env']=='0x1100'
assert e['map_public_predecessor']['name']=='start' and e['map_public_successor']['name']=='__exit__'
assert e['post_ah48_runtime_observation']['ah48_events']
assert e['post_ah48_runtime_observation']['next_exception']['kind']=='cpu_exception'
print('PASS W3-033: same target/-k; original DS=1100 valid read versus native selector-0 fault; AH=48 continuation captured separately')
