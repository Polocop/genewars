import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.le_loader import load_le
e=json.loads((ROOT/'evidence/mscdex_outer_return_work3.json').read_text(encoding='utf-8'))
assert e['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
c=e['dpmi_stub_call_context']
assert len(bytes.fromhex(c['stack_bytes_hex']))>=40
assert c['ret_target']=='0x001d2240' and c['outer_ret_slot_offset']==24 and c['outer_ret_target']=='0x001bbb55'
assert bytes.fromhex(c['stack_bytes_hex'])[24:28]==(0x001bbb55).to_bytes(4,'little')
assert c['outer_ret_target_bytes_hex'].startswith('8b45005d5f5ec3')
assert e['first_unsupported']['eip']=='0x001d23a7'
assert 'not configured' in e['first_unsupported']['reason']
packet=e['cdrom_request_events'][0]['real_mode_interrupt']['device_request']
assert packet['packet_length']==26 and packet['command']==3 and packet['transfer_length']==7
image=load_le(ROOT/'evidence/genewars-1_1.exe',rebase=0x100000)
for va,expected in ((0x001d23a7,'cd31c3'),(0x001d2240,c['ret_target_bytes_hex']),(0x001bbb55,c['outer_ret_target_bytes_hex'])):
    actual=bytes(image.mem[va-image.mem_base:va-image.mem_base+len(bytes.fromhex(expected))]).hex()
    assert actual==expected,(hex(va),actual,expected)
print('PASS W3-044: captured stack chain reaches original 1.1 epilogue 0x1BBB55; MSCDEX response remains unconfigured')
