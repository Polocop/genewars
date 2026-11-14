import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
e = json.loads((ROOT / 'evidence' / 'mscdex_packet_work2.json').read_text(encoding='utf-8'))
assert e['target_sha256'] == '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['stop_reason'] == 'emulation_returned_or_stopped_by_hook'
assert e['executed_instruction_count'] == 99080
assert e['first_unsupported']['vector'] == 47
assert e['first_unsupported']['eip'] == '0x001d23a7'
frames = [x for x in e['real_mode_0300'] if x['frame']['registers']['eax'] == 0x1510]
assert len(frames) == 1
f = frames[0]
assert f['frame']['registers']['ecx'] == 3
h = f['request_header']
assert h['segment'] == '0x2104' and h['offset'] == '0x0000'
assert h['bytes_hex'] == '1a00030000000000000000000000000007210700000000000000000000000000'
assert h['decoded'] == {
    'length': 0x1a, 'unit': 0, 'command': 3, 'status': 0,
    'reserved_hex': '0000000000000000',
    'command_data_hex': '00000007210700000000000000000000000000'
}
assert e['runtime_files']
for item in e['runtime_files']:
    assert hashlib.sha256((ROOT / item['path']).read_bytes()).hexdigest() == item['sha256']
combined = hashlib.sha256(''.join(x['path'] + ':' + x['sha256'] + '\n' for x in e['runtime_files']).encode()).hexdigest()
assert combined == e['runtime_sha256']
print('PASS W2-055: D: replay captures 26-byte DOS request header, command 03, initial status 0; AX=1510 remains explicitly trapped')

