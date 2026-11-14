import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
e = json.loads((ROOT / 'evidence' / 'mscdex_ioctl_buffer_work2.json').read_text(encoding='utf-8'))
assert e['target_sha256'] == '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['runtime_files']
for item in e['runtime_files']:
    assert hashlib.sha256((ROOT / item['path']).read_bytes()).hexdigest() == item['sha256'], item['path']
combined = hashlib.sha256(''.join(x['path'] + ':' + x['sha256'] + '\n' for x in e['runtime_files']).encode()).hexdigest()
assert combined == e['runtime_sha256']
request = next(x['request_header'] for x in e['real_mode_0300'] if x.get('request_header'))
assert request['decoded']['command'] == 3
assert request['decoded']['status'] == 0
buf = request['transfer_buffer']
assert (buf['offset'], buf['segment'], buf['linear']) == ('0x0000', '0x2107', '0x00021070')
assert buf['declared_length'] == 7
assert buf['captured_length'] == 32
assert bytes.fromhex(buf['bytes_hex'])[:7] == bytes([10]) + bytes(6)
assert buf['subfunction'] == 10
assert e['first_unsupported']['eip'] == '0x001d23a7'
assert e['executed_instruction_count'] == 99080
print('PASS W2-057: current D: trace points command 03 at far buffer 2107:0000, 7-byte subfunction 0A (audio-disc information); no guest memory was changed')
