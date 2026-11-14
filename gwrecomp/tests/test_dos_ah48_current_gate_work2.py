import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
e = json.loads((ROOT / 'evidence' / 'dos_ah48_current_gate_work2.json').read_text(encoding='utf-8'))
assert e['target_sha256'] == '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['stop_reason'] == 'process_terminated'
assert e['process_exit']['code'] == 0
assert e['executed_instruction_count'] == 7_975_503
assert e['first_unsupported'] is None
assert e['read_only_reference_unchanged'] is True
assert e['fixture']['size'] == 0
assert e['dos_memory_state']['dos_ah48_allocations'] == {}
assert e['runtime_files']
for item in e['runtime_files']:
    path = ROOT / item['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], item['path']
combined = hashlib.sha256(''.join(x['path'] + ':' + x['sha256'] + '\n' for x in e['runtime_files']).encode()).hexdigest()
assert combined == e['runtime_sha256']
missing_text = [x for x in e['runtime_service_tail']
                if (x.get('dos_filename') or {}).get('path', '').casefold() == 'data/text.dat'
                and x.get('service') == 'dos21.get_file_attributes.error']
assert missing_text, 'expected measured data/text.dat lookup in service tail'
assert all(x.get('registers_after', {}).get('eax') == '0x00000002' for x in missing_text)
root = ROOT / 'build' / 'dos_c_reference_20261006' / 'GENEWARS'
assert not (root / 'DATA' / 'TEXT.DAT').exists()
assert (root / 'DATA' / 'TEXT' / 'ENG' / 'TEXT.DAT').is_file()
print('PASS W2-054: current runtime replay terminates cleanly; AH=48 allocations are released; data/text.dat remains unresolved and is localized under DATA/TEXT/<lang>/TEXT.DAT')

