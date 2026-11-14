import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
evidence = json.loads((ROOT / 'evidence/startup_runtime_current_work2.json').read_text(encoding='utf-8'))
assert evidence['target_sha256'] == '2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert evidence['stop_reason'] == 'process_terminated'
assert evidence['process_exit']['code'] == 0
assert evidence['executed_instruction_count'] == 7_975_503
assert evidence['first_unsupported'] is None
assert evidence['read_only_reference_unchanged'] is True
assert evidence['fixture']['size'] == 0
assert evidence['fixture']['sha256'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
required = {'runtime/dos_services.py', 'runtime/dos_filesystem.py', 'runtime/dos_cdrom.py',
            'runtime/dos_iso9660.py', 'tests/probe_real_mode_2f_work2.py'}
assert required <= {item['path'] for item in evidence['runtime_files']}
for item in evidence['runtime_files']:
    assert hashlib.sha256((ROOT / item['path']).read_bytes()).hexdigest() == item['sha256'], item['path']
combined = hashlib.sha256(''.join(x['path'] + ':' + x['sha256'] + '\n'
                                    for x in evidence['runtime_files']).encode()).hexdigest()
assert combined == evidence['runtime_sha256']
events = [item.get('real_mode_interrupt', {}) for item in evidence['interrupts']]
assert any(item.get('service') == 'int2f.mscdex_install_check'
           and item.get('registers_before', {}).get('eax') == '0x00001500'
           for item in events)
assert evidence['last_guest_eip'] == '0x001afc33'
assert evidence['dos_memory_state']['dos_ah48_allocations'] == {}
print('PASS W2-074: fresh no-CD -k replay matches current Runtime, handled AX=1500, exited cleanly after 7,975,503 instructions; MENU not reached')
