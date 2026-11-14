import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence'/'text_dat_gate_work3.json').read_text(encoding='utf-8'))
assert all(hashlib.sha256((ROOT/x['path']).read_bytes()).hexdigest()==x['sha256'] for x in e['runtime_files'])
assert hashlib.sha256(''.join(x['path']+':'+x['sha256']+'\n' for x in e['runtime_files']).encode()).hexdigest()==e['runtime_sha256']
assert e['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['replay']['stop_reason']=='process_terminated' and e['replay']['process_exit']['code']==0
assert e['replay']['fixture']['size']==0 and e['replay']['read_only_reference_unchanged'] is True
assert e['source_freshness']['superseded_capture_is_stale'] and e['source_freshness']['fresh_current_runtime_sha256']==e['runtime_sha256']
f=e['dynamic_frontier']
assert (f['guest_eip'],f['path'],f['tail_observations_for_path'])==('0x001af93a','data/text.dat',85)
assert f['host_result']['eax']=='0x00000002' and int(f['host_result']['eflags'],16)&1
assert e['replay']['process_exit']['eip']=='0x001afc33'
assert not e['reference_asset_inventory']['flat_DATA/TEXT.DAT_present']
assert len(e['reference_asset_inventory']['text_dat_files'])==6
assert e['reference_asset_inventory']['reference_source_unchanged'] is True
assert 'cmpl   $0x5b8d80,_lbMemoryAvailable' in e['static_contract']['startup_source_window']
assert 'add    $0x2c,%ebx' in e['static_contract']['loader_source_window']
print('PASS W3-040 current replay hash, file-query outcome, process exit, loader contract, and immutable asset inventory')



