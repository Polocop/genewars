import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence'/'text_dat_name_transform_work3.json').read_text(encoding='utf-8'))
assert hashlib.sha256((ROOT/'evidence'/'genewars-1_1-le_disasm.s').read_bytes()).hexdigest()==e['disassembly_sha256']
assert hashlib.sha256((ROOT/'evidence'/'genewars-1_1.map').read_bytes()).hexdigest()==e['map_sha256']
assert e['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
for item in e['guest_runtime_files']:
 assert hashlib.sha256((ROOT/item['path']).read_bytes()).hexdigest()==item['sha256'],item['path']
assert hashlib.sha256(''.join(x['path']+':'+x['sha256']+'\n' for x in e['guest_runtime_files']).encode()).hexdigest()==e['guest_runtime_sha256']
assert e['source_freshness']['guest_runtime_files_match_capture'] is True
assert e['source_freshness']['probe_script_changed_after_replay'] is True
s=e['original_disassembly']; cb=s['callback_func_14bb0']; reg=s['registration_at_GetConfigs_EOF']; setter=s['setter_func_989e0']; use=s['filename_callback_consumption_in_func_989ec']
assert 'cmpb   $0x2a,(%eax)' in cb and 'sprintf_' in cb and 'aSS_16' in cb
assert 'data_11765c' in cb and 'data_117655' in cb and 'Language' not in cb
assert 'func_989e0' in reg and 'func_14bb0' in reg
assert 'mov    %eax,data_10a804' in setter and 'call   *data_10a804' in use
assert s['format_string']=='%s%s'
d=e['dynamic_reconciliation']
assert d['observed_path']=='data/text.dat' and d['observed_path_bytes_hex']=='646174612f746578742e646174'
assert d['result']['eax']=='0x00000002' and int(d['result']['eflags'],16)&1
assert d['runtime_stop']=='process_terminated' and d['runtime_exit']['code']==0 and d['runtime_exit']['eip']=='0x001afc33'
assert d['read_only_reference_unchanged'] is True
print('PASS W3-041: callback registration/transform and dynamic path agree; guest runtime hashes current; runner change is explicitly recorded')
