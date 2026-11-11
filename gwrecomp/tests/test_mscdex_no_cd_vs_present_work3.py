import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence'/'mscdex_no_cd_vs_present_work3.json').read_text(encoding='utf-8'))
assert e['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['comparison']['target_and_fixture_identical'] is True
assert e['fixture']['size']==0 and e['fixture']['sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
for x in e['guest_runtime_files']:
 assert x['no_cd_sha256']==x['cd_present_sha256']==x['current_sha256'],x['path']
assert e['guest_runtime_sha256_no_cd']==e['guest_runtime_sha256_cd_present']
n=e['no_cd']; assert n['stop_reason']=='process_terminated' and n['instructions']==7_975_503
frames=n['msc_frames']; assert len(frames)==1
assert frames[0]['service']=='int2f.mscdex_install_check'
assert frames[0]['before']['eax']=='0x00001500'
assert frames[0]['after']['ebx']=='0x00000000' and frames[0]['after']['ecx']=='0x00000000' and frames[0]['after']['edx']=='0x00000000'
assert any('ERROR loading data/text.dat!' in x['text'] for x in n['writes'])
assert any('Genewars requires the CDROM to play!' in x['text'] for x in n['writes'])
assert n['termination']['registers']['eax']=='0x00004c00' and n['termination']['eip']=='0x001afc33'
c=e['cd_present']; assert c['instructions']==99_080 and c['stop_reason']=='emulation_returned_or_stopped_by_hook'
cf=c['msc_frames']; assert [x['before']['eax'] for x in cf]==['0x00001500','0x0000150c','0x00001510']
assert cf[0]['after']['ebx']=='0x00000001' and cf[0]['after']['ecx']=='0x00000003' and cf[0]['after']['eflags']=='0x00000000'
assert cf[1]['after']['ebx']=='0x00000217' and cf[1]['after']['ecx']=='0x00000003' and cf[1]['after']['eflags']=='0x00000000'
req=cf[2]['device_request']; assert req['packet_length']==26 and req['command']==3 and req['transfer_length']==7 and req['transfer_before_hex'].startswith('0a')
assert c['first_unsupported']['eip']=='0x001d23a7' and 'audio-disc metadata is not configured' in c['first_unsupported']['reason']
assert c['last_guest_instruction']['bytes']=='cd31'
assert e['comparison']['work2_overlap'].startswith('W2-058')
print('PASS W3-042: no-CD error/exit versus CD-present MSCDEX 1500/150C success and exact unhandled 1510 subfunction 0A frontier')

