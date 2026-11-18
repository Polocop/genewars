import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence/startup_ah48_sites_work3.json').read_text(encoding='utf-8'))
b=json.loads((ROOT/'evidence/empty_config_overlay_work2.json').read_text(encoding='utf-8'))
assert e['target_sha256']==b['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['command_tail']=='-k' and e['fixture']['path']==b['empty_config_path']
assert e['fixture']['sha256']==b['empty_config_sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert e['executed_instruction_count']==6904141
sites=e['ah48_service_site_instructions']; by={x['eip']:x for x in sites}
assert by['0x001c3d21']['bytes']=='cd21' and by['0x001c3d35']['bytes']=='cd21'
assert by['0x001c3d42']['bytes']=='8ec0' and by['0x001c3d42']['registers']['eax']==0x9fca
block=bytes.fromhex(by['0x001c3d21']['basic_block_bytes'])
assert block[:2]==bytes.fromhex('cd21')
assert block[0x14:0x16]==bytes.fromhex('cd21')
assert block[0x21:0x23]==bytes.fromhex('8ec0')
assert block[0x23:0x25]==bytes.fromhex('b449')
services=e['dos_ah48_events']; assert len(services)==2
first,second=services
assert first['eip']=='0x001c3d21' and first['registers']['eax']=='0x00004800' and first['registers']['ebx']=='0x00000001'
assert first['registers_after']['eax']=='0x00009fca' and (int(first['registers_after']['eflags'],16)&1)==0
assert second['eip']=='0x001c3d35' and second['registers']['eax']=='0x000048ca' and second['registers']['ebx']=='0x00001000'
assert second['registers_after']['eax']=='0x00000008' and second['registers_after']['ebx']=='0x00000034'
assert int(second['registers_after']['eflags'],16)&1
fault=e['first_unsupported']; assert fault['kind']=='cpu_exception' and fault['vector']==13 and fault['eip']=='0x001c3d42'
assert fault['registers']['eax']=='0x00009fca' and e['runtime_sha256']
print('PASS W3-034: exact -k AH=48 responses, protected-mode MOV ES,AX #GP, matching runtime hash, no fabricated oracle result')
