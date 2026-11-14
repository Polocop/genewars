import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
e=json.loads((ROOT/'evidence/startup_after_mscdex_work3.json').read_text(encoding='utf-8'))
base=json.loads((ROOT/'evidence/empty_config_overlay_work2.json').read_text(encoding='utf-8'))
assert e['target_sha256']==base['target_sha256']=='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
assert e['command_tail']==base['command_tail']=='-k'
assert e['fixture']['path']==base['empty_config_path']
assert e['fixture']['sha256']==base['empty_config_sha256']=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert e['reference_config_absent'] and e['read_only_reference_unchanged']
assert e['cdrom_inventory']==[]
assert len(e['int2f_services'])==1 and e['int2f_services'][0]['ax']=='0x00001500'
pre=e['query_pre_hook']['frame']['registers']; ev=e['query_dispatch_event']; rm=ev['real_mode_interrupt']
assert e['query_pre_hook']['interrupt_eip']=='0x001d23a7'
assert pre['eax']==0x1500 and pre['ebx']==0 and pre['ecx']==0
assert rm['registers_before']['eax']=='0x00001500' and rm['registers_before']['ebx']=='0x00000000'
assert rm['registers_before']['ecx']=='0x00000000'
assert rm['registers_after']['eax']=='0x00001500' and rm['registers_after']['ebx']=='0x00000000'
assert rm['registers_after']['ecx']=='0x00000000'
assert (int(rm['registers_before']['eflags'],16)&1)==0 and (int(rm['registers_after']['eflags'],16)&1)==0
assert ev['registers_after']['eip']=='0x001d23a9'
assert (int(ev['registers']['eflags'],16)&1)==0 and (int(ev['registers_after']['eflags'],16)&1)==0
assert e['post_return_instructions'] and e['post_return_instructions'][0]['eip']=='0x001d23a9'
assert e['post_return_instructions'][0]['bytes'].startswith('c3')
assert e['post_query_services']
assert any(x['service']=='dpmi31.allocate_dos_memory' for x in e['post_query_services'])
assert e['first_ax0501'] and e['first_ax0501']['service']=='dpmi31.allocate_memory'
assert e['stop_reason'] in ('instruction_limit','emulation_returned_or_stopped_by_hook')
assert e['executed_instruction_count']>=1_000_000
assert not e['process_exit'] and not e['guest_exception'] and not e['unsupported_memory'] and not e['unsupported_port']
# Full caller register image, frame flags and DOS/4GW continuation.
for key in ('eax','ebx','ecx','edx','esi','edi','esp','ebp','eip','eflags'):
    assert key in ev['registers'] and key in ev['registers_after'] and key in e['query_pre_hook']['host_registers']
assert ev['registers']['eax']=='0x00000300' and ev['registers']['ebx']=='0x0000002f'
assert ev['registers']['ecx']=='0x00000000' and ev['registers']['edx']=='0x00000034'
assert ev['registers_after']['eax']=='0x00000300' and ev['registers_after']['ebx']=='0x0000002f'
assert ev['registers_after']['ecx']=='0x00000000' and ev['registers_after']['edx']=='0x00000034'
assert e['query_pre_hook']['frame']['registers']['edx']==0
assert e['mscdes_installation_status'].startswith('undetermined')
assert 'Dependence beyond the 2,000,000-instruction trace is untested' in e['cd_dependency']
first=e['first_post_query_service']
assert first['service']=='dpmi31.allocate_dos_memory' and first['eip']=='0x001d23a7'
assert first['registers']['ebx']=='0x00001000'
assert first['registers_after']['eax']=='0x00002208'
assert first['registers_after']['edx']=='0x0000003c'
b=e['observed_post_return_branch']
assert b['eip']=='0x001b955f' and b['bytes']=='7525' and b['eax']==0 and b['zf'] is True
assert b['next_eip']=='0x001b9561' and b['taken'] is False
lf=e['later_frontier']
assert lf['service']=='dpmi31.allocate_memory' and lf['eip']=='0x001c3cc1'
assert lf['registers']['eax']=='0x00000501' and lf['registers']['ecx']=='0x00001000'
assert lf['registers_after']['ebx']=='0x0000003c' and lf['registers_after']['ecx']=='0x00002000'
assert lf['run_stop']=='instruction_limit' and lf['run_last_eip']=='0x001c3aa7'
assert lf['first_unsupported'] is None
print('PASS W3-029: exact -k fixture, INT 2F AX=1500 frame/CF, resume path and next service validated')

