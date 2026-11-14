import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.le_loader import load_le
load=lambda p: json.loads((ROOT/p).read_text(encoding='utf-8-sig'))
TARGET='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
fx='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
current=load('evidence/gp_ds_contract_work3.json')
forced=load('evidence/gp_ds_historical_fault_work3.json')
old=load('evidence/startup_ah48_sites_work3.json')
compare=load('evidence/native_ds_compare_work3.json')
native=load('evidence/native_entry_after_dpmi0006_work1.json')
seed=load('evidence/native_ds_seed_comparison_work3.json')
assert current['task']=='W3-045' and current['target_sha256']==TARGET and current['command_tail']=='-k'
assert current['fixture']['size']==0 and current['fixture']['sha256']==fx
assert hashlib.sha256((ROOT/'runtime/dos_services.py').read_bytes()).hexdigest()==current['runtime_sha256']
assert current['stop_reason']=='process_terminated' and current['process_exit']['code']==0 and current['last_guest_eip']=='0x001afc33'
assert current['guest_exception'] is None and current['first_unsupported'] is None
sites=current['ah48_service_site_instructions']; valid=next(x for x in sites if x['eip']=='0x001c3d42')
assert valid['bytes']=='8ec0' and valid['registers']['eax']==0x4c and valid['registers']['eflags']==0xa07
assert valid['segments']=={'cs':'0x000c','ds':'0x0014','es':'0x0014','ss':'0x0014','fs':'0x0000','gs':'0x0000'}
d=valid['descriptor_fault_analysis']; assert d['attempted_selector']=='0x004c' and d['table']=='LDT' and d['descriptor_within_limit']
assert d['descriptor']['present'] and d['descriptor']['base']=='0x0009fca0' and d['descriptor']['limit']=='0x0000000f'
assert d['host_selector_base']==0x9fca0 and d['host_selector_limit']==15
assert valid['segment_descriptors']['cs']['base']=='0x00000000' and valid['segment_descriptors']['ds']['limit']=='0xffffffff'
assert len(bytes.fromhex(valid['stack_context']['bytes_hex']))==64
assert current['dos_ah48_events'][0]['registers_after']['eax']=='0x0000004c'
assert current['dos_ah48_events'][1]['registers_after']['eax']=='0x00000008' and int(current['dos_ah48_events'][1]['registers_after']['eflags'],16)&1
orig=current['original_start_checkpoint_1afb60'][0]
assert orig['eip']=='0x001afb60' and orig['bytes']=='8b06' and orig['ds']=='0x1100' and orig['ds_base']=='0x00011000'
assert orig['ds_limit']=='0x0000ffff' and orig['ds_descriptor']['present'] and orig['ds_descriptor']['base']=='0x00011000'
assert orig['registers']['esi']==0 and orig['linear_ea']=='0x00011000' and orig['memory_dword']=='00000100'
# Historical (pre-W2-053) measured AH=48 response and actual exception record.
assert old['runtime_sha256']=='677b995a8693875845feca859a8d562c098d0998947e888b506bba7c71d25399'
assert old['dos_ah48_events'][0]['registers_after']['eax']=='0x00009fca'
assert old['dos_ah48_events'][1]['registers_after']['eax']=='0x00000008'
hgp=compare['post_ah48_runtime_observation']['next_exception']
assert hgp['vector']==13 and hgp['eip']=='0x001c3d42' and hgp['fault_bytes'].startswith('8ec0')
assert hgp['registers']['eax']=='0x00009fca' and hgp['registers']['edx']=='0x00009fca'
assert hgp['registers']['ebx']=='0x80000008' and hgp['registers']['eflags']=='0x00000a07'
# Re-run only the recorded pre-fix AH=48 AX value in an explicitly labeled harness.
assert forced['guest_exception']['vector']==13 and forced['guest_exception']['eip']=='0x001c3d42'
assert len(forced['measured_harness_overrides'])==1
assert forced['measured_harness_overrides'][0]['measured_return_ax']=='0x9fca'
assert 'not current oracle behavior' in forced['measured_harness_overrides'][0]['purpose']
fgp=next(x for x in forced['ah48_service_site_instructions'] if x['eip']=='0x001c3d42')
assert fgp['registers']=={k:int(v,16) for k,v in hgp['registers'].items()}
fd=fgp['descriptor_fault_analysis']; assert fd['attempted_selector']=='0x9fca' and fd['table']=='GDT'
assert fd['descriptor_offset']=='0x00009fc8' and not fd['descriptor_within_limit'] and fd['descriptor'] is None
assert fd['gdtr']['base']=='0x00004000' and fd['gdtr']['limit']==0x1107
assert fd['ldtr']['base']=='0x00008000' and fd['ldtr']['limit']==0xfff
assert fgp['segments']['cs']=='0x000c' and fgp['segments']['ds']=='0x0014' and fgp['segments']['es']=='0x0014'
assert len(bytes.fromhex(fgp['stack_context']['bytes_hex']))==64
# W1-026 native snapshot and actual seeded environment bytes.
assert native['passed'] and native['target_sha256']==TARGET and native['command_tail']=='-k'
assert native['bootstrap_layout']['environment_selector']=='0x1100' and native['bootstrap_layout']['environment_linear']=='0x00009000'
assert native['captured_exception']['memory_fault_pending']==0
assert seed['native_source_evidence_sha256']==hashlib.sha256((ROOT/seed['native_source_evidence']).read_bytes()).hexdigest()
assert seed['native_boot_seed_sha256']==hashlib.sha256((ROOT/seed['native_boot_seed']).read_bytes()).hexdigest()
assert seed['native_env_prefix_hex'][:8]=='00000100' and seed['native_env_first_dword_hex']=='00000100'
assert seed['original_first_dword_hex']==orig['memory_dword'] and seed['native_env_first_dword_hex']==seed['original_first_dword_hex']
print('PASS W3-045: current AX=004C descriptor fixes the old AX=9FCA GDT-limit #GP; original/native DS read same dword with distinct backing addresses; W1-026 has no null-selector fault')

