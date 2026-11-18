import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name): return json.loads((ROOT/name).read_text(encoding='utf-8-sig'))
TARGET='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
EMPTY='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
summary=load('evidence/startup_ah48_current_work3.json')
full=load('evidence/startup_ah48_fresh_current_work3.json')
assert summary['task']=='W3-038' and summary['target_sha256']==TARGET and summary['command_tail']=='-k'
assert summary['fixture']['sha256']==EMPTY and summary['fixture']['size']==0 and summary['fixture_matches_gate']
assert summary['source_capture_sha256']==hashlib.sha256((ROOT/summary['source_capture']).read_bytes()).hexdigest()
assert summary['runtime_sha256']==hashlib.sha256((ROOT/'runtime/dos_services.py').read_bytes()).hexdigest()
assert summary['executed_instruction_count']==7975503 and summary['stop_reason']=='process_terminated'
assert summary['process_exit']['code']==0 and summary['process_exit']['eip']=='0x001afc33'
assert summary['last_guest_eip']=='0x001afc33' and summary['guest_exception'] is None and summary['first_unsupported'] is None
services=summary['int2f_services']; assert len(services)==1 and services[0]['ax']=='0x00001500' and services[0]['handled'] is True
query=full['query_dispatch_event']; rm=query['real_mode_interrupt']
assert rm['registers_before']['eax']=='0x00001500' and rm['registers_before']['ebx']=='0x00000000' and rm['registers_before']['ecx']=='0x00000000' and rm['registers_before']['edx']=='0x00000000'
assert rm['registers_after']['eax']=='0x00001500' and rm['registers_after']['ebx']=='0x00000000' and rm['registers_after']['ecx']=='0x00000000' and rm['registers_after']['edx']=='0x00000000'
assert int(rm['registers_after']['eflags'],16)&1==0 and query['registers_after']['eip']=='0x001d23a9'
assert len(full['dos_ah48_events'])>=2
first,second=full['dos_ah48_events'][:2]
assert first['registers']['eax']=='0x00004800' and first['registers']['ebx']=='0x00000001' and first['registers_after']['eax']=='0x0000004c' and int(first['registers_after']['eflags'],16)&1==0
assert second['registers']['eax']=='0x0000484c' and second['registers']['ebx']=='0x00001000' and second['registers_after']['eax']=='0x00000008' and int(second['registers_after']['eflags'],16)&1==1
site=next(x for x in full['ah48_service_site_instructions'] if x['eip']=='0x001c3d42')
d=site['descriptor_fault_analysis']; assert site['bytes']=='8ec0' and site['registers']['eax']==0x4c
assert d['attempted_selector']=='0x004c' and d['descriptor_within_limit'] and d['descriptor']['base']=='0x0009fca0' and d['descriptor']['limit']=='0x0000000f' and d['descriptor']['present']
assert not any(x['ax'] in ('0x0000150c','0x00001510') for x in services)
assert full['runtime_sha256']==summary['runtime_sha256'] and full['target_sha256']==TARGET
# Keep the generated gate honest about process termination, not a CPU exception.
subprocess.run([sys.executable,str(ROOT/'coordination/taskq.py'),'state'],cwd=ROOT,check=True,env={**__import__('os').environ,'PYTHONDONTWRITEBYTECODE':'1'})
state=(ROOT/'PROJECT_STATE.md').read_text(encoding='utf-8')
assert 'no-CD fixture then terminated via DOS AH=4Ch with code 0 at 0x001afc33' in state
assert 'Replay the exact empty-config -k fixture with the measured original CD media mounted' in state
print('PASS W3-038: current -k replay verifies AX=1500/AH=48 selector response, no GP, and the measured AH=4Ch no-CD stop')

