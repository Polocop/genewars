import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('taskq',Path('coordination/taskq.py'))
taskq=importlib.util.module_from_spec(spec); spec.loader.exec_module(taskq)
valid={'target_sha256':'hash-a','cases_completed':120,
       'selected_functions':[{'result':'PASS','patterns_passed':4,'patterns_failed':0} for _ in range(29)]+[{'result':'FAIL','patterns_passed':0,'patterns_failed':4}]}
expected={'valid':True,'reason':'target hash and case denominator verified','cases':120,'pass':116,'fail':4,'functions_pass':29,'functions_fail':1}
assert taskq.differential_corpus_metrics(valid,'hash-a')==expected
assert not taskq.differential_corpus_metrics(valid,'hash-b')['valid']
assert not taskq.differential_corpus_metrics({**valid,'cases_completed':119},'hash-a')['valid']
assert not taskq.differential_corpus_metrics({**valid,'selected_functions':valid['selected_functions'][:-1]},'hash-a')['valid']
print('PASS: hash, corpus denominator, and changed function list validation')

startup={'target_sha256':'hash-a','command_tail':'-k','gate':{'local_64':'01','local_68':'01'},
         'root_hits':{'main_':{},'setup_game':{'guest_eip':'0x00194ac0'}},
         'execution':{'stop_reason':'process_terminated','process_exit':{'code':0}},
         'early_setup_game_exit':{'return_address_link':'0x00094ae9'}}
sm=taskq.startup_gate_metrics(startup,'hash-a')
assert sm['valid'] and sm['setup_game_reached'] and not sm['playintro_reached']
assert sm['exit_return_link']=='0x00094ae9'
assert not taskq.startup_gate_metrics(startup,'hash-b')['valid']
assert not taskq.startup_gate_metrics({**startup,'command_tail':'-'},'hash-a')['valid']
print('PASS: startup gate target hash, option, gate locals, setup_game root, and early exit validation')
read_evidence={'target_sha256':'hash-a','empty_fixture_run':{'unsupported_service':{'function':0x3f,'eip':'0x001d2137'},
 'interrupt':{'eip_int_opcode_assumption':'0x001d2137','registers':{'ebx':'0x00000006','ecx':'0x00001000'}},
 'caller_function_boundary':{'name':'__qread_','bytes_at_int':'cd21'}}}
rm=taskq.getconfigs_read_metrics(read_evidence,'hash-a')
assert rm['valid'] and rm['service']==0x3f and rm['function']=='__qread_'
assert not taskq.getconfigs_read_metrics(read_evidence,'hash-b')['valid']
assert not taskq.getconfigs_read_metrics({**read_evidence,'empty_fixture_run':{}},'hash-a')['valid']
print('PASS: GetConfigs AH=3F service/context/symbol and target hash validation')
eof_evidence={'target_sha256':'hash-a','getconfigs':{'guest_return_eip':'0x00114f3a','return_al':'0x01','config_file_attempts':[{'operation':'read','path':'config.ini','result':0}]},
 'next_stop':{'kind':'DPMI INT 31h AX=0600 Lock Linear Region','guest_eip':'0x001d23a7','original_bytes':'cd31','map_function':'_DoINTR_',
 'registers':{'eax':'0x00000600','ebx':'0x0000001a','ecx':'0x0000ff40','esi':'0x00000000','edi':'0x00006221'}}}
em=taskq.getconfigs_eof_metrics(eof_evidence,'hash-a')
assert em['valid'] and em['service'].startswith('DPMI INT 31h') and em['getconfigs_al']=='0x01'
assert not taskq.getconfigs_eof_metrics(eof_evidence,'hash-b')['valid']
assert not taskq.getconfigs_eof_metrics({**eof_evidence,'getconfigs':{'return_al':'0x00'}},'hash-a')['valid']
print('PASS: GetConfigs EOF result, DPMI AX=0600 location/register contract, and target hash validation')

