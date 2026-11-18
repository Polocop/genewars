import importlib.util,json,subprocess,sys,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gw_taskq',ROOT/'coordination/taskq.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
e=json.loads((ROOT/'evidence/startup_ah48_current_work3.json').read_text(encoding='utf-8-sig'))
valid=m.post_mscdex_startup_metrics(e,e['target_sha256'])
assert valid['valid'] and valid['stop_kind']=='process_exit' and valid['stop_eip']=='0x001afc33' and valid['process_exit_code']==0
stale=dict(e); stale['runtime_sha256']='0'*64
rejected=m.post_mscdex_startup_metrics(stale,e['target_sha256'])
assert not rejected['valid'] and rejected['reason']=='runtime changed since captured trace'
subprocess.run([sys.executable,str(ROOT/'coordination/taskq.py'),'state'],cwd=ROOT,check=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
text=(ROOT/'PROJECT_STATE.md').read_text(encoding='utf-8')
assert 'no-CD fixture then terminated via DOS AH=4Ch with code 0 at 0x001afc33' in text
assert 'Replay the exact empty-config -k fixture with the measured original CD media mounted' in text
assert 'Historical DPMI AX=0100/next-service checkpoint:' in text
print('PASS post-MSCDEX metrics: current runtime/hash, DOS AH=4Ch gate, stale hash rejection and next CD-present replay are represented accurately')
