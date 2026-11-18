#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from typing import Any
MAX_SAMPLE_BYTES=64
EXPECTED_SIZE=0x4B000

def classify(rows:list[dict[str,Any]])->dict[str,Any]:
 req=next((r for r in rows if r.get('checkpoint')=='W3_188_B_SCREEN_ALLOC_REQUEST'),None)
 ret=next((r for r in rows if r.get('checkpoint')=='W3_188_B_SCREEN_ALLOC_RETURN'),None)
 store=next((r for r in rows if r.get('checkpoint')=='W3_129_B_SCREEN_POST_STORE'),None)
 free=next((r for r in rows if r.get('checkpoint')=='W3_129_MEMORY_FREE_ENTRY'),None)
 if not all((req,ret,store,free)):
  return {'classification':'INCONCLUSIVE','reason':'same-run allocation/request/store/free chain incomplete','request':req,'return':ret,'store':store,'free':free}
 try:
  size=int(req['eax']); pointer=int(ret['eax']); stored=int(store['w3_129_b_screen_value']); freed=int(free['eax'])
  raw=bytes.fromhex(store.get('w3_188_sample_hex','')); bounds=store.get('w3_188_sample_bounds_valid') is True
  same=pointer==stored==freed and pointer==int(store['eax'])
  ordered=req['sequence']<ret['sequence']<store['sequence']<free['sequence']
  valid=size==EXPECTED_SIZE and same and ordered and bounds and len(raw)<=MAX_SAMPLE_BYTES and len(raw)==store.get('w3_188_sample_bytes')
 except (KeyError,ValueError,TypeError):
  valid=False; raw=b''; bounds=False; same=False; ordered=False; size=pointer=stored=freed=0
 return {'classification':'SAMPLE_CAPTURED' if valid else 'INCONCLUSIVE','request_size':hex(size),'pointer':hex(pointer),'stored_pointer':hex(stored),'free_pointer':hex(freed),'same_pointer':same,'event_order_valid':ordered,'sample_bounds_valid':bounds,'sample_bytes':len(raw),'sample_hex':raw.hex(),'nonzero_bytes':sum(b!=0 for b in raw),'sample_is_pixel_payload':'UNKNOWN; bytes sampled from the measured allocation only','checkpoints':{'request':{'sequence':req.get('sequence'),'link_va':hex(int(req.get('link_va',0))),'eax':hex(int(req.get('eax',0)))},'return':{'sequence':ret.get('sequence'),'link_va':hex(int(ret.get('link_va',0))),'eax':hex(int(ret.get('eax',0)))},'store':{'sequence':store.get('sequence'),'link_va':hex(int(store.get('link_va',0))),'eip':hex(int(store.get('eip',0))),'ds_descriptor_valid':store.get('ds_descriptor_valid'),'ds_base':hex(int(store.get('ds_base',0))),'ds_limit':hex(int(store.get('ds_limit',0))),'global_sample_valid':store.get('w3_129_b_screen_sample_valid'),'sample_candidate':store.get('w3_188_sample_candidate'),'sample_bounds_valid':store.get('w3_188_sample_bounds_valid')},'free':{'sequence':free.get('sequence'),'link_va':hex(int(free.get('link_va',0))),'eax':hex(int(free.get('eax',0)))}},'reason':None if valid else 'allocation/request/pointer/order/sample validation failed'}
from tools.w3_100_capture_runner import sha,verify_sandbox
from tools.w3_143_postopen_branch import MAX_TRACE_BYTES,parse_jsonl
from tools.w3_182_original_ax0300_capture_runner import CONFIG,CONFIG_SHA256,CUE,CUE_SHA256,DOSBOX,GW_SHA256,GW_SIZE,GUARD,REVISION,SOURCE
MOUNT=ROOT/'build/dosboxx_oracle/C'
FIXTURE=MOUNT/'GENEWARS/GW.EXE'
CORE=SOURCE/'src/cpu/core_dyn_x86.cpp'
RUN_ID='w3-188-b-screen-payload-20261009-01'
TRACE=MOUNT/'W3_188_B_SCREEN_PAYLOAD_20261009_01.jsonl'
RESULT=ROOT/'evidence/w3_188_b_screen_payload.json'
EVDIR=ROOT/'evidence/oracle_runs'
STDOUT=EVDIR/f'{RUN_ID}.stdout.json'; STDERR=EVDIR/f'{RUN_ID}.stderr.txt'

def main():
    if any(a in ('-h','--help') for a in sys.argv[1:]):
        print('Usage: w3_188_b_screen_payload_runner.py [--help]; without --help performs one guarded replay.')
        return 0
    sandbox=verify_sandbox()
    if not sandbox.get('verified') or sandbox.get('label')!='GWORACLE': raise RuntimeError(f'GWORACLE preflight failed: {sandbox}')
    for p in (FIXTURE,CONFIG,CUE,DOSBOX,GUARD,CORE,TRACE.parent,EVDIR):
        if not p.exists(): raise FileNotFoundError(p)
    if FIXTURE.stat().st_size!=GW_SIZE or sha(FIXTURE)!=GW_SHA256: raise RuntimeError('fixture identity mismatch')
    if sha(CONFIG)!=CONFIG_SHA256 or sha(CUE)!=CUE_SHA256: raise RuntimeError('config/CUE hash mismatch')
    if not re.search(r'(?im)^\s*imgmount\s+d\s+.*\.cue.*-ro\b',CONFIG.read_text(encoding='utf-8')): raise RuntimeError('CUE is not mounted read-only')
    revision=subprocess.run(['git','-C',str(SOURCE),'rev-parse','HEAD'],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
    if revision!=REVISION: raise RuntimeError(f'pinned revision mismatch: {revision}')
    src=CORE.read_text(encoding='utf-8',errors='replace')
    for token in ('w3_188_alloc_request_candidate','w3_188_alloc_return_candidate','w3_188_sample_bounds_valid','w3_188_sample_hex'):
        if token not in src: raise RuntimeError(f'instrumentation missing {token}')
    for p in (TRACE,RESULT,STDOUT,STDERR):
        if p.exists(): raise FileExistsError(f'refusing to overwrite {p}')
    binary_sha=sha(DOSBOX); env=dict(os.environ)
    for key in tuple(env):
        if key.startswith('GWRECOMP_ANCHOR_') or key.startswith('GWRECOMP_EXEC_TRACE_'): env.pop(key,None)
    env.update({'GWRECOMP_GW_FILE_SIZE':str(GW_SIZE),'GWRECOMP_GW_LE_HEADER_OFFSET':'0x8f50','GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET':'0x9014',
      'GWRECOMP_EXEC_TRACE_PATH':str(TRACE),'GWRECOMP_EXEC_TRACE_MAX_BYTES':str(MAX_TRACE_BYTES),'GWRECOMP_EXEC_TRACE_FILE_IO':'0',
      'GWRECOMP_ANCHOR_MAIN_ENTRY_LINK':'0x000af96c','GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES':'eb765741',
      'GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK':'0x000c8702','GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK':'0x00093f30','GWRECOMP_W3_171_ENABLE_SAMPLES':'0'})
    command=[sys.executable,str(GUARD),'run','--exe',str(DOSBOX),'--config',str(CONFIG),'--staging-dir',str(MOUNT),'--host-drive','E:','--run-id',RUN_ID,'--operation','W3-188 bounded B_SCREEN payload sample','--commit-sha',REVISION,'--target-sha',GW_SHA256,'--runtime-sha',binary_sha,'--fixture-sha',GW_SHA256,'--evidence-dir',str(EVDIR),'--max-file-text-mib','1','--max-file-bin-mib','64','--max-run-gib','1','--host-floor-gib','100','--timeout-s','30','--growth-text-mibs','8','--growth-bin-mibs','24','--poll-hz','1']
    with STDOUT.open('xb') as out, STDERR.open('xb') as err:
        subprocess.run(command,cwd=ROOT,env=env,stdout=out,stderr=err,timeout=40,check=False)
    guard=json.loads(STDOUT.read_text(encoding='utf-8'))
    raw=TRACE.read_bytes() if TRACE.exists() else b''
    if len(raw)>MAX_TRACE_BYTES: raise RuntimeError('trace cap exceeded')
    rows=parse_jsonl(raw); outcome=classify(rows)
    result={**outcome,'schema':'w3-188-b-screen-payload/v1','task':'W3-188','run_id':RUN_ID,
      'source':{'target_sha256':GW_SHA256,'fixture_bytes':FIXTURE.stat().st_size,'config_sha256':sha(CONFIG),'cue_sha256':sha(CUE),'staging_revision':REVISION,'instrumented_core_sha256':sha(CORE),'staging_binary_sha256':binary_sha},
      'preflight':{'sandbox':sandbox,'cue_read_only_mount':True,'timeout_seconds':30,'trace_cap_bytes':MAX_TRACE_BYTES,'sample_cap_bytes':64,'global_trace':False},
      'guard':{k:guard.get(k) for k in ('run_id','operation','sandbox_verified','sandbox_capacity','host_free_before','host_free_after','limits','exit_reason','cause','detail','exit_code','killed_processes','duration_s','evidence_path','ok')},
      'trace':{'path':str(TRACE.relative_to(ROOT)).replace('\\','/'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest() if raw else None,'event_count':len(rows)},
      'limitations':['The sample is raw memory from the measured allocation; nonzero bytes do not establish pixel or framebuffer semantics.','No visible-frame, menu, or gameplay claim follows.']}
    RESULT.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'result':str(RESULT),'classification':outcome['classification'],'sample_bytes':outcome.get('sample_bytes'),'nonzero_bytes':outcome.get('nonzero_bytes'),'guard_cause':guard.get('cause')},indent=2))
    return 0 if guard.get('sandbox_verified') else 1

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as e:
        print(f'FAIL CLOSED: {e}',file=sys.stderr); raise SystemExit(2)

