#!/usr/bin/env python3
"""One bounded oracle_guard-only replay for the later PlaySmacker call chain."""
from __future__ import annotations
import hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.w3_100_capture_runner import sha,verify_sandbox
from tools.w3_266_capture_runner import CONFIG,CONFIG_SHA256,CUE,CUE_SHA256,FIXTURE,GW_SHA256,GW_SIZE,REVISION,STAGING,EVIDENCE_DIR
from tools.w3_275_second_smacker_call import MAX_BYTES,MAX_ROWS,analyze,parse_bounded
DOSBOX=ROOT/'build/staging-w3-059-ah44-stack-20261009/Debug/dosbox.exe'
GUARD=ROOT/'tools/oracle_guard.py'
RUN_ID='w3-275-second-smacker-call-20261009-01'
TRACE=ROOT/'build/dosboxx_oracle/C/W3_275_SECOND_SMACKER_20261009_01.jsonl'
RESULT=ROOT/'evidence/w3_275_second_smacker_call.json'
STDOUT=EVIDENCE_DIR/f'{RUN_ID}.stdout.json'
STDERR=EVIDENCE_DIR/f'{RUN_ID}.stderr.txt'
SOURCE_FILES=('src/cpu/core_dyn_x86.cpp','src/gui/render/opengl_renderer.cpp','src/dos/exec_trace.h','src/dos/dos_files.cpp')
def main()->int:
 if Path(sys.executable).name.lower()!='python.exe': raise RuntimeError(f'console Python required: {sys.executable}')
 sandbox=verify_sandbox()
 for p in (FIXTURE,CONFIG,CUE,DOSBOX,GUARD):
  if not p.is_file(): raise FileNotFoundError(p)
 if any(p.exists() for p in (TRACE,RESULT,STDOUT,STDERR)): raise FileExistsError('refusing to overwrite W3-275 artifacts')
 if FIXTURE.stat().st_size!=GW_SIZE or sha(FIXTURE)!=GW_SHA256: raise RuntimeError('GW fixture identity mismatch')
 if sha(CONFIG)!=CONFIG_SHA256 or sha(CUE)!=CUE_SHA256: raise RuntimeError('config/CUE hash mismatch')
 if '-ro' not in CONFIG.read_text(encoding='utf-8').casefold(): raise RuntimeError('CD mount is not read-only')
 rev=subprocess.run(['git','-C',str(STAGING),'rev-parse','HEAD'],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
 if rev!=REVISION: raise RuntimeError(f'pinned source revision mismatch: {rev}')
 source_hashes={rel:sha(STAGING/rel) for rel in SOURCE_FILES}
 binary_hash=sha(DOSBOX)
 env=dict(os.environ)
 prefixes=('GWRECOMP_ANCHOR_','GWRECOMP_EXEC_TRACE_','GWRECOMP_W3_262_','GWRECOMP_W3_264_','GWRECOMP_W3_267_','GWRECOMP_W3_269_','GWRECOMP_W3_271_','GWRECOMP_W3_274_','GWRECOMP_W3_275_')
 for key in tuple(env):
  if key.startswith(prefixes): env.pop(key,None)
 env.update({'GWRECOMP_GW_FILE_SIZE':str(GW_SIZE),'GWRECOMP_GW_LE_HEADER_OFFSET':'0x8f50','GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET':'0x9014','GWRECOMP_ANCHOR_MAIN_ENTRY_LINK':'0x000af96c','GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES':'eb765741','GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK':'0x000c8702','GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK':'0x00093f30','GWRECOMP_EXEC_TRACE_PATH':str(TRACE),'GWRECOMP_EXEC_TRACE_MAX_BYTES':str(MAX_BYTES),'GWRECOMP_EXEC_TRACE_FILE_IO':'0','GWRECOMP_W3_262_CAPTURE':'1','GWRECOMP_W3_262_TRACE_PATH':str(TRACE),'GWRECOMP_W3_262_RUN_ID':RUN_ID,'GWRECOMP_W3_267_CAPTURE_VIEWPORT':'1','GWRECOMP_W3_269_CAPTURE':'1','GWRECOMP_W3_269_RUN_ID':RUN_ID})
 EVIDENCE_DIR.mkdir(parents=True,exist_ok=True)
 command=[sys.executable,str(GUARD),'run','--exe',str(DOSBOX),'--config',str(CONFIG),'--staging-dir',str(ROOT/'build/dosboxx_oracle/C'),'--host-drive','E:','--run-id',RUN_ID,'--operation','W3-275 bounded later PlaySmacker call/entry/return capture','--commit-sha',REVISION,'--target-sha',GW_SHA256,'--runtime-sha',binary_hash,'--fixture-sha',GW_SHA256,'--evidence-dir',str(EVIDENCE_DIR),'--max-file-text-mib','1','--max-file-bin-mib','64','--max-run-gib','1','--host-floor-gib','100','--timeout-s','120','--growth-text-mibs','8','--growth-bin-mibs','24','--poll-hz','1']
 with STDOUT.open('xb') as out,STDERR.open('xb') as err: subprocess.run(command,cwd=ROOT,env=env,stdout=out,stderr=err,timeout=130,check=False)
 guard=json.loads(STDOUT.read_text(encoding='utf-8')); raw=TRACE.read_bytes() if TRACE.exists() else b''
 rows=parse_bounded(raw); analysis=analyze(rows)
 result={'schema':'w3-275-second-smacker-call/v1','task':'W3-275','run_id':RUN_ID,'evidence_level':'ORIGINAL_OBSERVED' if analysis['entry_929d0_seen'] else 'INCONCLUSIVE','provenance':{'target_sha256':GW_SHA256,'fixture_bytes':FIXTURE.stat().st_size,'config_sha256':sha(CONFIG),'cue_sha256':sha(CUE),'cue_read_only':True,'staging_revision':rev,'source_sha256':source_hashes,'binary_sha256':binary_hash},'preflight':{'sandbox':sandbox,'timeout_s':120,'trace_cap_bytes':MAX_BYTES,'trace_row_cap':MAX_ROWS,'target_events_cap':16,'file_io_suppressed':True,'global_trace':False,'bulk_memdump':False,'guest_modified':False},'guard':{k:guard.get(k) for k in ('run_id','operation','sandbox_verified','sandbox_capacity','host_free_before','host_free_after','limits','exit_reason','cause','detail','exit_code','killed_processes','duration_s','evidence_path','ok')},'trace':{'path':str(TRACE.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest() if raw else None,'rows':len(rows)},'analysis':analysis,'scope':{'original_replays':1,'menu_verified':False,'gameplay_verified':False}}
 RESULT.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'result':str(RESULT),'analysis':analysis,'guard_cause':guard.get('cause'),'trace_bytes':len(raw),'trace_rows':len(rows)},indent=2))
 return 0 if guard.get('sandbox_verified') is True else 1
if __name__=='__main__':
 try: raise SystemExit(main())
 except Exception as exc: print(f'W3-275 failed closed: {exc}',file=sys.stderr); raise SystemExit(2)
