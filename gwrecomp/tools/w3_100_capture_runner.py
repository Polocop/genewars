#!/usr/bin/env python3
"""One explicit-console, oracle_guard-only W3-100 original VESA capture."""
from __future__ import annotations
import hashlib,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MOUNT=ROOT/'build/dosboxx_oracle/C'
FIXTURE=MOUNT/'GENEWARS/GW.EXE'
CONFIG=ROOT/'build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf'
DOSBOX=ROOT/'build/staging-w3-059-exec/Debug/dosbox.exe'
GUARD=ROOT/'tools/oracle_guard.py'
SOURCE=ROOT/'third_party/dosbox-staging-w3-059-instrumented'
CORE=SOURCE/'src/cpu/core_dyn_x86.cpp'
TRACE=MOUNT/'W3_100_TARGETED_VESA_20261009_01.jsonl'
RUN_ID='w3-100-targeted-vesa-20261009-01'
RESULT=ROOT/'evidence/w3_100_targeted_vesa_capture.json'
REVISION='81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f'
GW_SIZE=1_251_658
GW_SHA256='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
CONFIG_SHA256='b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1'
MAX_TRACE=1_048_576
HOST_FLOOR=100*1024**3

def parse_trace_jsonl(raw: bytes) -> list[dict]:
 """Read complete instrumented JSONL rows without legacy event filtering."""
 rows=[]
 for line_number,line in enumerate(raw.splitlines(),1):
  if not line.strip(): continue
  try: row=json.loads(line)
  except (UnicodeDecodeError,json.JSONDecodeError) as exc:
   raise ValueError(f'invalid JSONL row {line_number}: {exc}') from exc
  if isinstance(row,dict): rows.append(row)
 return rows

def sha(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()

def verify_sandbox()->dict:
 p=subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',str(ROOT/'tools/verify_oracle_sandbox.ps1'),'-Json'],cwd=ROOT,capture_output=True,text=True,timeout=30,check=False)
 if p.returncode: raise RuntimeError(f'GWORACLE verification failed: {p.stderr[-1000:]}')
 d=json.loads(p.stdout)
 if d.get('verified') is not True or d.get('volume',d.get('label'))!='GWORACLE': raise RuntimeError(f'GWORACLE not verified: {d}')
 if int(d.get('host_free_bytes',0))<HOST_FLOOR: raise RuntimeError('host free space below floor')
 return d

def main()->int:
 if Path(sys.executable).name.lower()!='python.exe': raise RuntimeError(f'console Python required, got {sys.executable}')
 sandbox=verify_sandbox()
 for p in (FIXTURE,CONFIG,DOSBOX,GUARD,CORE):
  if not p.is_file(): raise FileNotFoundError(p)
 if TRACE.exists() or RESULT.exists(): raise FileExistsError('refusing to overwrite W3-100 artifacts')
 if FIXTURE.stat().st_size!=GW_SIZE or sha(FIXTURE)!=GW_SHA256: raise RuntimeError('GW.EXE identity mismatch')
 if sha(CONFIG)!=CONFIG_SHA256: raise RuntimeError('functional config identity mismatch')
 revision=subprocess.run(['git','-C',str(SOURCE),'rev-parse','HEAD'],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
 if revision!=REVISION: raise RuntimeError(f'pinned Staging revision mismatch: {revision}')
 binary_hash=sha(DOSBOX)
 preflight={'sandbox':sandbox,'fixture':str(FIXTURE),'fixture_bytes':FIXTURE.stat().st_size,'fixture_sha256':GW_SHA256,
  'config':str(CONFIG),'config_sha256':CONFIG_SHA256,'staging_exe':str(DOSBOX),'staging_sha256':binary_hash,
  'source_revision':revision,'core_source_sha256':sha(CORE),'trace':str(TRACE),'trace_cap_bytes':MAX_TRACE,'timeout_seconds':30,
  'runner_python':sys.executable,'explicit_console_python':True}
 env=dict(os.environ)
 for k in tuple(env):
  if k.startswith('GWRECOMP_ANCHOR_') or k.startswith('GWRECOMP_EXEC_TRACE_'):env.pop(k,None)
 env.update({'GWRECOMP_GW_FILE_SIZE':str(GW_SIZE),'GWRECOMP_GW_LE_HEADER_OFFSET':'0x8f50',
  'GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET':'0x9014','GWRECOMP_EXEC_TRACE_PATH':str(TRACE),
  'GWRECOMP_EXEC_TRACE_MAX_BYTES':str(MAX_TRACE),'GWRECOMP_EXEC_TRACE_FILE_IO':'0',
  'GWRECOMP_ANCHOR_MAIN_ENTRY_LINK':'0x000af96c','GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES':'eb765741',
  'GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK':'0x000c8702','GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK':'0x00093f30'})
 evidence_dir=ROOT/'evidence/oracle_runs';evidence_dir.mkdir(parents=True,exist_ok=True)
 stdout_path=evidence_dir/f'{RUN_ID}.stdout.json';stderr_path=evidence_dir/f'{RUN_ID}.stderr.txt'
 if stdout_path.exists() or stderr_path.exists():raise FileExistsError('refusing to overwrite guard output')
 cmd=[sys.executable,str(GUARD),'run','--exe',str(DOSBOX),'--config',str(CONFIG),'--staging-dir',str(MOUNT),
  '--host-drive','E:','--run-id',RUN_ID,'--operation','W3-100 targeted later VESA 0x101/0x180 call and return checkpoints',
  '--commit-sha',REVISION,'--target-sha',GW_SHA256,'--runtime-sha',binary_hash,'--fixture-sha',GW_SHA256,
  '--evidence-dir',str(evidence_dir),'--max-file-text-mib','1','--max-file-bin-mib','64','--max-run-gib','1',
  '--host-floor-gib','100','--timeout-s','30','--growth-text-mibs','8','--growth-bin-mibs','24','--poll-hz','1']
 with stdout_path.open('xb') as out,stderr_path.open('xb') as err:
  run=subprocess.run(cmd,cwd=ROOT,env=env,stdout=out,stderr=err,timeout=40,check=False)
 guard=json.loads(stdout_path.read_text(encoding='utf-8'))
 raw=TRACE.read_bytes() if TRACE.exists() else b''
 if len(raw)>MAX_TRACE:raise RuntimeError(f'trace exceeds cap: {len(raw)}')
 rows=parse_trace_jsonl(raw)
 targeted=[e for e in rows if e.get('event')=='target_runtime_checkpoint' and e.get('w3_100_targeted_vesa') is True]
 order=[e.get('checkpoint') for e in targeted]
 call=next((e for e in targeted if e.get('checkpoint')=='VIDEO_VESA_MODE_CALLSITE'),None)
 entry=next((e for e in targeted if e.get('link_va')==0xA3A00),None)
 ret=next((e for e in targeted if e.get('link_va')==0x9FDD1),None)
 before=next((e for e in targeted if e.get('link_va')==0x9FDEF),None)
 after=next((e for e in targeted if e.get('link_va')==0x9FDF9),None)
 classification='INCONCLUSIVE_TARGET_CALLSITE_ABSENT'
 if call:
  classification='TARGET_CALLSITE_ONLY'
  if entry:classification='TARGET_A3A00_ENTERED'
  if ret:classification='TARGET_CALL_RETURN_OBSERVED'
  if before:classification='TARGET_CALL_FALLTHROUGH_OBSERVED'
  if after:classification='TARGET_ASSIGNMENT_AFTER_OBSERVED'
 result={'schema':'w3-100-targeted-vesa-capture/v1','task':'W3-100','run_id':RUN_ID,'preflight':preflight,
  'guard':{k:guard.get(k) for k in ['run_id','operation','sandbox_verified','sandbox_capacity','host_free_before','host_free_after','limits','exit_reason','cause','detail','exit_code','killed_processes','duration_s','evidence_path','ok']},
  'guard_artifacts':{'stdout_path':str(stdout_path.relative_to(ROOT)),'stdout_bytes':stdout_path.stat().st_size,'stdout_sha256':sha(stdout_path),
   'stderr_path':str(stderr_path.relative_to(ROOT)),'stderr_bytes':stderr_path.stat().st_size},
  'trace':{'path':str(TRACE.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest() if raw else None,
   'event_count':len(rows),'target_event_count':len(targeted),'target_order':order,'target_events':targeted},
  'capture':{'classification':classification,'target_callsite':call,'a3a00_entry':entry,'return_9fdd1':ret,
   'assignment_before_9fdef':before,'assignment_after_9fdf9':after,
   'framebuffer_global_after':after.get('framebuffer_global_samples') if after else None,
   'page_mapping_observed':any('PAGE' in str(x.get('checkpoint','')) for x in targeted),
   'guest_memory_write_observed':False,'visible_frame_observed':False},
  'scope':{'guard_used':True,'new_original_replay_count':1,'guest_executable_modified':False,
   'fixture_or_config_modified':False,'source_install_modified':False,'global_instruction_trace':False,'bulk_memory_dump':False}}
 RESULT.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'result':str(RESULT),'classification':classification,'target_order':order,'trace_bytes':len(raw),
  'guard_cause':guard.get('cause'),'guard_exit':guard.get('exit_reason'),'guard_duration':guard.get('duration_s')},indent=2))
 return 0 if call else 1

if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as exc:
  print(f'PREFLIGHT/REPLAY FAILED CLOSED: {exc}',file=sys.stderr);raise SystemExit(2)
