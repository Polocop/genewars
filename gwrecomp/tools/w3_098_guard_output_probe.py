#!/usr/bin/env python3
"""Audit W3-095 empty guard output and verify console child stream capture only."""
from __future__ import annotations
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def sha(path: Path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()

def capture_child():
 code='import json,sys; print(json.dumps({"stdout_probe":"preserved"})); print("stderr_probe_preserved", file=sys.stderr)'
 p=subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,timeout=10,check=False)
 parsed=json.loads(p.stdout.strip()) if p.returncode==0 else None
 return {'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'parsed':parsed}

def main():
 base=ROOT/'evidence/oracle_runs'
 stdout=base/'w3-095-original-psp-tail-20261009-01.stdout.json'
 stderr=base/'w3-095-original-psp-tail-20261009-01.stderr.txt'
 trace=ROOT/'build/dosboxx_oracle/C/W3_095_ORIGINAL_PSP_TAIL_20261009_01.jsonl'
 assoc=subprocess.run(['cmd.exe','/c','assoc .py'],capture_output=True,text=True,timeout=10,check=False)
 ftype=subprocess.run(['cmd.exe','/c','ftype Python.File'],capture_output=True,text=True,timeout=10,check=False)
 child=capture_child()
 result={
  'schema':'w3-098-guard-output-capture/v1','task':'W3-098',
  'w3_095_artifacts':{
   'runner':'tools/w3_095_capture_runner.py',
   'invocation_observed_this_session':'PowerShell call operator invoked the .py path directly, without explicitly naming the project console Python executable.',
   'stdout_file_bytes':stdout.stat().st_size if stdout.exists() else None,
   'stderr_file_bytes':stderr.stat().st_size if stderr.exists() else None,
   'trace_bytes':trace.stat().st_size if trace.exists() else None,
   'trace_sha256':sha(trace) if trace.exists() else None,
   'guard_final_json_present':False,
   'cause':'UNKNOWN; association is inspected below, but available evidence cannot prove it caused the missing guard output.'
  },
  'windows_association':{'assoc_py':assoc.stdout.strip(),'assoc_returncode':assoc.returncode,'ftype_python_file':ftype.stdout.strip(),'ftype_returncode':ftype.returncode},
  'explicit_console_python':{'executable':sys.executable,'captured_child':child,'stdout_json_preserved':child['parsed']=={'stdout_probe':'preserved'},'stderr_preserved':child['stderr'].strip()=='stderr_probe_preserved'},
  'safe_future_invocation':'& E:\\GWRecomp\\.venv\\Scripts\\python.exe -B E:\\GWRecomp\\tools\\<runner>.py; require non-empty guard stdout JSON and persist stdout/stderr before parsing.',
  'scope':{'dosbox_invoked':False,'oracle_guard_invoked':False,'vhdx_touched':False,'w3_095_artifacts_modified':False}
 }
 out=ROOT/'evidence/w3_098_guard_output_capture.json'
 out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'evidence':str(out),'association':result['windows_association'],'explicit_stdout_ok':result['explicit_console_python']['stdout_json_preserved'],'explicit_stderr_ok':result['explicit_console_python']['stderr_preserved'],'w3_095_cause':result['w3_095_artifacts']['cause']},indent=2))
 return 0 if result['explicit_console_python']['stdout_json_preserved'] and result['explicit_console_python']['stderr_preserved'] else 1

if __name__=='__main__': raise SystemExit(main())
