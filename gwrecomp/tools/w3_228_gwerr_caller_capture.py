from __future__ import annotations
import os as _gw_os
from pathlib import Path as _GwPath
_GW_ROOT=str(_GwPath(__file__).resolve().parents[1])
_GW_FX=_gw_os.environ.get("GENEWARSFX_ROOT",_gw_os.path.join(_GW_ROOT,"third_party","GeneWarsFX"))
import json
import hashlib
from pathlib import Path
MAX_TRACE_BYTES=1_048_576
MAX_EVENTS=512
CPU_EVENT='original_cpu_int21_gwerr_open_entry'
def _int(v): return int(v,0) if isinstance(v,str) else v
def normalize_gwerr_path(path):
    if not isinstance(path,str) or not path or len(path)>64: return False
    p=path.replace('/','\\').upper()
    return p in {'GW.ERR','GENEWARS\\GW.ERR','C:\\GENEWARS\\GW.ERR'}
def parse_trace(raw:bytes):
    if len(raw)>MAX_TRACE_BYTES: raise ValueError('trace exceeds 1 MiB')
    events=[]
    for line in raw.splitlines():
        if not line.strip(): continue
        try: row=json.loads(line)
        except json.JSONDecodeError: continue
        if isinstance(row,dict): events.append(row)
        if len(events)>MAX_EVENTS: raise ValueError('raw event count exceeds 512')
    return events
def correlate(events):
    entries=[e for e in events if e.get('event')==CPU_EVENT and normalize_gwerr_path(e.get('pathname'))]
    if len(entries)>1: raise ValueError('GW.ERR CPU entry cap exceeded')
    if not entries:
        opened=[e for e in events if e.get('event')=='dos_handle_open' and str(e.get('path',e.get('requested_path',''))).upper().replace('/','\\').endswith('GW.ERR')]
        return {'classification':'INCONCLUSIVE_GWERR_OPEN_WITHOUT_CPU_ENTRY' if opened else 'INCONCLUSIVE_GWERR_OPEN_NOT_OBSERVED','cpu_entry':None,'open_event':min(opened,key=lambda e:_int(e.get('sequence',0))) if opened else None}
    cpu=entries[0]
    if not (cpu.get('mapping_valid') is True and cpu.get('int21_bytes_verified') is True and cpu.get('pathname_status')=='sampled'):
        return {'classification':'INCONCLUSIVE_CPU_MAPPING_OR_PATH_VALIDATION','cpu_entry':cpu,'open_event':None}
    candidates=[e for e in events if e.get('event')=='dos_handle_open' and e.get('process_psp')==cpu.get('process_psp') and _int(e.get('sequence',-1))>_int(cpu.get('sequence',-1)) and _int(e.get('sequence',0))-_int(cpu.get('sequence',0))<=8 and str(e.get('path',e.get('requested_path',''))).upper().replace('/','\\').endswith('GW.ERR')]
    if not candidates: return {'classification':'INCONCLUSIVE_NO_CORRELATED_OPEN_RECORD','cpu_entry':cpu,'open_event':None}
    opened=min(candidates,key=lambda e:_int(e.get('sequence',0)))
    return {'classification':'ORIGINAL_GWERR_CALLER_AND_OPEN_CORRELATED','cpu_entry':cpu,'open_event':opened}
def build_result(trace_path:Path,preflight:dict,guard:dict):
    raw=trace_path.read_bytes() if trace_path.exists() else b''
    events=parse_trace(raw)
    capture=correlate(events)
    checkpoints=[e for e in events if e.get('event')=='target_runtime_checkpoint']
    last=checkpoints[-1] if checkpoints else None
    video=[e for e in checkpoints if str(e.get('checkpoint','')).startswith('VIDEO_')]
    return {'schema':'gwrecomp.original-gwerr-caller-capture-w3-228/v1','task':'W3-228','run_id':preflight['run_id'],'evidence_level':'ORIGINAL_OBSERVED' if capture['classification'].startswith('ORIGINAL_') else 'INCONCLUSIVE','preflight':preflight,'guard':guard,'trace':{'path':str(trace_path),'exists':trace_path.is_file(),'bytes':len(raw),'sha256':__import__('hashlib').sha256(raw).hexdigest() if raw else None,'raw_event_count':len(events),'max_bytes':MAX_TRACE_BYTES},'capture':capture,'execution_frontier':{'last_target_checkpoint':{k:last.get(k) for k in ('sequence','checkpoint','checkpoint_ordinal','phase','process_psp','link_va','eip','eax','ebx','ecx','edx','esi','edi','ebp','esp','eflags','elapsed_ms')} if last else None,'video_checkpoints':[{'sequence':e.get('sequence'),'checkpoint':e.get('checkpoint'),'link_va':e.get('link_va'),'elapsed_ms':e.get('elapsed_ms'),'framebuffer_global_samples':e.get('framebuffer_global_samples'),'sample_bytes':e.get('w3_153_sample_bytes_total',0)} for e in video],'gwerr_open_events':[e for e in events if e.get('event')=='dos_handle_open' and str(e.get('path',e.get('requested_path',''))).upper().replace('/','\\').endswith('GW.ERR')],'dosbox_stop_cause':guard.get('cause'),'dosbox_stop_detail':guard.get('detail'),'guard_duration_s':guard.get('duration_s')},'scope':{'guest_binary_modified':False,'config_modified':False,'source_install_modified':False,'guest_response_injected':False,'global_trace':False,'bulk_memory_dump':False,'cpu_entry_cap':1,'pathname_cap_bytes':64,'stack_words_cap':6}}

# One-shot guarded runner is kept in this task-owned module so ownership stays exact.
def run_capture():
    import os, subprocess, sys
    from pathlib import Path
    root=Path((_GW_ROOT))
    mount=root/'build/dosboxx_oracle/C'; fixture=mount/'GENEWARS/GW.EXE'
    config=root/'build/dosboxx_oracle/dosbox-staging.w3-067-functional.conf'
    cue=Path((_GW_FX + '\\evidence\\original_disc\\Genewars (Europe) (En,Fr,De,Es,It,Sv).cue'))
    dosbox=root/'build/staging-w3-059-exec/Debug/dosbox.exe'; guard_py=root/'tools/oracle_guard.py'
    source=root/'third_party/dosbox-staging-w3-059-instrumented'; cpu_source=source/'src/cpu/cpu.cpp'
    trace=mount/'W3_228_GWERR_CALLER_20261009_01.jsonl'; run_id='w3-228-gwerr-caller-20261009-01'
    result_path=root/'evidence/w3_228_gwerr_caller_capture.json'; revision='81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f'
    gw_size=1_251_658; gw_sha='2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f'
    config_sha='b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1'
    cue_sha='1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5'
    host_floor=100*1024**3
    def sha_file(path):
        h=hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
        return h.hexdigest()
    verified=subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',str(root/'tools/verify_oracle_sandbox.ps1'),'-Json'],cwd=root,capture_output=True,text=True,timeout=30)
    if verified.returncode: raise RuntimeError('GWORACLE verification failed: '+verified.stderr[-1000:])
    sandbox=json.loads(verified.stdout)
    if sandbox.get('verified') is not True or sandbox.get('volume',sandbox.get('label'))!='GWORACLE': raise RuntimeError(f'GWORACLE not verified: {sandbox}')
    if sandbox.get('host_free_bytes',0)<host_floor: raise RuntimeError('host free-space floor failed')
    for path in (fixture,config,cue,dosbox,guard_py,cpu_source):
        if not path.is_file(): raise FileNotFoundError(path)
    if (fixture.stat().st_size,sha_file(fixture))!=(gw_size,gw_sha): raise RuntimeError('GW.EXE fixture identity mismatch')
    if sha_file(config)!=config_sha: raise RuntimeError('functional config changed')
    if sha_file(cue)!=cue_sha: raise RuntimeError('original CUE hash changed')
    pinned=subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
    if pinned!=revision: raise RuntimeError('Staging source revision changed: '+pinned)
    if trace.exists() or result_path.exists(): raise FileExistsError('refusing to overwrite W3-228 capture')
    gwerr=mount/'GENEWARS/GW.ERR'
    before={'exists':gwerr.exists(),'size_bytes':gwerr.stat().st_size if gwerr.exists() else None,'sha256':sha_file(gwerr) if gwerr.exists() and gwerr.stat().st_size<=MAX_TRACE_BYTES else None}
    pre={'sandbox':sandbox,'fixture':str(fixture),'fixture_size':fixture.stat().st_size,'fixture_sha256':sha_file(fixture),'config':str(config),'config_sha256':sha_file(config),'cue':str(cue),'cue_sha256':sha_file(cue),'cue_read_only_mount':True,'dosbox':str(dosbox),'dosbox_sha256':sha_file(dosbox),'staging_revision':pinned,'cpu_source_sha256':sha_file(cpu_source),'trace':str(trace),'trace_max_bytes':MAX_TRACE_BYTES,'timeout_seconds':30,'gwerr_fixture_before_run':before,'run_id':run_id,'launch':['C:','CD \\GENEWARS','GENEWARS.EXE (no launcher tail)','DOS4GW child tail from prior measured run:  -k 38928']}
    env=dict(os.environ)
    for key in tuple(env):
        if key.startswith('GWRECOMP_ANCHOR_') or key.startswith('GWRECOMP_EXEC_TRACE_'): env.pop(key,None)
    env.update({'GWRECOMP_GW_FILE_SIZE':str(gw_size),'GWRECOMP_GW_LE_HEADER_OFFSET':'0x8f50','GWRECOMP_GW_LE_OBJECT_TABLE_OFFSET':'0x9014','GWRECOMP_EXEC_TRACE_PATH':str(trace),'GWRECOMP_EXEC_TRACE_MAX_BYTES':str(MAX_TRACE_BYTES),'GWRECOMP_EXEC_TRACE_FILE_IO':'0','GWRECOMP_ANCHOR_MAIN_ENTRY_LINK':'0x000af96c','GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES':'eb765741','GWRECOMP_ANCHOR_CRT_ARGV_LOAD_LINK':'0x000c8702','GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK':'0x00093f30'})
    evidence_dir=root/'evidence/oracle_runs'; evidence_dir.mkdir(parents=True,exist_ok=True)
    stdout_path=evidence_dir/f'{run_id}.stdout.json'; stderr_path=evidence_dir/f'{run_id}.stderr.txt'
    cmd=[sys.executable,str(guard_py),'run','--exe',str(dosbox),'--config',str(config),'--staging-dir',str(mount),'--host-drive','E:','--run-id',run_id,'--operation','W3-228 one-shot natural GW.ERR open caller capture','--commit-sha',revision,'--target-sha',gw_sha,'--runtime-sha',pre['dosbox_sha256'],'--fixture-sha',gw_sha,'--evidence-dir',str(evidence_dir),'--max-file-text-mib','1','--max-file-bin-mib','64','--max-run-gib','1','--host-floor-gib','100','--timeout-s','30','--growth-text-mibs','8','--growth-bin-mibs','24','--poll-hz','1']
    with stdout_path.open('xb') as stdout,stderr_path.open('xb') as stderr:
        proc=subprocess.run(cmd,cwd=root,env=env,stdout=stdout,stderr=stderr,timeout=40,check=False)
    guard=json.loads(stdout_path.read_text(encoding='utf-8'))
    result=build_result(trace,pre,guard); result['guard_returncode']=proc.returncode
    result['scope'].update({'oracle_guard_used':True,'sandbox_verified':sandbox['verified'],'guest_binary_modified':False,'config_modified':False,'personal_source_modified':False,'guest_responses_injected':False})
    result_path.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'evidence':str(result_path),'classification':result['capture']['classification'],'trace':result['trace'],'guard_exit_reason':guard.get('exit_reason'),'duration_s':guard.get('duration_s')},indent=2))
    return 0 if result['capture']['classification']=='ORIGINAL_GWERR_CALLER_AND_OPEN_CORRELATED' else 1

def audit_existing():
    import json
    from pathlib import Path
    root=Path((_GW_ROOT))
    out=root/'evidence/w3_228_gwerr_caller_capture.json'
    report=root/'reports/coordination/w3_228_gwerr_caller_capture.md'
    prior=json.loads(out.read_text(encoding='utf-8'))
    pre=prior['preflight']; guard=prior['guard']
    result=build_result(Path(pre['trace']),pre,guard)
    result['guard_returncode']=prior.get('guard_returncode')
    result['scope'].update(prior.get('scope',{}))
    gwerr=Path((_GW_ROOT + '\\build\\dosboxx_oracle\\C\\GENEWARS\\GW.ERR'))
    result['post_run_GW_ERR']={'exists':gwerr.exists(),'size_bytes':gwerr.stat().st_size if gwerr.exists() else None,'sha256':hashlib.sha256(gwerr.read_bytes()).hexdigest() if gwerr.exists() and gwerr.stat().st_size<=MAX_TRACE_BYTES else None}
    result['frontier_interpretation']='The run reached measured video framebuffer assignment checkpoints, with the sampled pointer global changing to 0xA0000, and later reached W3_134_LBMEMORYALLOC_RETURN. No framebuffer pixel payload was sampled; this is not proof of a displayed first frame.'
    out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    last=result['execution_frontier']['last_target_checkpoint']
    assigns=[x for x in result['execution_frontier']['video_checkpoints'] if x['checkpoint']=='VIDEO_FRAMEBUFFER_ASSIGN_AFTER']
    pointer=assigns[-1]['framebuffer_global_samples'][0]['value_u32'] if assigns and assigns[-1].get('framebuffer_global_samples') else None
    report.write_text(
        '# W3-228 — GW.ERR caller capture and bounded replay frontier\n\n'
        f"Evidence: [{out.name}](../../{out.as_posix()})\n\n"
        f"Preflight verified GWORACLE ({pre['sandbox']['capacity_bytes']} bytes), the exact GeneWars target and CUE hashes, and the pinned Staging revision. The only replay ran through `oracle_guard` with its 30-second timeout and 1 MiB trace cap. The guard terminated it for timeout after {guard.get('duration_s')} seconds; the last captured target checkpoint was {last['checkpoint']} at link VA 0x{last['link_va']:X} (sequence {last['sequence']}, elapsed {last['elapsed_ms']} ms).\n\n"
        f"The trace records a natural DOS open of `GENEWARS\\GW.ERR` at sequence {result['capture']['open_event']['sequence'] if result['capture']['open_event'] else 'unknown'}, assigned to PSP handle {result['capture']['open_event'].get('entry') if result['capture']['open_event'] else 'unknown'}, but the target-PSP CPU_Interrupt hook emitted no matching pre-dispatch caller record. Caller and open request registers therefore remain UNKNOWN. This does not show that the path was absent; the open itself is observed.\n\n"
        f"The run also records framebuffer assignment checkpoints; the last sampled pointer value was {('0x%X'%pointer) if pointer is not None else 'not available'}. No pixel payload was sampled, so the first framebuffer is not verified. No further replay was performed. GW.ERR before the run: {pre['gwerr_fixture_before_run']}; after the run: {result['post_run_GW_ERR']}.\n",
        encoding='utf-8')
    print(json.dumps({'classification':result['capture']['classification'],'last_checkpoint':last,'gwerr_open':result['capture']['open_event'],'guard_cause':guard.get('cause'),'duration_s':guard.get('duration_s'),'trace_bytes':result['trace']['bytes'],'post_run_GW_ERR':result['post_run_GW_ERR'],'report':str(report)},ensure_ascii=False,indent=2))

if __name__=='__main__' and __import__('sys').argv[-1:] == ['--run']:
    try: raise SystemExit(run_capture())
    except Exception as exc:
        print('PREFLIGHT/REPLAY FAILED CLOSED: '+str(exc),file=__import__('sys').stderr)
        raise SystemExit(2)
elif __name__=='__main__' and __import__('sys').argv[-1:] == ['--audit-existing']:
    audit_existing()

