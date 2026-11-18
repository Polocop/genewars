import json, os, pathlib, subprocess, sys, tempfile, sqlite3
ROOT=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(dir=ROOT/'cache') as td:
    d=pathlib.Path(td); db=d/'queue.sqlite3'; evidence=d/'proof.json'; evidence.write_text('{"ok":true}')
    spec=d/'task.json'; spec.write_text(json.dumps({'id':'T1','title':'transition test','roles':['WORK1'],'priority':1,'acceptance':['test'],'files':['x'],'tests':[]}))
    env={**os.environ,'GW_TASK_DB':str(db),'PYTHONDONTWRITEBYTECODE':'1'}
    def run(*args): subprocess.run([sys.executable,str(ROOT/'coordination'/'taskq.py'),*map(str,args)],cwd=ROOT,env=env,check=True,text=True,capture_output=True)
    run('add',spec)
    run('claim','--role','WORK1','--worker','WORK1','--id','T1')
    run('block','T1','--worker','WORK1','--reason','stale reason','--evidence',evidence)
    run('unblock','T1','--worker','WORK1','--reason','resolved by evidence','--evidence',evidence)
    c=sqlite3.connect(db)
    status=c.execute("select status from tasks where id='T1'").fetchone()[0]
    action,detail=c.execute("select action,detail from events where task_id='T1' order by id desc limit 1").fetchone()
    detail=json.loads(detail)
    assert status=='READY' and action=='UNBLOCKED'
    assert detail['previous_reason']=='stale reason' and detail['previous_evidence']
    c.close()
print('task transitions PASS')
