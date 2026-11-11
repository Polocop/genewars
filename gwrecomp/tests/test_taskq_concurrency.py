import os, pathlib, subprocess, sys, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
CLI=ROOT/'coordination'/'taskq.py'
class QueueConcurrency(unittest.TestCase):
 def test_two_workers_cannot_claim_same_task(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'cache') as d:
   db=pathlib.Path(d)/'queue.sqlite3'; env={**os.environ,'GW_TASK_DB':str(db),'PYTHONDONTWRITEBYTECODE':'1'}
   init="import sys;sys.path.insert(0,r'%s');import taskq; c=taskq.con(); taskq.add_task(c,{'id':'RACE','title':'race','description':'','priority':1,'roles':['WORK1','WORK3'],'dependencies':[],'acceptance':[],'tests':[],'files':[],'evidence':[]})" % str(ROOT/'coordination')
   p=subprocess.run([sys.executable,'-c',init],env=env,capture_output=True,text=True); self.assertEqual(p.returncode,0,p.stderr)
   ps=[subprocess.Popen([sys.executable,str(CLI),'claim','--role',role,'--worker',worker,'--id','RACE'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for role,worker in [('WORK1','A'),('WORK3','B')]]
   results=[p.communicate(timeout=30)+(p.returncode,) for p in ps]; codes=[x[2] for x in results]
   self.assertEqual(codes.count(0),1,results); self.assertEqual(sum(x!=0 for x in codes),1,results)
if __name__=='__main__': unittest.main()
