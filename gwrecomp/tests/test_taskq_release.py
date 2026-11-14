import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI = ROOT / "coordination" / "taskq.py"

class QueueReleaseTests(unittest.TestCase):
    def test_release_is_audited_and_requires_matching_claim_owner(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "cache") as temp:
            base = pathlib.Path(temp)
            db = base / "queue.sqlite3"
            evidence = base / "orphan.json"
            evidence.write_text('{"active_agents": ["WORK2"]}\n', encoding="utf-8")
            env = {**os.environ, "GW_TASK_DB": str(db), "PYTHONDONTWRITEBYTECODE": "1"}
            init = (
                "import sys;sys.path.insert(0,r'%s');import taskq;"
                "c=taskq.con();taskq.add_task(c,{'id':'RECOVER','title':'recover','description':'',"
                "'priority':1,'roles':['WORK1'],'dependencies':[],'acceptance':[],'tests':[],'files':[],'evidence':[]})"
            ) % str(ROOT / "coordination")
            setup = subprocess.run([sys.executable, "-c", init], env=env, capture_output=True, text=True)
            self.assertEqual(setup.returncode, 0, setup.stderr)
            claim = subprocess.run([sys.executable, str(CLI), "claim", "--role", "WORK1", "--worker", "WORK1", "--id", "RECOVER"],
                                   env=env, capture_output=True, text=True)
            self.assertEqual(claim.returncode, 0, claim.stderr + claim.stdout)
            mismatch = subprocess.run([sys.executable, str(CLI), "release", "RECOVER", "--worker", "WORK2",
                                       "--expected-owner", "OTHER", "--reason", "stale", "--evidence", str(evidence)],
                                      env=env, capture_output=True, text=True)
            self.assertNotEqual(mismatch.returncode, 0)
            release = subprocess.run([sys.executable, str(CLI), "release", "RECOVER", "--worker", "WORK2",
                                      "--expected-owner", "WORK1", "--reason", "no active owner",
                                      "--evidence", str(evidence)], env=env, capture_output=True, text=True)
            self.assertEqual(release.returncode, 0, release.stderr + release.stdout)
            import sqlite3
            conn = sqlite3.connect(db)
            task = conn.execute("SELECT status,owner,role,claimed_at,evidence FROM tasks WHERE id='RECOVER'").fetchone()
            event = conn.execute("SELECT actor,action,detail FROM events WHERE task_id='RECOVER' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual(task[:4], ("READY", None, None, None))
            self.assertEqual(json.loads(task[4]), [str(evidence)])
            self.assertEqual(event[:2], ("WORK2", "RELEASED"))
            detail = json.loads(event[2])
            self.assertEqual(detail["previous_owner"], "WORK1")
            self.assertEqual(detail["reason"], "no active owner")
            conn.close()

if __name__ == "__main__":
    unittest.main()
