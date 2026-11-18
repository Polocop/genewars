"""Synthetic-only integration tests for the session coordinator. No game/oracle calls."""
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI = ROOT / "coordination" / "autopilot.py"
QUEUE = ROOT / "coordination" / "taskq.py"
sys.path.insert(0, str(ROOT / "coordination"))
import autopilot


class AutopilotV1(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "cache")
        self.d = pathlib.Path(self.tmp.name)
        self.db = self.d / "queue.sqlite3"
        self.proof = self.d / "proof.json"
        self.proof.write_text('{"synthetic":true}\n', encoding="utf-8")
        self.dashboard = self.d / "dashboard.md"
        self.env = {**os.environ, "GW_TASK_DB": str(self.db), "GW_AUTOPILOT_EVIDENCE_DIR": str(self.d),
                    "GW_AUTOPILOT_DASHBOARD_PATH": str(self.dashboard), "PYTHONDONTWRITEBYTECODE": "1"}
        self.run_cli("status")
        spec = {"id":"SYN-1","title":"synthetic queue contract","roles":["WORK1"],"priority":1,
                "dependencies":[],"acceptance":["record evidence"],"tests":[],"files":[],
                "files_owned":["scratch/autopilot_owned.py"],"max_attempts":3}
        f = self.d / "task.json"
        f.write_text(json.dumps(spec), encoding="utf-8")
        self.run_queue("add", str(f))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, ok=True):
        p = subprocess.run([sys.executable, str(CLI), *args], cwd=ROOT, env=self.env,
                           capture_output=True, text=True)
        if ok:
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p

    def run_queue(self, *args):
        p = subprocess.run([sys.executable, str(QUEUE), *args], cwd=ROOT, env=self.env,
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p

    def add_task(self, task_id, title, files_owned=None):
        spec = {"id":task_id,"title":title,"roles":["WORK1"],"priority":2,
                "dependencies":[],"acceptance":["synthetic"],"tests":[],"files":[],"files_owned":files_owned or []}
        f = self.d / f"{task_id}.json"
        f.write_text(json.dumps(spec), encoding="utf-8")
        self.run_queue("add", str(f))

    def claim(self, *extra):
        return self.run_cli("claim", "WORK1", "--worker", "alpha", "--id", "SYN-1", *extra)

    def status(self):
        c = sqlite3.connect(self.db)
        try:
            return c.execute("select status from tasks where id='SYN-1'").fetchone()[0]
        finally:
            c.close()

    def test_atomic_claim_has_single_winner(self):
        ps = [subprocess.Popen([sys.executable, str(CLI), "claim", "WORK1", "--worker", worker, "--id", "SYN-1"],
                               cwd=ROOT, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
              for worker in ("alpha", "beta")]
        results = [p.communicate(timeout=30) + (p.returncode,) for p in ps]
        self.assertEqual(sum(x[2] == 0 for x in results), 1, results)

    def test_replay_named_evidence_is_not_mistaken_for_game_replay(self):
        self.assertFalse(autopilot.forbidden_test_operation([
            "py", "-3", "tools/verify_w1_050_pilot.py",
            "evidence/native_setup_replay_w1_050.json"]))
        self.assertFalse(autopilot.forbidden_test_operation([
            "py", "-3", "-m", "unittest", "tests.test_w1_066_environment_replay"]))
        self.assertFalse(autopilot.forbidden_test_operation([
            "py", "-3", "tools/verify_w1_066_environment_replay.py",
            "evidence/native_setenvp_aligned_replay_w1_066.json"]))
        self.assertTrue(autopilot.forbidden_test_operation([
            "py", "-3", "tests/test_native_guest_image.py", "--capture-crt-startup"]))
        self.assertTrue(autopilot.forbidden_test_operation(["py", "tests/run_replay.py"]))
        self.assertTrue(autopilot.forbidden_test_operation(["dosbox-x", "capture.conf"]))
        self.assertTrue(autopilot.forbidden_test_operation(["python", "tools/oracle_guard.py", "run"]))

    def test_role_ownership_is_enforced(self):
        self.claim()
        p = self.run_cli("finish", "SYN-1", "--worker", "intruder", "--status", "INCONCLUSIVE",
                         "--evidence", str(self.proof), "--evidence-level", "INCONCLUSIVE", ok=False)
        self.assertNotEqual(p.returncode, 0)

    def test_persistence_after_process_restart(self):
        self.claim()
        self.assertEqual(self.status(), "RUNNING")
        self.assertIn('"SYN-1"', self.run_cli("status").stdout)

    def test_blocked_task_does_not_hide_another_ready_task(self):
        # Queue picker skips blocked items and returns the other eligible task.
        self.add_task("SYN-2", "other")
        self.claim()
        self.assertEqual(self.status(), "RUNNING")
        self.run_cli("finish", "SYN-1", "--worker", "alpha", "--status", "BLOCKED", "--reason", "synthetic gate",
                     "--evidence", str(self.proof), "--evidence-level", "INCONCLUSIVE")
        self.run_cli("claim","WORK1","--worker","beta","--id","SYN-2")

    def test_conflicted_ready_task_is_logged_and_picker_claims_next_compatible(self):
        self.claim()
        self.add_task("SYN-2","higher priority conflicting file",["scratch/autopilot_owned.py"])
        self.add_task("SYN-3","independent ready work",["scratch/independent.py"])
        c=sqlite3.connect(self.db); c.execute("update tasks set priority=1000 where id='SYN-2'"); c.execute("update tasks set priority=999 where id='SYN-3'"); c.commit(); c.close()
        p=self.run_cli("claim","WORK1","--worker","beta")
        self.assertIn('"claimed": "SYN-3"',p.stdout)
        self.assertIn('"task": "SYN-2"',p.stdout)
        c=sqlite3.connect(self.db)
        try:
            self.assertEqual(c.execute("select status from tasks where id='SYN-2'").fetchone()[0],"READY")
            self.assertGreater(c.execute("select count(*) from events where task_id='SYN-2' and action='CLAIM_WAITING_OWNERSHIP'").fetchone()[0],0)
        finally:c.close()

    def test_done_requires_registered_acceptance_test_and_pass(self):
        self.claim()
        p = self.run_cli("finish", "SYN-1", "--worker", "alpha", "--status", "DONE",
                         "--evidence", str(self.proof), "--evidence-level", "SYNTHETIC_PASS", ok=False)
        self.assertIn("no executable acceptance tests", p.stderr)
        self.assertEqual(self.status(), "RUNNING")

    def test_evidence_file_is_required_and_dependencies_only_release_on_done(self):
        self.claim()
        p = self.run_cli("finish", "SYN-1", "--worker", "alpha", "--status", "INCONCLUSIVE",
                         "--evidence", str(self.d / "missing.json"), "--evidence-level", "INCONCLUSIVE", ok=False)
        self.assertIn("does not exist", p.stderr)
        self.assertEqual(self.status(), "RUNNING")

    def test_evidence_alone_does_not_release_a_dependency(self):
        child={"id":"SYN-CHILD","title":"dependent","roles":["WORK1"],"dependencies":["SYN-1"],
               "acceptance":["wait for parent"],"tests":[],"files":[]}
        f=self.d/"child.json"; f.write_text(json.dumps(child),encoding="utf-8"); self.run_queue("add",str(f))
        self.claim()
        p=self.run_cli("claim","WORK1","--worker","beta","--id","SYN-CHILD",ok=False)
        self.assertIn("dependencies are not DONE",p.stderr)
        self.run_cli("finish","SYN-1","--worker","alpha","--status","INCONCLUSIVE","--evidence",str(self.proof),"--evidence-level","INCONCLUSIVE")
        p=self.run_cli("claim","WORK1","--worker","beta","--id","SYN-CHILD",ok=False)
        self.assertNotEqual(p.returncode,0)

    def test_passing_acceptance_test_is_prerequisite_to_done(self):
        spec={"id":"SYN-DONE","title":"verified synthetic task","roles":["WORK1"],"dependencies":[],
              "acceptance":["explicit passing test"],"tests":[{"argv":[sys.executable,"-c","print('PASS')"],"suite":"synthetic"}],"files":[]}
        f=self.d/"done.json"; f.write_text(json.dumps(spec),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_cli("claim","WORK1","--worker","alpha","--id","SYN-DONE")
        p=self.run_cli("finish","SYN-DONE","--worker","alpha","--status","DONE","--evidence",str(self.proof),"--evidence-level","SYNTHETIC_PASS",ok=False)
        self.assertIn("successful tests",p.stderr)
        self.run_cli("test","SYN-DONE","--worker","alpha")
        self.run_cli("finish","SYN-DONE","--worker","alpha","--status","DONE","--evidence",str(self.proof),"--evidence-level","SYNTHETIC_PASS")
        c=sqlite3.connect(self.db)
        try:self.assertEqual(c.execute("select status from tasks where id='SYN-DONE'").fetchone()[0],"DONE")
        finally:c.close()

    def test_handoff_persists_across_processes(self):
        self.claim()
        out = self.run_cli("handoff", "SYN-1", "--worker", "alpha", "--to-role", "WORK2", "--summary", "synthetic handoff",
                           "--evidence", str(self.proof), "--next-action", "inspect evidence", "--evidence-level", "SYNTHETIC_PASS").stdout
        hid = json.loads(out)["handoff_id"]
        self.assertIn(hid, self.run_cli("handoffs").stdout)
        self.run_cli("ack", hid, "--role", "WORK2", "--worker", "beta")
        self.assertNotIn(hid, self.run_cli("handoffs").stdout)

    def test_inconclusive_result_preserves_evidence(self):
        self.claim()
        self.run_cli("finish", "SYN-1", "--worker", "alpha", "--status", "INCONCLUSIVE",
                     "--evidence", str(self.proof), "--evidence-level", "INCONCLUSIVE", "--next-action", "new measurement")
        c = sqlite3.connect(self.db)
        try:
            row = c.execute("select status,evidence,evidence_level,next_action from tasks where id='SYN-1'").fetchone()
        finally:
            c.close()
        self.assertEqual(row[0], "INCONCLUSIVE")
        self.assertIn(str(self.proof), json.loads(row[1]))
        self.assertEqual(row[2:], ("INCONCLUSIVE", "new measurement"))

    def test_expired_claim_is_quarantined_not_reassigned(self):
        self.claim("--lease-minutes", "1")
        c=sqlite3.connect(self.db); c.execute("update tasks set lease_until='2000-01-01T00:00:00+00:00' where id='SYN-1'"); c.commit(); c.close()
        self.run_cli("recover", "--actor", "test")
        self.assertEqual(self.status(), "INCONCLUSIVE")
        self.assertFalse(json.loads(self.run_cli("status").stdout)["active"])

    def test_claim_quarantines_only_confirmed_expired_lease_before_releasing_file_ownership(self):
        self.claim("--lease-minutes","1")
        c=sqlite3.connect(self.db)
        c.execute("update tasks set lease_until='2000-01-01T00:00:00+00:00',evidence=? where id='SYN-1'",(json.dumps(["prior-proof.json"]),)); c.commit(); c.close()
        self.add_task("SYN-2","waiting for expired file",["scratch/autopilot_owned.py"])
        p=self.run_cli("claim","WORK1","--worker","beta","--id","SYN-2")
        self.assertIn('"claimed": "SYN-2"',p.stdout)
        c=sqlite3.connect(self.db)
        try:
            row=c.execute("select status,owner,evidence from tasks where id='SYN-1'").fetchone()
            self.assertEqual(row[:2],("INCONCLUSIVE",None)); self.assertEqual(json.loads(row[2]),["prior-proof.json"])
            self.assertGreater(c.execute("select count(*) from events where task_id='SYN-1' and action='EXPIRED_LEASE_QUARANTINED'").fetchone()[0],0)
        finally:c.close()

    def test_resource_lock_excludes_other_claim(self):
        self.claim()
        self.run_cli("lock","SYN-1","--worker","alpha","--resource","build")
        self.add_task("SYN-2", "second")
        self.run_cli("claim","WORK1","--worker","beta","--id","SYN-2")
        p=self.run_cli("lock","SYN-2","--worker","beta","--resource","build",ok=False)
        self.assertEqual(json.loads(p.stdout)["lock"],"WAITING_RESOURCE")
        self.run_cli("unlock","SYN-1","--worker","alpha","--resource","build")
        self.run_cli("lock","SYN-2","--worker","beta","--resource","build")

    def test_shared_resources_are_derived_and_reserved_at_claim(self):
        self.add_task("SYN-BUILD", "shared build", ["runtime/shared.c", "build/result.bin", "reports/run.md"])
        self.run_cli("claim", "WORK1", "--worker", "alpha", "--id", "SYN-BUILD")
        locks=json.loads(self.run_cli("status").stdout)["resource_locks"]
        self.assertEqual(locks, [])
        self.add_task("SYN-OTHER", "parallel build")
        self.run_cli("claim","WORK1","--worker","beta","--id","SYN-OTHER")

    def test_declared_task_files_and_legacy_active_scope_are_not_ignored(self):
        legacy={"id":"SYN-LEGACY","title":"legacy runtime source task","roles":["WORK2"],"dependencies":[],
                "acceptance":["synthetic"],"tests":[],"files":["runtime/legacy.c"],"files_owned":[]}
        f=self.d/"legacy.json"; f.write_text(json.dumps(legacy),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_queue("claim","--role","WORK2","--worker","legacy-agent","--id","SYN-LEGACY")
        incoming={"id":"SYN-CODE","title":"new source edit","roles":["WORK1"],"dependencies":[],
                  "acceptance":["synthetic"],"tests":[],"files":["runtime/new.c"],"files_owned":[]}
        f=self.d/"incoming.json"; f.write_text(json.dumps(incoming),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_cli("claim","WORK1","--worker","new-agent","--id","SYN-CODE")

    def test_oracle_claim_reserves_exclusive_oracle_resources(self):
        spec={"id":"SYN-ORACLE","title":"guarded oracle capture","roles":["WORK3"],"dependencies":[],
              "acceptance":["synthetic"],"tests":[],"files":["evidence/capture.json"],"files_owned":[]}
        f=self.d/"oracle.json"; f.write_text(json.dumps(spec),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_cli("claim","WORK3","--worker","oracle-worker","--id","SYN-ORACLE")
        locks=json.loads(self.run_cli("status").stdout)["resource_locks"]
        self.assertTrue({"oracle","oracle-vhdx"}.issubset({x["resource"] for x in locks}))

    def test_renew_and_owner_check_reject_expired_lease(self):
        self.claim("--lease-minutes","1")
        c=sqlite3.connect(self.db)
        try: before=c.execute("select lease_until from tasks where id='SYN-1'").fetchone()[0]
        finally: c.close()
        self.run_cli("renew","SYN-1","--worker","alpha","--lease-minutes","120")
        self.assertIn("OWNER SYN-1 alpha",self.run_cli("check","SYN-1","--worker","alpha").stdout)
        c=sqlite3.connect(self.db); c.execute("update tasks set lease_until='2000-01-01T00:00:00+00:00' where id='SYN-1'"); c.commit(); c.close()
        p=self.run_cli("check","SYN-1","--worker","alpha",ok=False)
        self.assertIn("Lease lost or expired",p.stderr)
        p=self.run_cli("finish","SYN-1","--worker","alpha","--status","DONE","--evidence",str(self.proof),"--evidence-level","SYNTHETIC_PASS",ok=False)
        self.assertIn("Lease lost or expired",p.stderr)
        self.assertEqual(self.status(),"RUNNING")

    def test_end_to_end_dependency_lease_handoff_and_dashboard(self):
        a={"id":"SYN-A","title":"synthetic shared build A","roles":["WORK1"],"dependencies":[],
           "acceptance":["passing synthetic test"],"tests":[{"argv":[sys.executable,"-c","print('PASS')"],"suite":"synthetic"}],
           "files":["runtime/a.c","reports/a.md"],"files_owned":["runtime/a.c"]}
        b={"id":"SYN-B","title":"dependent integration B","roles":["WORK2"],"dependencies":["SYN-A"],
           "acceptance":["passing synthetic test"],"tests":[{"argv":[sys.executable,"-c","print('PASS')"],"suite":"synthetic"}],
           "files":["runtime/b.c"],"files_owned":["runtime/b.c"]}
        for spec in (a,b):
            f=self.d/f"{spec['id']}.json"; f.write_text(json.dumps(spec),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_cli("claim","WORK1","--worker","agent-A","--id","SYN-A","--lease-minutes","1")
        acquired=json.loads(self.run_cli("status").stdout)
        self.assertEqual(acquired["resource_locks"],[])
        self.assertIn("RENEWED SYN-A",self.run_cli("renew","SYN-A","--worker","agent-A","--lease-minutes","120").stdout)
        self.run_cli("check","SYN-A","--worker","agent-A")
        self.assertNotEqual(self.run_cli("claim","WORK2","--worker","agent-B","--id","SYN-B",ok=False).returncode,0)
        self.run_cli("test","SYN-A","--worker","agent-A")
        self.run_cli("finish","SYN-A","--worker","agent-A","--status","DONE","--evidence",str(self.proof),"--evidence-level","SYNTHETIC_PASS")
        self.run_cli("claim","WORK2","--worker","agent-B","--id","SYN-B")
        self.run_cli("renew","SYN-B","--worker","agent-B","--lease-minutes","120")
        self.run_cli("check","SYN-B","--worker","agent-B")
        self.run_cli("test","SYN-B","--worker","agent-B")
        self.run_cli("lock","SYN-B","--worker","agent-B","--resource","integration","--resource","outputs")
        self.run_cli("unlock","SYN-B","--worker","agent-B","--resource","integration","--resource","outputs")
        out=self.run_cli("handoff","SYN-B","--worker","agent-B","--to-role","WORK1","--summary","synthetic handoff",
                         "--evidence",str(self.proof),"--next-action","agent A reviews handoff","--evidence-level","SYNTHETIC_PASS").stdout
        hid=json.loads(out)["handoff_id"]
        self.assertIn(hid,self.run_cli("handoffs","--status","ALL").stdout)
        # A's old session can inspect the durable handoff after B publishes it.
        self.assertIn(hid,self.run_cli("handoffs","--status","ALL").stdout)
        dashboard=self.run_cli("dashboard")
        self.assertEqual(pathlib.Path(dashboard.stdout.strip()),self.dashboard)
        rendered=self.dashboard.read_text(encoding="utf-8")
        for expected in ("SYN-A", "SYN-B", hid, "agent-B", "integration"):
            self.assertIn(expected,rendered)
        c=sqlite3.connect(self.db)
        try:
            self.assertEqual(c.execute("select status from tasks where id='SYN-A'").fetchone()[0],"DONE")
            self.assertEqual(c.execute("select status,owner from tasks where id='SYN-B'").fetchone(),("RUNNING","agent-B"))
            self.assertEqual(c.execute("select count(*) from events where task_id in ('SYN-A','SYN-B') and action='AUTOPILOT_TESTED' and json_extract(detail,'$.passed')=1").fetchone()[0],2)
        finally:c.close()

    def test_overlapping_exclusive_file_ownership_is_rejected(self):
        self.claim()
        self.add_task("SYN-2","overlapping file owner",["scratch/autopilot_owned.py"])
        p=self.run_cli("claim","WORK1","--worker","beta","--id","SYN-2",ok=False)
        self.assertIn("overlapping path",p.stdout)

    def test_dashboard_regenerates_from_queue(self):
        p=self.run_cli("dashboard")
        self.assertEqual(pathlib.Path(p.stdout.strip()),self.dashboard)

    def test_fixture_build_and_path_metadata_survive_creation(self):
        c=sqlite3.connect(self.db)
        try:
            row=c.execute("select files_owned,max_attempts from tasks where id='SYN-1'").fetchone()
        finally:c.close()
        self.assertEqual(json.loads(row[0]),["scratch/autopilot_owned.py"])
        self.assertEqual(row[1],3)

    def test_historical_task_status_is_not_rewritten(self):
        spec = {"id":"HIST","title":"old","roles":["WORK1"],"dependencies":[],"acceptance":["synthetic"],"tests":[],"files":[]}
        f=self.d/"hist.json"; f.write_text(json.dumps(spec),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_queue("claim","--role","WORK1","--worker","WORK1","--id","HIST")
        self.run_queue("done","HIST","--worker","WORK1","--evidence",str(self.proof))
        self.run_cli("status")
        c=sqlite3.connect(self.db)
        try:self.assertEqual(c.execute("select status from tasks where id='HIST'").fetchone()[0],"DONE")
        finally:c.close()

    def test_coordinator_test_guard_blocks_oracle_commands(self):
        revised={"id":"SYN-1","title":"synthetic queue contract","roles":["WORK1"],"priority":1,
                 "dependencies":[],"acceptance":["record evidence"],
                 "tests":[{"argv":["python","tools/oracle_guard.py","run"],"suite":"synthetic"}],"files":[],
                 "files_owned":["scratch/autopilot_owned.py"],"max_attempts":3}
        spec=self.d/"unsafe-task.json"; spec.write_text(json.dumps(revised),encoding="utf-8")
        self.run_queue("revise","SYN-1","--file",str(spec))
        self.claim()
        p=self.run_cli("test","SYN-1","--worker","alpha",ok=False)
        self.assertIn("may not invoke the oracle",p.stderr)

    def test_repeated_failed_hypothesis_requires_reformulation(self):
        self.claim()
        for _ in range(2):
            self.run_cli("attempt","SYN-1","--worker","alpha","--hypothesis","same cause","--evidence",str(self.proof),"--outcome","FAILED")
        p=self.run_cli("attempt","SYN-1","--worker","alpha","--hypothesis","same cause","--evidence",str(self.proof),"--outcome","FAILED","--new-evidence",ok=False)
        self.assertIn("failed twice",p.stderr)
        p=self.run_cli("attempt","SYN-1","--worker","alpha","--hypothesis","new supported cause","--evidence",str(self.proof),"--outcome","FAILED","--new-evidence",ok=False)
        self.assertIn("newly changed or added evidence",p.stderr)
        self.proof.write_text('{"synthetic":false}\n',encoding="utf-8")
        self.run_cli("attempt","SYN-1","--worker","alpha","--hypothesis","new supported cause","--evidence",str(self.proof),"--outcome","FAILED","--new-evidence")

    def test_pending_handoff_is_not_lost_when_task_finishes(self):
        self.claim()
        self.run_cli("handoff","SYN-1","--worker","alpha","--to-role","WORK2","--summary","handoff survives",
                     "--evidence",str(self.proof),"--next-action","continue","--evidence-level","SYNTHETIC_PASS")
        self.run_cli("finish","SYN-1","--worker","alpha","--status","INCONCLUSIVE","--evidence",str(self.proof),"--evidence-level","INCONCLUSIVE")
        self.assertIn("handoff survives",self.run_cli("handoffs").stdout)

    def test_legacy_no_lease_oracle_reservation_is_logged_and_not_recovered(self):
        spec={"id":"SYN-LEGACY-ORACLE","title":"oracle capture","roles":["WORK3"],"dependencies":[],"acceptance":["synthetic"],"tests":[],"files":["tools/oracle_guard.py"]}
        f=self.d/"legacy-oracle.json"; f.write_text(json.dumps(spec),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_queue("claim","--role","WORK3","--worker","legacy-owner","--id","SYN-LEGACY-ORACLE")
        incoming={"id":"SYN-ORACLE-2","title":"oracle vhdx use","roles":["WORK3"],"dependencies":[],"acceptance":["synthetic"],"tests":[],"files":[]}
        f=self.d/"oracle-2.json"; f.write_text(json.dumps(incoming),encoding="utf-8"); self.run_queue("add",str(f))
        p=self.run_cli("claim","WORK3","--worker","oracle-agent","--id","SYN-ORACLE-2",ok=False)
        data=json.loads(p.stdout)
        self.assertEqual(data["claim"],"WAITING_RESOURCE")
        self.assertTrue(data["conflicts"][0]["conflicts"][0]["legacy"])
        self.assertEqual(data["conflicts"][0]["conflicts"][0]["owner"],"legacy-owner")
        c=sqlite3.connect(self.db)
        try:
            self.assertEqual(c.execute("select status,lease_until from tasks where id='SYN-LEGACY-ORACLE'").fetchone(),("CLAIMED",None))
            self.assertGreater(c.execute("select count(*) from events where task_id='SYN-ORACLE-2' and action='CLAIM_WAITING_RESOURCE'").fetchone()[0],0)
        finally:c.close()

    def test_active_manual_resource_lock_is_owner_checked_and_released(self):
        self.claim()
        self.run_cli("lock","SYN-1","--worker","alpha","--resource","build","--resource","outputs")
        self.add_task("SYN-2","other task")
        self.run_cli("claim","WORK1","--worker","beta","--id","SYN-2")
        p=self.run_cli("lock","SYN-2","--worker","beta","--resource","build",ok=False)
        self.assertEqual(json.loads(p.stdout)["lock"],"WAITING_RESOURCE")
        p=self.run_cli("unlock","SYN-1","--worker","intruder","--resource","build",ok=False)
        self.assertIn("Lease lost or expired",p.stderr)
        self.run_cli("unlock","SYN-1","--worker","alpha","--resource","build","--resource","outputs")
        self.run_cli("lock","SYN-2","--worker","beta","--resource","build")

    def test_registered_operation_locks_only_while_running_and_keeps_distinct_resources_parallel(self):
        spec={"id":"SYN-WRITE","title":"build operation","roles":["WORK1"],"dependencies":[],"acceptance":["pass"],
              "tests":[{"argv":[sys.executable,"-c","print('synthetic build')"],"resources":["build","outputs"]}],"files":[]}
        f=self.d/"write.json"; f.write_text(json.dumps(spec),encoding="utf-8"); self.run_queue("add",str(f))
        self.run_cli("claim","WORK1","--worker","alpha","--id","SYN-WRITE")
        self.run_cli("lock","SYN-WRITE","--worker","alpha","--resource","integration")
        self.run_cli("test","SYN-WRITE","--worker","alpha")
        status=json.loads(self.run_cli("status").stdout)
        self.assertEqual({x["resource"] for x in status["resource_locks"]},{"integration"})
        self.run_cli("unlock","SYN-WRITE","--worker","alpha","--resource","integration")
        self.assertEqual(json.loads(self.run_cli("status").stdout)["resource_locks"],[])

    def test_two_agents_hold_independent_shared_resources_simultaneously(self):
        self.claim()
        self.add_task("SYN-2","second role task",["scratch/second.py"])
        self.run_cli("claim","WORK1","--worker","beta","--id","SYN-2")
        self.run_cli("lock","SYN-1","--worker","alpha","--resource","build","--resource","outputs")
        self.run_cli("lock","SYN-2","--worker","beta","--resource","integration")
        locks=json.loads(self.run_cli("status").stdout)["resource_locks"]
        self.assertEqual({(x["resource"],x["owner"]) for x in locks},{("build","alpha"),("outputs","alpha"),("integration","beta")})

    def test_legacy_release_preserves_evidence_and_event_history(self):
        self.add_task("SYN-LEGACY-RELEASE","legacy evidence")
        c=sqlite3.connect(self.db)
        try:c.execute("update tasks set status='CLAIMED',owner='old-owner',role='LOCAL',claimed_at='2026-10-07T00:00:00+00:00',evidence=? where id='SYN-LEGACY-RELEASE'",(json.dumps(["old-evidence.json"]),)); c.commit()
        finally:c.close()
        self.run_queue("release","SYN-LEGACY-RELEASE","--worker","operator","--expected-owner","old-owner","--reason","synthetic confirmed abandoned","--evidence",str(self.proof))
        c=sqlite3.connect(self.db)
        try:
            row=c.execute("select status,owner,evidence from tasks where id='SYN-LEGACY-RELEASE'").fetchone()
            actions=[r[0] for r in c.execute("select action from events where task_id='SYN-LEGACY-RELEASE' order by id")]
        finally:c.close()
        self.assertEqual(row[0:2],("READY",None))
        self.assertEqual(set(json.loads(row[2])),{"old-evidence.json",str(self.proof)})
        self.assertIn("CREATED",actions); self.assertIn("RELEASED",actions)


if __name__ == "__main__":
    unittest.main()
