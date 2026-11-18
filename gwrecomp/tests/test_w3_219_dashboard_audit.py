import json, pathlib, tempfile, sqlite3, datetime, unittest
from unittest.mock import patch
from coordination import dashboard_view as dv

class DashboardAuditTests(unittest.TestCase):
    def make_db(self, root):
        db=pathlib.Path(root)/'tasks.sqlite3'
        c=sqlite3.connect(db)
        c.executescript('''
        CREATE TABLE tasks(id TEXT,title TEXT,description TEXT,priority INTEGER,roles TEXT,deps TEXT,acceptance TEXT,tests TEXT,files TEXT,evidence TEXT,status TEXT,owner TEXT,role TEXT,claimed_at TEXT,updated_at TEXT,blocked_reason TEXT,derive TEXT,max_attempts INTEGER,build_id TEXT,fixture_id TEXT,next_action TEXT,files_owned TEXT,lease_until TEXT,evidence_level TEXT);
        CREATE TABLE events(id INTEGER PRIMARY KEY,task_id TEXT,at TEXT,actor TEXT,action TEXT,detail TEXT);
        CREATE TABLE autopilot_handoffs(id TEXT,task_id TEXT,from_worker TEXT,to_role TEXT,payload TEXT,status TEXT,created_at TEXT,acknowledged_by TEXT,acknowledged_at TEXT);
        CREATE TABLE autopilot_attempts(id INTEGER PRIMARY KEY,task_id TEXT,worker TEXT,hypothesis TEXT,evidence TEXT,outcome TEXT,at TEXT);
        CREATE TABLE autopilot_locks(resource TEXT,task_id TEXT,owner TEXT,acquired_at TEXT,expires_at TEXT);
        ''')
        return c,db
    def add_task(self,c, id, role, status, updated, level=None, evidence='[]', roles=None, deps='[]', owner=None, lease=None):
        c.execute('INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
          (id,id,'',100,json.dumps(roles or [role]),deps,'[]','[]','[]',evidence,status,owner,role if owner else None,None,updated,None,'[]',2,None,None,None,'[]',lease,level))
    def test_snapshot_counts_handoffs_and_levels(self):
        with tempfile.TemporaryDirectory() as td:
            c,db=self.make_db(td)
            now=datetime.datetime(2026,10,9,8,tzinfo=datetime.timezone.utc)
            stamp='2026-10-09T07:30:00+00:00'
            native=pathlib.Path(td)/'native.json'; native.write_text(json.dumps({'execution_mode':'native_recompiled_guest','next_frontier':{'trap':{'vector':'21','eax':'3d01','eip':'000afcc4','ebx':'2'}}}),encoding='utf-8')
            orig=pathlib.Path(td)/'original.json'; orig.write_text(json.dumps({'execution_mode':'original Staging','guard':{'timeout':30}}),encoding='utf-8')
            self.add_task(c,'W1-071','WORK1','DONE',stamp,'NATIVE_REACHED',json.dumps(['native.json']))
            self.add_task(c,'W3-203','WORK3','DONE',stamp,'ORIGINAL_OBSERVED',json.dumps(['original.json']))
            self.add_task(c,'W1-072','WORK1','READY',stamp,roles=['WORK1'],deps='["W1-071"]')
            c.execute('INSERT INTO events VALUES(1,?,?,?,?,?)',('W3-203',stamp,'WORK3','AUTOPILOT_INCONCLUSIVE',json.dumps({'reason':'30-second timeout before checkpoint'})))
            c.execute('INSERT INTO autopilot_handoffs VALUES(?,?,?,?,?,?,?,?,?)',('h','W3-203','WORK3','WORK1','{"summary":"fresh original result"}','OPEN','2026-10-09T01:00:00+00:00',None,None))
            c.commit()
            c.row_factory=sqlite3.Row
            snap=dv.take_snapshot(c,db,now,td); text=dv.render(snap)
            self.assertEqual(snap['counts']['DONE'],2)
            self.assertEqual([x['id'] for x in snap['agents'][0]['ready']],['W1-072'])
            self.assertEqual(snap['native']['task']['id'],'W1-071')
            self.assertEqual(snap['original']['task']['id'],'W3-203')
            self.assertIn('INCONCLUSIVE causes',text)
            self.assertIn('Oracle timeout / guard limit: 1',text)
            self.assertIn('first framebuffer',text.lower())
            self.assertIn('not a progress score',text.lower())
            self.assertIn('STALE',text)
            c.close()
    def test_missing_or_changing_evidence_is_omitted(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(dv.read_json(td,'missing.json'))
            too_big=pathlib.Path(td)/'large.json'; too_big.write_text(' '*40,encoding='utf-8')
            self.assertIsNone(dv.read_json(td,'large.json',max_bytes=10))
            self.assertIsNone(dv.read_json(td,'bad.json'))
            with patch.object(pathlib.Path, 'read_bytes', side_effect=FileNotFoundError):
                self.assertIsNone(dv.read_json(td,'racing.json'))
    def test_atomic_repeated_generation_does_not_duplicate_sections_or_mutate_queue(self):
        with tempfile.TemporaryDirectory() as td:
            c,db=self.make_db(td)
            stamp='2026-10-09T07:30:00+00:00'
            self.add_task(c,'W1-071','WORK1','DONE',stamp,'NATIVE_REACHED','[]')
            c.commit(); before=c.execute('select status from tasks').fetchall()
            out=pathlib.Path(td)/'dashboard.md'
            for _ in range(2): dv.generate(db,out,root=td,now=datetime.datetime(2026,10,9,8,tzinfo=datetime.timezone.utc))
            first=out.read_text(encoding='utf-8'); second=out.read_text(encoding='utf-8')
            self.assertEqual(first,second)
            self.assertEqual(first.count('## Agent status'),1)
            self.assertEqual(first.count('## GeneWars replay progress'),1)
            self.assertEqual(before,c.execute('select status from tasks').fetchall())
            self.assertFalse(list(pathlib.Path(td).glob('.dashboard.md.*.tmp')))
            c.close()

    def test_duplicate_attempts_are_reported_separately_from_done(self):
        roles=list(dv.ROLES)
        snap={'rows':[],'generated':'2026-10-09T08:00:00+00:00','cutoff':'2026-10-08T08:00:00+00:00',
              'counts':{x:0 for x in ('READY','RUNNING','CLAIMED','BLOCKED','INCONCLUSIVE','DONE','FAILED')},
              'agents':[{'role':r,'name':r,'active':[],'ready':[],'last_activity':None} for r in roles],
              'handoffs':[],'events':[],'attempts':[{'outcome':'INCONCLUSIVE','hypothesis':'same bounded checkpoint'},
              {'outcome':'FAILED','hypothesis':'  SAME   BOUNDED CHECKPOINT '}],
              'outcomes':{r:{a:[] for a in ('AUTOPILOT_DONE','AUTOPILOT_INCONCLUSIVE','AUTOPILOT_BLOCKED')} for r in roles},
              'native':None,'original':None,'stale_hours':6,'queue_path':'tasks.sqlite3','locks':[]}
        text=dv.render(snap)
        self.assertIn('1 groups (1 repeat attempts beyond the first)',text)
        self.assertIn('2 attempts: same bounded checkpoint',text)

    def test_native_event_string_frontier_is_not_stale_or_conflated(self):
        role_rows=[{'role':r,'name':r,'active':[],'ready':[],'last_activity':None} for r in dv.ROLES]
        task={'id':'W1-072','updated_at':'2026-10-09T08:09:06+00:00'}
        native={'task':task,'path':'evidence/native_address_open_w1_072.json','data':{
            'execution_mode':'native_recompiled_guest',
            'game_gate':{'setup_game_entry_observed':False},
            'address_txt':{'open_event':'OPEN OK','request_response':'response_eax=00000005 cf_out=0 handled=1'},
            'next_frontier':{'event':'NATIVE_NEXT_TRAP vector=21 eip=000c8973 eax=00004400 ebx=00000005'}}}
        snap={'rows':[],'generated':'2026-10-09T08:10:00+00:00','cutoff':'2026-10-08T08:10:00+00:00',
              'counts':{x:0 for x in ('READY','RUNNING','CLAIMED','BLOCKED','INCONCLUSIVE','DONE','FAILED')},
              'agents':role_rows,'handoffs':[],'events':[],'attempts':[],
              'outcomes':{r:{a:[] for a in ('AUTOPILOT_DONE','AUTOPILOT_INCONCLUSIVE','AUTOPILOT_BLOCKED')} for r in dv.ROLES},
              'native':native,'original':None,'stale_hours':6,'queue_path':'tasks.sqlite3','locks':[]}
        text=dv.render(snap)
        self.assertIn('Latest native recompiled frontier: W1-072',text)
        self.assertIn('AX/EAX=00004400',text)
        self.assertIn('BX/EBX=00000005',text)
        self.assertIn('link EIP 000c8973',text)
        self.assertIn('AX=3D01 opened the authenticated virtual C:\\ADDRESS.TXT',text)
        self.assertIn('native setup_game is not reached in the latest native replay',text)
        self.assertNotIn('latest W1-071 replay',text)

if __name__=='__main__': unittest.main()
