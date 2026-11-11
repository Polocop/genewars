import hashlib, importlib.util, json, pathlib, unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
STATE=ROOT/'PROJECT_STATE.md'
CD=ROOT/'evidence'/'cd_present_gate_work3.json'
W1=ROOT/'evidence'/'mscdex_fault_context_current_work1.json'
EXIT=ROOT/'evidence'/'local_process_exit_classification.json'
TASKQ=ROOT/'coordination'/'taskq.py'
spec=importlib.util.spec_from_file_location('gw_taskq_projection',TASKQ)
taskq=importlib.util.module_from_spec(spec); spec.loader.exec_module(taskq)

class CurrentCdPresentGateProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cd=json.loads(CD.read_text(encoding='utf-8-sig'))
        cls.w1=json.loads(W1.read_text(encoding='utf-8-sig'))
        cls.exit=json.loads(EXIT.read_text(encoding='utf-8-sig'))
        cls.target=cls.cd['target_sha256']
        cls.metrics=taskq.cd_present_gate_metrics(cls.cd,cls.target,cls.w1,cls.exit)
        cls.state=STATE.read_text(encoding='utf-8-sig')

    def test_cd_present_source_and_cross_work_corroboration(self):
        m=self.metrics
        self.assertTrue(m['valid'],m['reason'])
        self.assertEqual(m['source_task'],'W3-046')
        self.assertEqual(m['source_sha256'],hashlib.sha256(CD.read_bytes()).hexdigest())
        self.assertTrue(m['runtime_matches'])
        self.assertEqual(m['msc_request_count'],8)
        self.assertTrue(m['work1_028_oracle_corroborated'])
        self.assertEqual(m['execution_mode'],'original-byte Unicorn oracle')
        self.assertFalse(m['native_differential_established'])
        self.assertEqual((m['stop_kind'],m['stop_eip'],m['stop_address']),
                         ('memory_write_fault','0x00194b5a','0x00000000'))
        self.assertFalse(m['menu_reached'])

    def test_generated_state_uses_cd_present_as_current_gate(self):
        self.assertIn('CD-present current gate:',self.state)
        self.assertIn("'source_task': 'W3-046'",self.state)
        self.assertIn("'w3_046_task_done': True",self.state)
        self.assertIn("'w3_046_evidence_attached': True",self.state)
        self.assertIn('Original-byte Unicorn CD-present `-k` oracle handled 8 CUE-derived MSCDEX requests',self.state)
        self.assertIn('stopped after 7771728 instructions at 0x00194b5a',self.state)
        self.assertIn('Next gate: Measure the first native-versus-original divergence at setup_game `this` (W1-033)',self.state)
        self.assertIn('This is not a native-versus-original differential and does not establish a missing initializer.',self.state)
        self.assertNotIn('no-CD fixture then terminated via DOS AH=4Ch with code 0 at 0x001afc33. MENU not reached\n- Next gate:',self.state)

    def test_no_cd_exit_remains_a_distinct_expected_control(self):
        post=taskq.post_mscdex_startup_metrics(
            json.loads((ROOT/'evidence'/'startup_ah48_current_work3.json').read_text(encoding='utf-8-sig')),
            self.target)
        self.assertTrue(post['valid'])
        self.assertEqual((post['stop_kind'],post['stop_eip'],post['process_exit_code']),
                         ('process_exit','0x001afc33',0))
        det=self.exit['determination']
        self.assertTrue(det['no_cd_exit_is_expected'])
        self.assertFalse(det['no_cd_exit_gate_to_menu'])
        self.assertIn('No-CD process-exit control:',self.state)

    def test_stale_runtime_or_missing_work1_corroboration_is_rejected(self):
        stale=json.loads(json.dumps(self.cd))
        stale['runtime_sha256']='0'*64
        self.assertFalse(taskq.cd_present_gate_metrics(stale,self.target,self.w1,self.exit)['valid'])
        self.assertFalse(taskq.cd_present_gate_metrics(self.cd,self.target,None,self.exit)['valid'])

if __name__=='__main__': unittest.main()
