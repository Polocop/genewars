import json
import unittest
from pathlib import Path
from tools.w3_228_gwerr_caller_capture import CPU_EVENT, correlate, normalize_gwerr_path, parse_trace

def row(**kw):
    d={'event':CPU_EVENT,'sequence':10,'process_psp':7811,'pathname':'gw.err','pathname_status':'sampled','mapping_valid':True,'int21_bytes_verified':True}
    d.update(kw); return d
class W3228Tests(unittest.TestCase):
    def test_path_filter_is_exact_and_bounded(self):
        self.assertTrue(normalize_gwerr_path('gw.err'))
        self.assertTrue(normalize_gwerr_path(r'C:\GENEWARS\GW.ERR'))
        self.assertFalse(normalize_gwerr_path('../gw.err'))
        self.assertFalse(normalize_gwerr_path('gw.err'+'x'*64))
    def test_pairs_only_same_psp_later_open(self):
        cpu=row()
        ok={'event':'dos_handle_open','sequence':12,'process_psp':7811,'entry':2,'internal_handle':3,'path':r'GENEWARS\GW.ERR'}
        other_psp={'event':'dos_handle_open','sequence':11,'process_psp':9000,'path':'GW.ERR'}
        out=correlate([other_psp,cpu,ok])
        self.assertEqual(out['classification'],'ORIGINAL_GWERR_CALLER_AND_OPEN_CORRELATED')
        self.assertEqual(out['open_event']['entry'],2)
    def test_caps_and_unknown_conditions(self):
        event=row()
        with self.assertRaisesRegex(ValueError,'cap'):
            correlate([event,{**event,'sequence':11}])
        self.assertEqual(correlate([])['classification'],'INCONCLUSIVE_GWERR_OPEN_NOT_OBSERVED')
        self.assertEqual(correlate([row(mapping_valid=False)])['classification'],'INCONCLUSIVE_CPU_MAPPING_OR_PATH_VALIDATION')
    def test_json_trace_size_and_parse(self):
        data=(json.dumps(row())+'\n').encode()
        self.assertEqual(parse_trace(data)[0]['pathname'],'gw.err')
        with self.assertRaisesRegex(ValueError,'1 MiB'):
            parse_trace(b' '* (1_048_576+1))
    def test_recorded_replay_keeps_open_observation_distinct_from_missing_caller(self):
        p=Path(__file__).resolve().parents[1]/'evidence/w3_228_gwerr_caller_capture.json'
        d=json.loads(p.read_text(encoding='utf-8'))
        self.assertEqual(d['capture']['classification'],'INCONCLUSIVE_GWERR_OPEN_WITHOUT_CPU_ENTRY')
        self.assertIsNone(d['capture']['cpu_entry'])
        self.assertEqual(d['capture']['open_event']['path'],r'GENEWARS\GW.ERR')
        self.assertEqual(d['guard']['cause'],'TIMEOUT')
        self.assertLessEqual(d['trace']['bytes'],1_048_576)
        self.assertEqual(d['execution_frontier']['last_target_checkpoint']['checkpoint'],'W3_134_LBMEMORYALLOC_RETURN')
        self.assertIn('not proof',d['frontier_interpretation'])
        self.assertFalse(d['preflight']['sandbox']['verified'] is False)
if __name__=='__main__': unittest.main()
