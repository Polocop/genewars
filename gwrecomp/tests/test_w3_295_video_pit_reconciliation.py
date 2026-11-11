import json
import unittest
from tools.w3_295_video_pit_reconciliation import parse_trace, summarize

class TraceTests(unittest.TestCase):
    def test_extracts_last_checkpoint_and_rejects_false_pit_progress(self):
        rows=[
            {'event':'main_mapping','link_va':0xAF96C,'code_rebase':0x1EB000},
            {'event':'target_runtime_checkpoint','checkpoint':'VIDEO_FRAMEBUFFER_ASSIGN_AFTER','link_va':0x9FDF9},
            {'event':'setup_dos_api','ordinal':128,'operation':'INT21_AH3F','resolved_path':'GENEWARS\\SOUND\\SOUND.DAT'},
            {'event':'dos_handle_close','path':'GENEWARS\\DATA\\CREATURE\\MULE.ANB'},
        ]
        result=summarize(rows)
        self.assertEqual(result['last_runtime_checkpoint']['link_va'],0x9FDF9)
        self.assertEqual(result['api_event_count'],1)
        self.assertEqual(result['last_trace_event']['event'],'dos_handle_close')
        self.assertEqual(result['port_events'],[])
        self.assertEqual(result['branch_events'],[])

    def test_validates_bounded_jsonl(self):
        rows=parse_trace(b'{"event":"one"}\n{"event":"two"}\n',max_bytes=64,max_rows=2)
        self.assertEqual(len(rows),2)
        with self.assertRaises(ValueError): parse_trace(b'12345',max_bytes=4,max_rows=2)
        with self.assertRaises(ValueError): parse_trace(b'{"event":"1"}\n{"event":"2"}',max_bytes=64,max_rows=1)

    def test_rejects_invalid_json(self):
        with self.assertRaises(json.JSONDecodeError): parse_trace(b'{bad json}\n')

if __name__=='__main__': unittest.main()
