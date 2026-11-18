from __future__ import annotations
import hashlib
import json
import unittest
from pathlib import Path
from tools.w3_085_handle5_lineage import summarize_handle_lineage

ROOT = Path(__file__).resolve().parents[1]

class Handle5LineageTests(unittest.TestCase):
    def test_target_psp_open_maps_stream_entry(self):
        events = [
            {'event':'dos_handle_open','process_psp':10,'sequence':2,'entry':5,'internal_handle':4,'path':'GENEWARS\\GW.ERR'},
            {'event':'dos_handle_open','process_psp':11,'sequence':3,'entry':5,'internal_handle':5,'path':'OTHER'},
        ]
        result = summarize_handle_lineage(events, target_psp=10)
        self.assertEqual(result['status'], 'MAPPED')
        self.assertEqual(result['owner']['path'], 'GENEWARS\\GW.ERR')

    def test_duplicate_maps_source_entry_to_stream_entry(self):
        events = [
            {'event':'dos_handle_table_snapshot','process_psp':10,'sequence':1,'entries':[
                {'entry':1,'internal_handle':1,'open':True,'name':'CON'},
                {'entry':5,'internal_handle':255,'open':False,'name':None}]},
            {'event':'dos_handle_dup','process_psp':10,'sequence':2,'source_entry':1,'new_entry':5,'internal_handle':1,'path':'CON'},
        ]
        result = summarize_handle_lineage(events, target_psp=10)
        self.assertEqual(result['status'], 'MAPPED')
        self.assertEqual(result['owner']['source'], 'dos_handle_dup')
        self.assertEqual(result['owner']['path'], 'CON')

    def test_callsite_uses_prior_snapshot_not_later_handle_reuse(self):
        events = [
            {'event':'dos_handle_table_snapshot','process_psp':10,'sequence':31,'entries':[
                {'entry':5,'internal_handle':3,'open':True,'name':'ADDRESS.TXT'}]},
            {'event':'dos_handle_close','process_psp':10,'sequence':49,'entry':5,'internal_handle':3,'path':'ADDRESS.TXT'},
            {'event':'dos_handle_open','process_psp':10,'sequence':50,'entry':5,'internal_handle':4,'path':'DINOCRAB.ANB'},
        ]
        result = summarize_handle_lineage(events, target_psp=10, as_of_sequence=38)
        self.assertEqual(result['status'], 'MAPPED')
        self.assertEqual(result['owner']['path'], 'ADDRESS.TXT')
        self.assertEqual(result['owner']['sequence'], 31)

    def test_unknown_is_not_treated_as_absence(self):
        result = summarize_handle_lineage([], target_psp=10)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIn('absence is not proof', result['limitation'])

    def test_event_cap_marks_truncated_and_unknown(self):
        events = [{'event':'dos_handle_open','process_psp':10,'sequence':n,'entry':5,
                   'internal_handle':5,'path':'A'} for n in range(2)]
        result = summarize_handle_lineage(events, target_psp=10, max_events=2)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['status'], 'UNKNOWN')

    def test_original_evidence_is_hash_bound_and_bounded(self):
        evidence = json.loads((ROOT / 'evidence/w3_085_handle5_lineage.json').read_text(encoding='utf-8'))
        self.assertEqual(evidence['handle_lineage']['status'], 'MAPPED')
        self.assertEqual(evidence['handle_lineage']['as_of_sequence'], 38)
        self.assertEqual(evidence['handle_lineage']['owner']['path'], 'ADDRESS.TXT')
        self.assertEqual(evidence['handle_lineage_callsite']['link_va'], 0xBA4E4)
        self.assertEqual(evidence['classification'], 'ORIGINAL_HANDLE5_PROVENANCE_MAPPED')
        self.assertEqual(evidence['caller_reconciliation']['handle5_open_event']['requested_path'], 'c:\\address.txt')
        self.assertEqual(evidence['caller_reconciliation']['handle5_open_event']['entry'], 5)
        self.assertEqual(evidence['caller_reconciliation']['original_bx1_callback_count'], 0)
        self.assertEqual(evidence['trace']['bytes'], 153429)
        self.assertTrue(evidence['trace']['handle_event_cap_reached'])
        source_paths = {
            'previous_original_capture': 'evidence/w3_081_original_ah44_caller.json',
            'native_caller_evidence': 'evidence/native_ah44_bx1_callsite_work1.json',
            'pinned_dos_files_source': 'third_party/dosbox-staging-w3-059-instrumented/src/dos/dos_files.cpp',
            'pinned_cpu_source': 'third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp',
            'capture_runner': 'tools/w3_085_capture_runner.py',
        }
        for key, rel in source_paths.items():
            digest = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(digest, evidence['source_hashes'][key], key)

if __name__ == '__main__':
    unittest.main()


