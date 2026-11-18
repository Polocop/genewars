from __future__ import annotations
import hashlib
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class AddressTxtProvenanceTests(unittest.TestCase):
    def test_hash_bound_provenance_and_open_mode(self):
        ev=json.loads((ROOT/'evidence/w3_086_address_txt_provenance.json').read_text(encoding='utf-8'))
        self.assertEqual(ev['classification'],'SANDBOX_OUTPUT_NOT_FIXTURE_ASSET')
        inventory=json.loads((ROOT/'evidence/w3_user_functional_source_inventory_work3.json').read_text(encoding='utf-8'))
        clone=json.loads((ROOT/'evidence/w3_067_functional_clone_20261008.json').read_text(encoding='utf-8'))
        self.assertFalse(any(x['relative_path'].lower().endswith('address.txt') for x in inventory['inventory']['files']))
        self.assertEqual(clone['source_copy']['source_file_count'],429)
        self.assertEqual(clone['clone']['file_count'],430)
        self.assertEqual(ev['w3_085_open']['open_event']['requested_path'],'c:\\address.txt')
        self.assertEqual(ev['w3_085_open']['open_event']['entry'],5)
        self.assertEqual(ev['w3_085_open']['open_event']['flags'],1)
        self.assertEqual(ev['w3_085_open']['mode_symbol'],'OPEN_WRITE')
        self.assertEqual(ev['current_vhdx_root_file']['size_bytes'],24)
        self.assertIn('predates the W3-085 run',ev['conclusion']['current_run_relation'])
        self.assertFalse(ev['scope']['oracle_run_performed'])
        paths={
          'source_inventory':'evidence/w3_user_functional_source_inventory_work3.json',
          'clone_manifest':'evidence/w3_067_functional_clone_20261008.json',
          'w3_085_capture':'evidence/w3_085_handle5_lineage.json',
          'staging_dos_dispatch':'third_party/dosbox-staging-w3-059-instrumented/src/dos/dos.cpp',
          'staging_dos_open_modes':'third_party/dosbox-staging-w3-059-instrumented/src/dos/dos_system.h',
          'prior_run_1':'evidence/oracle_runs/oracle_runs_w3-059-path-progress-20261007.json',
          'prior_run_2':'evidence/oracle_runs/oracle_runs_w3-067-functional-guarded2-20261008.json',
          'prior_run_3':'evidence/oracle_runs/oracle_runs_w3-067-functional-absolute-conf-20261008.json',
        }
        for key,rel in paths.items():
            self.assertEqual(hashlib.sha256((ROOT/rel).read_bytes()).hexdigest(),ev['source_hashes'][key],key)

if __name__=='__main__':
    unittest.main()
