from __future__ import annotations
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class GetConfigsBranchEvidenceTests(unittest.TestCase):
    def test_hash_bound_original_success_and_no_config_exit(self):
        evidence = json.loads((ROOT / 'evidence/w3_084_getconfigs_branch_compare.json').read_text(encoding='utf-8'))
        self.assertEqual(evidence['task'], 'W3-084')
        for rel, expected in evidence['source_hashes'].items():
            # Source keys are descriptive labels; paths are the known evidence inputs below.
            pass
        source_paths = {
            'disassembly': 'evidence/genewars-1_1-le_disasm.s',
            'original_capture': 'evidence/w3_083_setup_continuation.json',
            'no_config_control': 'evidence/getconfigs_staged_tree_work2.json',
            'no_config_report': 'reports/getconfigs_staged_tree_work2.md',
            'fixture_validation': 'evidence/w3_067_staging_functional_validation_20261008.json',
            'fixture_provenance': 'evidence/w3_067_functional_clone_20261008.json',
        }
        self.assertEqual(set(source_paths), set(evidence['source_hashes']))
        for key, rel in source_paths.items():
            digest = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(digest, evidence['source_hashes'][key], key)

        static = evidence['static_control_flow']
        self.assertEqual(static['line_range'], [161700, 161707])
        self.assertEqual(static['snippet'][1:7], ['call GetConfigs', 'test %al,%al', 'jne jump_94ae9', 'xor %eax,%eax', 'call exit_', 'jump_94ae9:'])
        observed = evidence['original_config_present_observation']
        self.assertEqual(observed['success_continuation']['link_va'], 0x94AE9)
        self.assertEqual(observed['success_continuation']['eax'], 1)
        self.assertEqual(observed['main_mapping']['code_rebase'], 0x1EB000)
        self.assertEqual(observed['main_mapping']['data_rebase'], 0x1DA000)
        self.assertEqual(observed['dosbox_config_sha256'], 'b2bac63096aa97a808abb8ea09486db79559b12a25a1410ea930be0e5eeffff1')

        control = evidence['no_config_control']
        self.assertEqual(control['config_open_attempts'][0]['error'], 2)
        self.assertEqual(control['process_exit']['eip'], '0x001afc33')
        self.assertFalse(control['target_stop_is_observed_checkpoint'])
        self.assertFalse(evidence['guard_and_scope']['new_oracle_run'])
        self.assertIn('does not establish that CONFIG.INI is the only cause', evidence['comparison']['bounded_conclusion'])

if __name__ == '__main__':
    unittest.main()

