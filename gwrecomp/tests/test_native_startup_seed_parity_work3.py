import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class NativeStartupSeedParityTests(unittest.TestCase):
    def test_fixture_and_seed_gap_are_explicit(self):
        d=json.loads((ROOT/"evidence/native_startup_seed_parity_work3.json").read_text(encoding="utf-8"))
        self.assertEqual(d["status"],"DONE_WITH_COMPARABILITY_LIMITATION")
        self.assertTrue(d["fixture"]["input_parity_verified"])
        self.assertFalse(d["comparator"]["shared_seed_proven"])
        self.assertTrue(d["comparator"]["original_full_entry_snapshot_missing"])
        self.assertEqual(d["earliest_common_measured_checkpoint"]["matching_request_registers"],["eax","ebx","ecx","edx"])
        self.assertEqual(d["earliest_common_measured_checkpoint"]["differing_fields"]["esi"],["0x00000160","0x00000008"])

    def test_checkpoint_mismatch_is_not_overclaimed(self):
        d=json.loads((ROOT/"evidence/native_startup_seed_parity_work3.json").read_text(encoding="utf-8"))
        self.assertIn("not an identified earliest causal",d["earliest_common_measured_checkpoint"]["classification"])
        self.assertFalse(d["downstream"]["null_this_is_native_divergence"])
        self.assertFalse(d["downstream"]["invented_this_seeded"])

if __name__ == "__main__":
    unittest.main()
