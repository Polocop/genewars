import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NativeThisDivergenceEvidenceTests(unittest.TestCase):
    def test_fixture_and_frontier_are_pinned_without_overclaim(self):
        data = json.loads((ROOT / "evidence/native_this_divergence_work1.json").read_text())
        fixture = data["fixture_parity"]
        self.assertEqual(data["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(fixture["command_tail"], "-k")
        self.assertEqual(fixture["config_sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(fixture["cue_sha256"], "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5")
        self.assertTrue(fixture["cue_read_only"])

        original = data["runs"]["original"]["ax0501"]
        native = data["runs"]["native"]["ax0501"]
        for register in ("eax", "ebx", "ecx", "edx"):
            self.assertEqual(original[register], native[register], register)
        self.assertNotEqual(original["esi"], native["esi"])
        self.assertEqual(data["comparison"]["null_this_is_native_divergence"], False)
        self.assertFalse(data["runs"]["native"]["this_read_or_write_observed"])
        self.assertIn("not a proven first instruction divergence", data["comparison"]["classification"])


if __name__ == "__main__":
    unittest.main()
