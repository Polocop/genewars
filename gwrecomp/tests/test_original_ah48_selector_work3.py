import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "original_ah48_selector_004c_work3.json"


class OriginalAh48SelectorContractTest(unittest.TestCase):
    def test_unmapped_extender_descriptor_is_not_misused(self):
        data = json.loads(EVIDENCE.read_text(encoding="utf-8-sig"))
        self.assertEqual(data["task"], "W3-059")
        self.assertEqual(data["status"], "blocked_unmapped_gene_wars_frontier")
        self.assertEqual(data["target"]["sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        measured = data["measurement"]
        self.assertFalse(measured["target_ah48_return_004c_captured"])
        self.assertFalse(measured["target_mov_es_site_captured"])
        self.assertFalse(measured["target_ah49_release_captured"])
        self.assertEqual(measured["code_va_translation"], "unavailable")
        self.assertEqual(measured["selector_004c_observation"]["association_with_target_ah48"], "NOT ESTABLISHED; sampled during a different DPMI/extender event; prohibited from W2-083 use")
        self.assertIn("0x0001fb30", measured["selector_004c_observation"]["selinfo_base"])
        self.assertIn("W3-056", data["required_unblock"])

    def test_fixture_and_disk_guard_are_pinned(self):
        data = json.loads(EVIDENCE.read_text(encoding="utf-8-sig"))
        fixture = data["fixture"]
        self.assertEqual(fixture["staged_main_sha256"], data["target"]["sha256"])
        self.assertEqual(fixture["empty_config_sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(fixture["cue_sha256"], "1d417e3aed625d4f054b51054a1211562a19cd4f712b08e7846613517228a5b5")
        self.assertEqual(data["runtime"]["guard_preflight"], "PASS")
        self.assertEqual(data["runtime"]["guard_limits"]["minimum_free_gib"], 100)
        self.assertFalse(data["reference_library_modified"])


if __name__ == "__main__":
    unittest.main()
