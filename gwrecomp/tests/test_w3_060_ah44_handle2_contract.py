from __future__ import annotations

import json
import unittest

from tools.w3_060_ah44_handle2_contract import OUT, build_contract


class W3060Ah44Handle2Tests(unittest.TestCase):
    def test_original_bx2_request_and_response(self):
        result = build_contract()
        self.assertTrue(result["acceptance_checks"]["original_ax4400_bx2_observed"])
        self.assertTrue(result["acceptance_checks"]["site_mapping_verified_for_capture"])
        self.assertTrue(result["acceptance_checks"]["same_process_and_registers"])
        self.assertTrue(result["acceptance_checks"]["dos_return_observed"])
        self.assertEqual(result["request"]["main_callsite"]["link_va"], 0xC8973)
        self.assertEqual(result["request"]["BX"], 2)
        self.assertEqual(result["response"]["AX"], 2)
        self.assertEqual(result["response"]["DX"], 2)
        self.assertFalse(result["response"]["CF"])

    def test_handle_and_continuation_are_scoped(self):
        result = build_contract()
        self.assertEqual(result["request"]["JFT_entry"]["entry"], 2)
        self.assertEqual(result["request"]["JFT_entry"]["name"], "CON")
        self.assertTrue(result["acceptance_checks"]["next_runtime_dos_event_observed"])
        self.assertFalse(result["continuation"]["immediate_return_checkpoint"])
        self.assertIn("BX=1", " ".join(result["limits"]))
        self.assertIn("UNKNOWN", " ".join(result["limits"]))

    def test_serialized_evidence_is_repeatable_and_no_replay_is_claimed(self):
        first = build_contract()
        second = json.loads(OUT.read_text(encoding="utf-8"))
        self.assertEqual(first, second)
        self.assertEqual(first["provenance"]["target_sha256"],
                         "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(first["evidence_level"], "ORIGINAL_OBSERVED")


if __name__ == "__main__":
    unittest.main()
