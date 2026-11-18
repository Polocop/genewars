from __future__ import annotations

import json
import unittest

from tools.w3_225_ah4400_static_audit import audit, OUT


class W3225AuditTests(unittest.TestCase):
    def test_ordinal_six_pair_and_return_are_evidence_bound(self):
        result = audit()
        event = result["ordinal6"]
        self.assertEqual(event["sequence"], 43)
        self.assertEqual(event["request"]["AX"], 0x4400)
        self.assertEqual(event["request"]["BX"], 2)
        self.assertEqual(event["return"], {"AX": 2, "DX": 2, "CF": False})
        self.assertEqual(event["same_process_callsite_sequence"], 42)
        self.assertEqual(event["callsite_link_va"], 0xC8973)
        self.assertTrue(event["callsite_registers_match_callback"])

    def test_mapping_marker_is_not_misread_as_failed_anchor(self):
        result = audit()
        marker = result["mapping_marker_audit"]
        self.assertTrue(marker["byte_signature_matches"])
        self.assertFalse(marker["serialized_measured_address_matches"])
        self.assertTrue(marker["instrumentation_order_confirms_false_is_preseed"])
        self.assertEqual(marker["anchor_candidate_rebase"], 0x1EB000)

    def test_unresolved_caller_stays_unknown_and_json_is_repeatable(self):
        first = audit()
        second = json.loads(OUT.read_text(encoding="utf-8"))
        self.assertEqual(first, second)
        self.assertEqual(second["ordinal6"]["direct_caller"], "UNKNOWN")
        self.assertGreater(second["ordinal6"]["stack_return_candidate_link_va"],
                           second["ordinal6"]["map_nearest_symbol_before"]["va"])
        self.assertEqual(second["conclusion"], first["conclusion"])


if __name__ == "__main__":
    unittest.main()
