import unittest

from tools.w3_222_adjustment_checkpoint_audit import audit


class AdjustmentCheckpointAuditTests(unittest.TestCase):
    def test_pinned_inputs_and_hashes_are_present(self):
        result = audit()
        self.assertEqual(result["task"], "W3-222")
        self.assertEqual(result["pinned_staging_revision"],
                         "81835b01c54dcb1510bc2d09d0b9aa5a3f9a989f")
        self.assertTrue(result["w3_213_source_revision_matches_pin"])
        for path in (
            "evidence\\w3_213_adjustamount_original.json",
            "build\\dosboxx_oracle\\C\\W3_213_ADJUSTMENT_20261009_02.jsonl",
            "evidence\\w3_068_caller_chain_capture_20261008.json",
            "evidence\\w3_068_heap_alignment_capture_20261008_01.jsonl",
            "evidence\\native_ax0501_strict_w1_063.json",
        ):
            self.assertTrue(result["files"][path]["exists"], path)
            self.assertEqual(len(result["files"][path]["sha256"]), 64, path)

    def test_missed_checkpoints_are_not_misreported_as_runtime_absence(self):
        result = audit()
        hypothesis = result["hypothesis_audit"]
        self.assertEqual(result["w3_213"]["target_count"], 0)
        self.assertEqual(len(result["w3_213"]["checkpoints_found"]), 0)
        self.assertIn("UNKNOWN", hypothesis["exact_reason_target_was_not_seen"])
        self.assertTrue(hypothesis["new_hypothesis_supported"])
        self.assertEqual(result["w3_213"]["guard"]["cause"], "TIMEOUT")

    def test_distinct_original_and_native_contexts_stay_separate(self):
        result = audit()
        original = result["w3_068_original"]
        native = result["w1_063_native"]
        self.assertEqual(original["adjustamount_input"].split()[0], "0x40")
        self.assertEqual(original["adjustamount_output"].split()[0], "0x1000")
        self.assertEqual(native["request_size_bytes"], "0x00001000")
        self.assertEqual(native["native_adjustamount_global_10c828"], "0x10")
        self.assertIsNone(original["global_10c828_at_adjust_entry"])
        self.assertEqual(result["evidence_level"], "SYNTHETIC_PASS")
        self.assertEqual(result["runtime_capture_outcome"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
