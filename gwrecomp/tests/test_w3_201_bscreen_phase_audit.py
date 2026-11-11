"""Read-only provenance audit plus synthetic B_SCREEN sample-bound tests."""
import unittest

from tools.w3_201_bscreen_phase_audit import audit, bounded_sample_range


class BScreenPhaseAuditTests(unittest.TestCase):
    def test_sample_window_is_inside_measured_allocation(self):
        start, end = bounded_sample_range(0x8B03C8, 307200, 64)
        self.assertEqual((start, end), (0x8B03C8, 0x8B0408))
        self.assertLessEqual(end, 0x8B03C8 + 307200)

    def test_unverified_or_oversized_ranges_fail_closed(self):
        with self.assertRaises(ValueError):
            bounded_sample_range(0x8B03C8, 0x4AFFF, 64)
        with self.assertRaises(ValueError):
            bounded_sample_range(0x8B03C8, 307200, 307201)
        with self.assertRaises(ValueError):
            bounded_sample_range(0xFFFFFFF0, 307200, 64)

    def test_real_evidence_reconciles_allocation_store_and_matching_free(self):
        result = audit()
        same_run = result["w3_199_same_run"]
        self.assertEqual(same_run["allocation"]["size_bytes"], 307200)
        self.assertEqual(same_run["allocation"]["pointer"], same_run["store"]["b_screen_pointer"])
        self.assertEqual(same_run["store"]["b_screen_pointer"], same_run["free"]["eax_pointer"])
        self.assertEqual(result["bounded_sample_candidate"]["bytes_max"], 64)
        self.assertIn("not pixel-format", result["bounded_sample_candidate"]["interpretation_limit"])


if __name__ == "__main__":
    unittest.main()
