import unittest
from pathlib import Path

from tools.w3_237_bx1_dynamic_pairing import (
    ENTRY, REQUEST, RETURN, correlate, probe_window_contains,
)
from tests.test_w3_237_bx1_dynamic_pairing import checkpoint


class W3239ProbeWindowTests(unittest.TestCase):
    def test_probe_window_boundaries_and_gates(self):
        start, end, rebase = 0xC896A, 0xC8975, 0x1EB000
        self.assertFalse(probe_window_contains(start, capture_only=False, main_rebase=rebase))
        self.assertFalse(probe_window_contains(start, capture_only=True, main_rebase=0))
        self.assertFalse(probe_window_contains(start - 1, capture_only=True, main_rebase=rebase))
        self.assertTrue(probe_window_contains(start, capture_only=True, main_rebase=rebase))
        self.assertTrue(probe_window_contains(0xC8973, capture_only=True, main_rebase=rebase))
        self.assertTrue(probe_window_contains(end, capture_only=True, main_rebase=rebase))
        self.assertFalse(probe_window_contains(end + 1, capture_only=True, main_rebase=rebase))

    def test_source_has_narrow_mapping_gated_probe(self):
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text()
        self.assertIn("w3_237_capture_only && candidate_link_va >= 0x000c896a", source)
        self.assertIn("candidate_link_va <= 0x000c8975", source)
        self.assertIn("w3_237_probe_window ||", source)

    def test_synthetic_bx1_correlates_to_active_same_process_entry(self):
        entry = checkpoint(ENTRY, 1, eax=5, ebx=2, link_va=0xC896A)
        request = checkpoint(REQUEST, 1, eax=0x4400, ebx=1,
                             correlated=1, valid=True, link_va=0xC8973)
        request["ds_edx_plus_10_valid"] = True
        request["ds_edx_plus_10"] = 1
        ret = checkpoint(RETURN, 0, correlated=1, valid=True, link_va=0xC8975)
        result = correlate([entry, request, ret])
        self.assertEqual(result["classification"], "ORIGINAL_OBSERVED")
        self.assertEqual(result["bx1_requests"][0]["correlated_entry_ordinal"], 1)

    def test_cross_process_correlation_is_rejected(self):
        entry = checkpoint(ENTRY, 1, link_va=0xC896A)
        request = checkpoint(REQUEST, 1, eax=0x4400, ebx=1,
                             correlated=1, valid=True, link_va=0xC8973)
        request["process_psp"] = 0x2000
        with self.assertRaises(ValueError):
            correlate([entry, request])

    def test_capture_event_bound_is_enforced(self):
        entries = [checkpoint(ENTRY, i + 1, link_va=0xC896A) for i in range(193)]
        with self.assertRaises(ValueError):
            correlate(entries)


if __name__ == "__main__":
    unittest.main()
