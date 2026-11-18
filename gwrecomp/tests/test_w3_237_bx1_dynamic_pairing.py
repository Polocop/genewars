import unittest
import subprocess
import sys

from tools.w3_237_bx1_dynamic_pairing import correlate, source_instrumentation_valid


def checkpoint(name, ordinal, eax=0, ebx=0, correlated=0, valid=False,
               link_va=0xC8973):
    return {"event": "target_runtime_checkpoint", "checkpoint": name,
            "w3_237_event_ordinal": ordinal,
            "w3_237_correlated_isatty_entry_ordinal": correlated,
            "w3_237_correlation_valid": valid,
            "process_psp": 0x1E83,
            "eax": eax, "ebx": ebx, "ecx": 0, "edx": 0, "esi": 0,
            "edi": 0, "ebp": 0, "esp": 0x1000, "eflags": 0x202,
            "cs": 0x160, "ds": 0x168, "ss": 0x168,
            "stack_words_u32": [0x123456, 0, 0, 0], "return_address": 0x123456,
            "linear": 0x200000, "link_va": link_va}


class W3237PairingTests(unittest.TestCase):
    def test_each_natural_bx1_request_pairs_to_active_entry(self):
        events = [checkpoint("W3_237_ISATTY_ENTRY", 1, link_va=0xC896A),
                  checkpoint("W3_237_AH4400_REQUEST", 1, 0x4400, 1, 1, True),
                  checkpoint("W3_237_AH4400_RETURN", 0, correlated=1, valid=True),
                  checkpoint("W3_237_ISATTY_ENTRY", 2, link_va=0xC896A),
                  checkpoint("W3_237_AH4400_REQUEST", 2, 0x4400, 5, 2, True)]
        result = correlate(events)
        self.assertEqual(result["classification"], "ORIGINAL_OBSERVED")
        self.assertEqual(result["bx1_requests"][0]["correlated_entry_ordinal"], 1)
        self.assertIs(result["bx1_requests"][0]["entry"], events[0])

    def test_no_entry_is_reported_as_unpaired_not_invented(self):
        event = checkpoint("W3_237_AH4400_REQUEST", 1, 0x4400, 1)
        result = correlate([event])
        self.assertEqual(result["classification"], "ORIGINAL_OBSERVED")
        self.assertEqual(result["bx1_requests"][0]["correlated_entry_ordinal"], 0)
        self.assertIsNone(result["bx1_requests"][0]["entry"])

    def test_wrong_active_ordinal_and_missing_cpu_context_are_rejected(self):
        events = [checkpoint("W3_237_ISATTY_ENTRY", 1, link_va=0xC896A),
                  checkpoint("W3_237_AH4400_REQUEST", 1, 0x4400, 1, 2, True)]
        with self.assertRaises(ValueError):
            correlate(events)
        incomplete = checkpoint("W3_237_AH4400_REQUEST", 1, 0x4400, 1)
        del incomplete["eflags"]
        with self.assertRaises(ValueError):
            correlate([incomplete])

    def test_capture_mode_is_bounded_and_present_in_source(self):
        from pathlib import Path
        source = Path("third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text()
        self.assertTrue(source_instrumentation_valid(source))
        runner = Path("tools/w3_237_bx1_dynamic_pairing_runner.py").read_text()
        for key in ("GWRECOMP_ANCHOR_MAIN_ENTRY_LINK", "GWRECOMP_ANCHOR_MAIN_ENTRY_BYTES",
                    "GWRECOMP_ANCHOR_GAME_MAIN_ENTRY_LINK", "GWRECOMP_W3_237_CAPTURE_ONLY"):
            self.assertIn(key, runner)
        result = subprocess.run([sys.executable, "-B", "-c",
                                 "import tools.w3_238_bx1_dynamic_pairing_runner"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_probe_window_requires_mode_and_measured_main_mapping(self):
        from tools.w3_237_bx1_dynamic_pairing import probe_window_contains
        self.assertFalse(probe_window_contains(0xC896A, capture_only=False, main_rebase=1))
        self.assertFalse(probe_window_contains(0xC896A, capture_only=True, main_rebase=0))
        self.assertFalse(probe_window_contains(0xC8969, capture_only=True, main_rebase=1))
        self.assertTrue(probe_window_contains(0xC896A, capture_only=True, main_rebase=0x1EB000))
        self.assertTrue(probe_window_contains(0xC8973, capture_only=True, main_rebase=0x1EB000))
        self.assertTrue(probe_window_contains(0xC8975, capture_only=True, main_rebase=0x1EB000))
        self.assertFalse(probe_window_contains(0xC8976, capture_only=True, main_rebase=0x1EB000))


if __name__ == "__main__":
    unittest.main()
