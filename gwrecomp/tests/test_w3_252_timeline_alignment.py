import unittest

from tools.w3_252_timeline_alignment import align


def make(w236_elapsed=14705, w251_elapsed=18792, bx1=True):
    w236 = {
        "preflight": {"target_sha256": "t", "cue_sha256": "c", "config_sha256": "f", "runtime_sha256": "old"},
        "address_txt_initial": {"sha256": "a"},
        "mapping": {"code_rebase": 0x1EB000},
        "chktty_and_bx1": {
            "chktty_checkpoints": [{"sequence": 36, "link_va": 0xC896A, "elapsed_ms": w236_elapsed, "eax": 5, "ebx": 2, "edi": 5}],
            "bx1_callsites": ([{"sequence": 104, "cpu_entry_ordinal": 1, "int_instruction_link_va": 0xC8973, "return_link_va": 0xC8975}] if bx1 else []),
        },
        "guard": {"cause": "TIMEOUT", "limits": {"timeout_s": 30}},
        "last_checkpoint": "W3_149_LBSCREENSWAP_RETURN",
    }
    w251 = {
        "preflight": {"target_sha256": "t", "cue_sha256_before": "c", "config_sha256": "f", "address_sha256": "a", "runtime_sha256": "new"},
        "caller_pairing": {"isatty_entries": [{"code_rebase": 0x1EB000}], "bx1_requests": []},
        "target_checkpoints_compact": [{"checkpoint": "W3_237_ISATTY_ENTRY", "sequence": 19, "elapsed_ms": w251_elapsed, "eax": "0x5", "ebx": "0x2", "edi": "0x5"}],
        "original_ax4400_observations": [{"in_bx": "0x0005"}] * 5 + [{"in_bx": "0x0002"}] * 3,
        "guard": {"cause": "TIMEOUT", "limits": {"timeout_s": 30}},
        "dos_execute_tails": [' y "E:/build/Resources/drives/y" -t dir -label essentials -ro'],
        "last_trace_event": {"sequence": 125, "event": "dos_handle_close"},
    }
    return w236, w251


class TimelineAlignmentTests(unittest.TestCase):
    def test_measures_same_entry_delay_without_claiming_cause(self):
        old, new = make()
        result = align(old, new, {"alignment_conclusion": {"earliest_runtime_divergence": "UNKNOWN"}}, {"runtime_progress": {}})
        self.assertEqual(result["comparison"]["entry_elapsed_delta_ms"], 4087)
        self.assertIn("not_proven", result["interpretation"])
        self.assertEqual(result["classification"], "SAME_ENTRY_REACHED_LATER_IN_W3_251")
        self.assertTrue(result["comparison"]["same_fixture_hashes"])

    def test_preserves_missing_bx1(self):
        old, new = make(bx1=False)
        result = align(old, new, {}, {})
        self.assertIsNone(result["comparison"]["w3_236_bx1"])
        self.assertFalse(result["comparison"]["w3_251_bx1_observed"])

    def test_missing_elapsed_is_not_filled_in(self):
        old, new = make(w236_elapsed=None)
        old["chktty_and_bx1"]["chktty_checkpoints"][0].pop("elapsed_ms")
        result = align(old, new, {}, {})
        self.assertIsNone(result["comparison"]["entry_elapsed_delta_ms"])
        self.assertEqual(result["classification"], "COMPARABLE_ENTRY_TIMING_UNKNOWN")

    def test_requires_shared_entry_checkpoints(self):
        old, new = make()
        new["target_checkpoints_compact"] = []
        with self.assertRaises(ValueError):
            align(old, new, {}, {})


if __name__ == "__main__":
    unittest.main()
