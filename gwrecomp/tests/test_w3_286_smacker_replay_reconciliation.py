import unittest

from tools.w3_286_smacker_replay_reconciliation import CHAIN, classify, validate_trace


def row(name, seq, link, **extra):
    return {"sequence": seq, "event": "target_runtime_checkpoint", "checkpoint": name,
            "link_va": link, "cs": 0x160, "eax": 7, "ebx": 0, "ecx": 1,
            "edx": 0, "esi": 10, "edi": 11, "ebp": 12, "esp": 13,
            "eflags": 0x246, "stack_words_u32": [0x299306], **extra}


def capture(rows, run="run", rebase="0x001EB000"):
    return {
        "run_id": run,
        "provenance": {"target_sha256": "target", "fixture_bytes": 100,
                       "config_sha256": "config", "cue_sha256": "cue",
                       "cue_read_only": True, "staging_revision": "rev"},
        "analysis": {"code_rebase": rebase},
        "_rows": rows,
        "scope": {"menu_verified": False, "gameplay_verified": False},
    }


class SmackerReplayReconciliationTests(unittest.TestCase):
    def setUp(self):
        links = [0x92ADD, 0xAE2D0, 0xAE308, 0xC62F0]
        self.rows = [row(name, i + 1, links[i]) for i, name in enumerate(CHAIN)]

    def test_same_first_chain_is_classified_as_duplicate(self):
        result = classify(capture(self.rows), capture(self.rows, "second"))
        first = result["first_invocation_chain"]
        self.assertTrue(result["fixture_identity_equal"])
        self.assertTrue(first["same_observed_registers_and_direct_return"])
        self.assertIn("repeats the same first", first["conclusion"])
        self.assertTrue(first["ordered_in_both_runs"]["W3-280"])
        self.assertFalse(result["later_invocation"]["w3_285_adds_new_frontier"])

    def test_register_change_prevents_duplicate_claim(self):
        changed = [dict(r) for r in self.rows]
        changed[2]["esi"] += 1
        result = classify(capture(self.rows), capture(changed, "second"))
        self.assertFalse(result["first_invocation_chain"]["same_observed_registers_and_direct_return"])
        self.assertEqual(result["first_invocation_chain"]["conclusion"], "not proven identical")

    def test_later_branch_is_attributed_to_run_that_contains_it(self):
        later = [
            {"event": "w3_278_later_play_smk_entry", "link_va": 0xAE2D0},
            {"event": "w3_278_branch_target", "link_va": 0xAE2E3},
        ]
        result = classify(capture(self.rows + later), capture(self.rows, "second"))
        self.assertTrue(result["later_invocation"]["w3_280_later_entry_and_branch_destination_observed"])
        self.assertFalse(result["later_invocation"]["w3_285_later_entry_or_branch_destination_observed"])
        self.assertFalse(result["later_invocation"]["w3_285_adds_new_later_invocation"])

    def test_return_site_is_not_inferred_from_entry_stack(self):
        result = classify(capture(self.rows), capture(self.rows, "second"))
        self.assertFalse(result["return_and_visual_gate"]["ae306_executed_return_observed_w3_280"])
        self.assertFalse(result["return_and_visual_gate"]["ae306_executed_return_observed_w3_285"])
        self.assertFalse(result["return_and_visual_gate"]["framebuffer_pixels_verified_in_either_trace"])

    def test_trace_hash_row_count_and_caps_are_separate(self):
        import hashlib
        raw = b'{"sequence":1}\n'
        expected = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "rows": 1}
        checked = validate_trace(raw, expected)
        self.assertTrue(checked["metadata_matches"])
        self.assertTrue(checked["within_byte_cap"])
        self.assertTrue(checked["within_row_cap"])
        expected["sha256"] = "0" * 64
        self.assertFalse(validate_trace(raw, expected)["metadata_matches"])
        oversized = b"x" * (1_048_577)
        capped = validate_trace(oversized, {"bytes": len(oversized), "sha256": hashlib.sha256(oversized).hexdigest(), "rows": 1})
        self.assertFalse(capped["within_byte_cap"])

    def test_out_of_order_chain_is_not_called_duplicate(self):
        reversed_rows = list(reversed(self.rows))
        result = classify(capture(self.rows), capture(reversed_rows, "second"))
        self.assertFalse(result["first_invocation_chain"]["ordered_in_both_runs"]["W3-285"])
        self.assertFalse(result["first_invocation_chain"]["same_observed_registers_and_direct_return"])


if __name__ == "__main__":
    unittest.main()
