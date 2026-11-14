import unittest

from tools.w3_292_ecd40_run_reconciliation import reconcile


def run(name, before, after, opts, source, binary, stop=None, steps=None):
    identity = {"target_sha256": "target", "fixture_bytes": 123, "config_sha256": "config", "cue_sha256": "cue", "cue_read_only": True, "staging_revision": "rev", "code_rebase": "0x001EB000"}
    return {
        **identity, "source_sha256": source, "binary_sha256": binary,
        "w3_177_dispatch": {"link_va": 0xEDC94, "eax": 1, "eflags": 2, "elapsed_ms": 10},
        "w3_177_handler": {"link_va": 0xECCF0, "eax": 1, "eflags": 2, "elapsed_ms": 11},
        "w3_193_initial_step": {"before_link_va": before, "after_link_va": after},
        "w3_198_step_ordinals": steps or [], "w3_198_stop": stop,
        "probe_opt_ins_in_runner": opts,
        "probe_event_counts": {"w3_278_branch_target": 0, "w3_285_smacker_direct_entry": 0, "w3_289_smacker_callee_entry": 0, "w3_291_ecd40_target_hit": 0},
    }


class W3292ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.opt_a = {"w3_279_branch_step": True, "w3_285_capture": True, "w3_289_capture": True, "w3_291_capture": False}
        self.opt_b = {"w3_279_branch_step": False, "w3_285_capture": False, "w3_289_capture": False, "w3_291_capture": True}
        self.a = run("W3-289", 0xECD2B, 0xECD31, self.opt_a, "srca", "bina", steps=[1, 2, 3, 4, 5])
        self.b = run("W3-291", 0xECD31, 0xECD34, self.opt_b, "srcb", "binb", stop={"reason": "initial_step_did_not_reach_measured_successor", "steps": 0})

    def test_identity_and_register_equality_do_not_imply_causality(self):
        out = reconcile(self.a, self.b)
        self.assertTrue(all(out["same_fixture_identity_fields"].values()))
        self.assertTrue(all(out["measured_w3_177_register_equality"]["w3_177_handler"].values()))
        self.assertEqual(out["causal_attribution"], "UNKNOWN")
        self.assertFalse(out["same_run_or_same_seed_claim"])

    def test_initial_step_difference_is_preserved(self):
        out = reconcile(self.a, self.b)
        self.assertEqual(out["w3_289_initial_step"]["before_link_va"], "0x000ECD2B")
        self.assertEqual(out["w3_291_initial_step"]["before_link_va"], "0x000ECD31")
        self.assertEqual(out["w3_291_initial_step"]["stop"]["steps"], 0)

    def test_build_and_runner_variation_is_explicit(self):
        out = reconcile(self.a, self.b)
        self.assertFalse(out["source_sha256_equal"])
        self.assertFalse(out["binary_sha256_equal"])
        self.assertTrue(out["runner_opt_in_difference"]["w3_289_capture"]["W3-289"])
        self.assertTrue(out["runner_opt_in_difference"]["w3_291_capture"]["W3-291"])
        self.assertFalse(out["framebuffer_verified"])


if __name__ == "__main__":
    unittest.main()
