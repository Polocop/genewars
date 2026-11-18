import unittest

from tools.w3_241_isatty_static_caller import analyze


class W3241IsattyStaticCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = analyze()

    def test_target_and_static_artifact_are_exact_hash_bound(self):
        target = self.result["target"]
        static = self.result["static_source"]
        self.assertEqual(target["size"], 1_251_658)
        self.assertEqual(len(target["sha256"]), 64)
        self.assertEqual(target["sha256"], static["target_sha256"])

    def test_dynamic_return_pairs_first_call_to_sopen_only(self):
        dynamic = self.result["dynamic_source"]
        static = self.result["static_source"]
        self.assertEqual(static["caller"], "sopen_")
        self.assertEqual(static["callsite"], "0x000AFCEF")
        self.assertTrue(dynamic["return_matches_static_callsite"])
        self.assertEqual(dynamic["return_link_va"], "0xAFCF4")
        self.assertEqual(dynamic["request_bx"], "0x5")
        self.assertEqual(dynamic["return_cf"], False)

    def test_argument_origin_and_later_bx1_are_separated(self):
        self.assertTrue(self.result["argument_corroboration"]["dynamic_values_match"])
        self.assertEqual(self.result["later_bx1_status"]["w3_236_dynamic_caller"], "UNKNOWN")
        self.assertFalse(self.result["later_bx1_status"]["same_invocation_as_w3_239_first_call"])
        self.assertFalse(self.result["native_comparison"]["same_run_or_same_dynamic_call"])


if __name__ == "__main__":
    unittest.main()
