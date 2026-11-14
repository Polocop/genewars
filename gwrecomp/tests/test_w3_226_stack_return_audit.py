from __future__ import annotations

import unittest

from tools.w3_226_stack_return_audit import audit


class W3226StackReturnAuditTests(unittest.TestCase):
    def test_sampled_return_word_lies_inside_stack_window(self):
        result = audit()
        observed = result["stack_observation"]
        self.assertEqual(observed["ss"], observed["ds"])
        self.assertEqual(observed["stack_linear"], observed["esp"])
        self.assertEqual(observed["stack_return_raw"] - observed["esp"], 33)
        self.assertTrue(observed["sampler_emitted_eight_words"])

    def test_candidate_is_not_in_main_executable_objects(self):
        result = audit()
        self.assertTrue(result["candidate_analysis"]["candidate_in_le_object_3_stack"])
        self.assertFalse(result["candidate_analysis"]["candidate_in_le_executable_objects"])
        self.assertEqual(result["classification"], "NOT_VALIDATED_AS_MAIN_CALLER")

    def test_flat_cs_prevents_claiming_impossible_address(self):
        result = audit()
        self.assertEqual(result["code_descriptor"]["base"], 0)
        self.assertEqual(result["code_descriptor"]["limit"], 0xFFFFFFFF)
        self.assertEqual(result["direct_caller"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
