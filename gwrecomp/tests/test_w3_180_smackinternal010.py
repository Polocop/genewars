import unittest

from tools.w3_180_smackinternal010_audit import audit


class SmackInternal010AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = audit()

    def test_source_fingerprints_and_dynamic_target_are_exact(self):
        self.assertEqual(self.result["provenance"]["target_sha256"],
                         "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertEqual(self.result["dynamic_entry"]["handler_link_va"], "0xeccf0")
        self.assertEqual(self.result["dynamic_entry"]["handler_sequence"],
                         self.result["dynamic_entry"]["dispatcher_sequence"] + 1)

    def test_initial_branch_and_convergence_bytes_are_exact(self):
        self.assertEqual(self.result["first_branch"]["link_va"], "0xecd02")
        self.assertEqual(self.result["first_branch"]["target_link_va"], "0xecd40")
        self.assertEqual(self.result["first_progress_instruction"]["bytes"], "a0c0c91000")

    def test_label_range_is_not_misrepresented_as_function_extent(self):
        self.assertIn("not a proven standalone function extent",
                      self.result["label_range"]["interpretation"])
        self.assertGreater(len(self.result["direct_flow_exits_from_label_range"]), 0)
        self.assertEqual(self.result["returns_inside_label_range"], [])

    def test_unknown_dynamic_values_remain_unknown(self):
        self.assertEqual(self.result["entry_instruction"]["global_pre_and_post_values"],
                         "NOT_CAPTURED")
        self.assertIn("handler completion", self.result["next_capture_recommendation"]["not_proven"])


if __name__ == "__main__":
    unittest.main()
