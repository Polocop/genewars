import unittest

from tools.w3_172_smack_unsmack_dataflow import audit


class SmackUnsmackDataflowTests(unittest.TestCase):
    def test_exact_target_and_static_argument_order(self):
        result = audit()
        self.assertEqual(result["target"]["sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        params = result["static"]["callee_parameter_order"]
        self.assertEqual([p["value"] for p in params], [
            "caller [ESI+0x3E0]", "caller [ESI+0x39C]", "caller [ESI+0x3A0]"])

    def test_keeps_destination_unknown_when_callback_is_indirect(self):
        result = audit()
        self.assertIn("UNKNOWN", result["static"]["w_screen_argument_role"])
        self.assertIn("indirect JMP", result["static"]["decoder_dispatch"])

    def test_uses_valid_same_run_sample_points_and_order(self):
        result = audit()
        dynamic = result["dynamic_same_run"]
        self.assertEqual(dynamic["w_screen_pointer_frame_and_copy"], "0x394920")
        self.assertLess(dynamic["frame_sequence"], dynamic["copy_pre_sequence"])
        self.assertEqual(dynamic["sampled_classification"], "SAMPLED_BYTES_STABLE")


if __name__ == "__main__":
    unittest.main()
