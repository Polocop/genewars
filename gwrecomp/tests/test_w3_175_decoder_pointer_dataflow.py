import unittest

from tools.w3_175_decoder_pointer_dataflow import audit


class DecoderPointerDataflowTests(unittest.TestCase):
    def test_exact_target_and_observed_argument_mapping(self):
        result = audit()
        self.assertEqual(result["target"]["sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        args = result["observed_arguments"]
        self.assertEqual([a["value"] for a in args], ["0x8f958c", "0x8b06c0", "0x1a0b34"])
        self.assertEqual([a["static_caller_source"] for a in args],
                         ["[caller ESI+0x3E0]", "[caller ESI+0x39C]", "[caller ESI+0x3A0]"])

    def test_decoder_indirect_dispatch_and_unknown_destination_are_explicit(self):
        result = audit()
        static = result["exact_target_static_flow"]
        self.assertIn("indirect JMP", static["dispatch"])
        self.assertIn("UNKNOWN", static["destination_finding"])
        self.assertFalse(result["dynamic_same_run"]["decoded_callback_target_observed"])

    def test_next_boundary_is_source_anchored(self):
        result = audit()
        self.assertEqual(result["next_minimal_dynamic_point"]["static_label"], "jump_ede94")
        self.assertEqual(result["next_minimal_dynamic_point"]["link_va"], "0xEDE94")


if __name__ == "__main__":
    unittest.main()
