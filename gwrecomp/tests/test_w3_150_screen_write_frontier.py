import unittest
from tools.w3_150_screen_write_frontier import audit, TARGET_SHA256


class LbScreenSwapStaticFrontierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = audit()

    def test_exact_target_hash_and_function_bounds(self):
        self.assertEqual(self.result["provenance"]["target_sha256"], TARGET_SHA256)
        self.assertEqual(self.result["function"]["link_start"], "0x0009FFE0")
        self.assertEqual(self.result["function"]["link_end_exclusive"], "0x000A0090")

    def test_copy_instruction_addresses_are_exact_decoded_boundaries(self):
        instructions = {item["link_va"]: item for item in self.result["instructions"]}
        self.assertEqual(instructions["0x000A0013"]["bytes"], "f3a5")
        self.assertEqual(instructions["0x000A005D"]["bytes"], "f3a5")
        self.assertEqual(instructions["0x000A0000"]["bytes"], "7515")

    def test_globals_are_map_and_le_object_bound(self):
        globals_ = self.result["globals"]
        self.assertEqual(globals_["_lbDisplay"]["link_va"], "0x0019CA58")
        self.assertEqual(globals_["lbDisplay__WScreen"]["link_va"], "0x0019CA5C")
        self.assertEqual(globals_["lbDisplay__VesaIsSetUp"]["link_va"], "0x0019CABE")
        self.assertEqual(globals_["_lbDisplay"]["le_object"], 3)

    def test_next_capture_is_bounded_and_mapping_distinguishes_code_data(self):
        plan = self.result["next_capture_plan"]
        self.assertTrue(plan["one_replay"])
        self.assertEqual(len(plan["capture_only"]), 5)
        mapping = self.result["runtime_mapping"]
        self.assertEqual(mapping["code_rebase_observed_in_W3_149"], "0x001EB000")
        self.assertEqual(mapping["data_rebase_observed_in_W3_149"], "0x001DA000")
        self.assertTrue(mapping["require_fresh_measurement_each_replay"])
        self.assertIn("does not establish", " ".join(plan["limitations"]))


if __name__ == "__main__":
    unittest.main()
