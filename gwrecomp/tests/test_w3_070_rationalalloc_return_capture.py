import unittest

from tools.w3_070_rationalalloc_return_runner import validate_invocation_link


class RationalAllocReturnCaptureTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"sequence": 10, "checkpoint": "RATIONALALLOC_PRE_RET",
             "expected_return_link_va": 0xC3CBD, "epilogue_return_address": 0x2AEDB5,
             "esp": 100, "eax": 0x001A0008, "bytes": "83c4045f5e5a595bc353"},
            {"sequence": 11, "checkpoint": "RATIONALALLOC_EXPECTED_CALLER_CANDIDATE",
             "link_va": 0xC3CBD, "eip": 0x2AEDB5, "esp": 128, "eax": 0x001A0008},
        ]

    def test_accepts_ordered_same_invocation(self):
        link = validate_invocation_link(self.events)
        self.assertIsNotNone(link)
        self.assertTrue(link["causally_linked"])
        self.assertEqual(link["expected_return_link_va"], 0xC3CBD)
        self.assertFalse(link["ret_opcode_checkpoint_observed"])
        self.assertEqual(link["net_esp_advance"], 28)

    def test_rejects_different_return_target(self):
        self.events[1]["link_va"] = 0xC3D00
        self.assertIsNone(validate_invocation_link(self.events))

    def test_rejects_changed_return_value(self):
        self.events[1]["eax"] = 0x1000
        self.assertIsNone(validate_invocation_link(self.events))

    def test_rejects_incorrect_stack_delta(self):
        self.events[1]["esp"] = 124
        self.assertIsNone(validate_invocation_link(self.events))

    def test_rejects_intervening_capture(self):
        self.events[1]["sequence"] = 12
        self.assertIsNone(validate_invocation_link(self.events))


if __name__ == "__main__":
    unittest.main()
