import unittest

from tools.w3_156_loader_callsite import rel32_target


class LoaderCallsiteTests(unittest.TestCase):
    def test_relative_call_target_and_return(self):
        call_va = 0x94DBC
        instruction = bytes.fromhex("e8cf02f8ff")
        self.assertEqual(rel32_target(call_va, instruction), 0x15090)
        self.assertEqual(call_va + len(instruction), 0x94DC1)

    def test_rejects_non_call_or_bad_length(self):
        with self.assertRaises(ValueError):
            rel32_target(0x94DBC, bytes.fromhex("e8"))
        with self.assertRaises(ValueError):
            rel32_target(0x94DBC, bytes.fromhex("e9cf02f8ff"))


if __name__ == "__main__":
    unittest.main()
