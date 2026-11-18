import pathlib
import unittest

from tools.verify_native_ah44_bx1_callsite_work1 import validate


class NativeAh44Bx1CallsiteTests(unittest.TestCase):
    def test_fresh_bx1_isatty_request_has_dynamic_chktty_caller(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        result = validate(root / "evidence" / "native_ah44_bx1_callsite_work1.json")
        self.assertTrue(result["passed"])
        self.assertEqual(result["dynamic_caller"], "0x000BA4D6 (__chktty_)")
        self.assertEqual(result["callsite"], "0x000BA4E4")
        self.assertEqual(result["isatty_entry_eax"], "0x00000001")
        self.assertEqual(result["request_bx"], "0x00000001")
        self.assertFalse(result["original_equivalence"])


if __name__ == "__main__":
    unittest.main()
