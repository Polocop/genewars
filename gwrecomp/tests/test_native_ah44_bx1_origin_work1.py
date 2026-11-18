import pathlib
import unittest

from tools.verify_native_ah44_bx1_origin_work1 import validate


class NativeAh44Bx1OriginEvidenceTests(unittest.TestCase):
    def test_fresh_capture_proves_guest_eax_copy_but_not_dynamic_caller(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        result = validate(root / "evidence" / "native_ah44_bx1_origin_work1.json")
        self.assertTrue(result["passed"])
        self.assertEqual(result["entries"], 12)
        self.assertEqual(result["requests"], 12)
        self.assertEqual(int(result["bx1"]["ebx"], 16), 1)
        self.assertEqual(result["dynamic_caller"], "unresolved: dummy RECOMP_RETADDR is not a caller address")


if __name__ == "__main__":
    unittest.main()
