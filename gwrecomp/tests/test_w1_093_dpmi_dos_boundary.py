import pathlib
import unittest

from tools.verify_w1_093_dpmi_dos_boundary import verify


ROOT = pathlib.Path(__file__).resolve().parents[1]


class W1_093DpmiDosBoundaryTests(unittest.TestCase):
    def test_native_trace_keeps_dos_backing_disjoint_from_image(self):
        result = verify(ROOT / "evidence" / "dpmi_allocator_lifecycle_w1_093.json")
        self.assertEqual(result["dos_free_end_segment"], "1000")
        self.assertEqual(result["frontier"], "000ae0b0")
        self.assertFalse(result["vesa_reached"])


if __name__ == "__main__":
    unittest.main()
