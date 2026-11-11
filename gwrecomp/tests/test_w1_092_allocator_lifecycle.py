import pathlib
import unittest

from tools.verify_w1_093_dpmi_dos_boundary import verify


ROOT = pathlib.Path(__file__).resolve().parents[1]


class W1_093AllocatorLifecycleTests(unittest.TestCase):
    def test_fresh_native_receipt_has_bounded_real_allocator_events(self):
        result = verify(ROOT / "evidence" / "dpmi_allocator_lifecycle_w1_093.json")
        self.assertGreaterEqual(result["event_count"], result["sampled_events"])
        self.assertGreater(result["successes_sampled"], 0)
        self.assertEqual(result["guest_map_capacity"], "0xFFFF0000")


if __name__ == "__main__":
    unittest.main()
