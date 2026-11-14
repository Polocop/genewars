import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
import bootstrap


class BootstrapPreflightTests(unittest.TestCase):
    def test_target_entry_and_first_runtime_blocker_are_reported(self):
        result = bootstrap.prepare(ROOT / "evidence" / "genewars-1_1.exe")
        self.assertTrue(result["prepared"])
        self.assertFalse(result["executed"])
        self.assertEqual(result["entry"]["object"], 1)
        self.assertEqual(result["entry"]["linear"], "0xaf96c")
        self.assertTrue(result["entry"]["object_executable"])
        self.assertEqual(result["stack"]["object"], 3)
        self.assertTrue(result["stack"]["object_writable"])
        self.assertEqual(result["memory"]["fixup_count"], 25204)
        self.assertEqual(result["le_import_modules"], 0)
        self.assertEqual(result["runtime_status"], "BLOCKED_BEFORE_EXECUTION")
        self.assertEqual(result["blocker"]["first_required_service"], "DOS INT 0x21")


if __name__ == "__main__":
    unittest.main()
