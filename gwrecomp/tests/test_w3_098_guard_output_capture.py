import json
import subprocess
import sys
import unittest


class GuardOutputCaptureTests(unittest.TestCase):
    def test_explicit_console_python_preserves_both_streams(self):
        code = 'import json,sys; print(json.dumps({"ok": True})); print("diagnostic", file=sys.stderr)'
        done = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True,
                              text=True, timeout=10, check=False)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(json.loads(done.stdout), {"ok": True})
        self.assertEqual(done.stderr.strip(), "diagnostic")

    def test_empty_historical_guard_logs_are_not_accepted_as_json(self):
        self.assertEqual("".strip(), "")
        with self.assertRaises(json.JSONDecodeError):
            json.loads("")


if __name__ == "__main__":
    unittest.main()
