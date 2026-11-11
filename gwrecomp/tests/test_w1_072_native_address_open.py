"""Fresh native W1-072 replay through the authenticated virtual ADDRESS.TXT."""
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_address_open_w1_072.json"


class NativeAddressOpen(unittest.TestCase):
    def test_fresh_runtime_backed_ax6300_address_open(self):
        command = [
            sys.executable, "-B", "tests/test_native_guest_image.py",
            "--capture-crt-startup", "--use-w3-original-environment",
            "--continue-known-services", "--continue-selector-query",
            "--continue-time-query", "--continue-dpmi-linear-success",
            "--serve-w3-address-seed", "--continue-dpmi-ax6300",
            "--continue-dos-ah3d", "--w1-072-native-address-open",
            "--command-tail", "-k 38928",
            "--evidence-name", "native_address_open_w1_072.json",
            "--recovery-dir", "work/recovery/W1-072-20261009",
            "--reuse-compiled-closure",
        ]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0,
                         msg=f"native replay failed ({result.returncode})\n{result.stdout[-12000:]}\n{result.stderr[-12000:]}")
        capture = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(capture.get("task"), "W1-072")
        self.assertTrue(capture.get("fresh_replay"))
        self.assertTrue(capture.get("passed"), capture.get("acceptance_errors"))
        self.assertFalse(capture.get("original_equivalence_claimed"))


if __name__ == "__main__":
    unittest.main()
