"""Fresh native W1-074 replay through authenticated ADDRESS.TXT metadata."""
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_address_ax4400_w1_074.json"


class NativeAddressAx4400(unittest.TestCase):
    def test_fresh_replay_routes_active_address_handle_through_runtime(self):
        command = [
            sys.executable, "-B", "tests/test_native_guest_image.py",
            "--capture-crt-startup", "--use-w3-original-environment",
            "--continue-known-services", "--continue-selector-query",
            "--continue-time-query", "--continue-dpmi-linear-success",
            "--serve-w3-address-seed", "--continue-dpmi-ax6300",
            "--continue-dos-ah3d", "--w1-074-native-address-ax4400",
            "--command-tail", "-k 38928",
            "--evidence-name", "native_address_ax4400_w1_074.json",
            "--recovery-dir", "work/recovery/W1-074-20261009",
            "--reuse-compiled-closure",
        ]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0,
                         msg=f"native replay failed ({result.returncode})\n{result.stdout[-12000:]}\n{result.stderr[-12000:]}")
        capture = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(capture.get("task"), "W1-074")
        self.assertTrue(capture.get("fresh_replay"))
        self.assertTrue(capture.get("passed"), capture.get("acceptance_errors"))
        self.assertFalse(capture.get("original_equivalence_claimed"))


if __name__ == "__main__":
    unittest.main()
