"""Fresh native replay regression for the W1-071 AX=6300 provider."""
import json
import pathlib
import subprocess
import sys
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "native_dpmi_ax6300_provider_w1_071.json"


class NativeAx6300ProviderReplay(unittest.TestCase):
    def test_fresh_native_replay_uses_provider_bridge(self):
        started = time.time()
        command = [
            sys.executable, str(ROOT / "tests" / "test_native_guest_image.py"),
            "--command-tail", "-k 38928",
            "--capture-crt-startup", "--use-w3-original-environment",
            "--continue-known-services", "--continue-selector-query", "--continue-time-query",
            "--continue-dpmi-linear-success", "--continue-dpmi-ax6300",
            "--reuse-compiled-closure", "--evidence-name", EVIDENCE.name,
        ]
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout[-12000:] + result.stderr[-12000:])
        self.assertIn("NATIVE_DPMI0300_AX6300 ordinal=1", result.stdout)
        self.assertTrue(EVIDENCE.is_file())
        capture = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertGreaterEqual(EVIDENCE.stat().st_mtime, started)


if __name__ == "__main__":
    unittest.main()
