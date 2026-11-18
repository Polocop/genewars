"""Verify the W3-authorized CONFIG.INI and its bounded native startup replay."""
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SHA256 = "e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798"


class NativeW3ConfigFixtureWork2(unittest.TestCase):
    def test_fixture_bytes_match_functional_w3_install(self):
        source = ROOT / "build" / "dosboxx_oracle" / "C" / "GENEWARS" / "CONFIG.INI"
        fixture = ROOT / "tests" / "fixtures" / "w3_067_functional_config.ini"
        clone = json.loads((ROOT / "evidence" / "w3_067_functional_clone_20261008.json").read_text(encoding="utf-8"))
        functional = json.loads((ROOT / "evidence" / "w3_067_staging_functional_validation_20261008.json").read_text(encoding="utf-8"))
        config = clone["clone"]["key_files"]["CONFIG.INI"]
        expected = bytes.fromhex(EXPECTED_SHA256)
        self.assertTrue(clone["clone"]["all_source_paths_sizes_hashes_match"])
        self.assertTrue(clone["clone"]["config_ini_unchanged"])
        self.assertEqual(config["bytes"], 130)
        self.assertEqual(config["sha256"].lower(), EXPECTED_SHA256)
        self.assertEqual(functional["runtime"]["guest_errors"]["CONFIG_INI_sha256"].lower(), EXPECTED_SHA256)
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), expected)
        self.assertEqual(fixture.read_bytes(), source.read_bytes())
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).digest(), expected)

    def test_native_startup_reads_exact_config_and_reports_next_frontier(self):
        evidence_name = "native_w3_config_frontier_work2.json"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tests" / "test_native_guest_image.py"),
                "--reuse-compiled-closure",
                "--capture-crt-startup",
                "--continue-known-services",
                "--continue-selector-query",
                "--continue-time-query",
                "--continue-dpmi-linear-success",
                "--serve-w3-functional-config",
                "--command-tail",
                " -k 38928",
                "--evidence-name",
                evidence_name,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=600,
        )
        self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
        capture = json.loads((ROOT / "evidence" / evidence_name).read_text(encoding="utf-8"))
        config = capture["w3_functional_config"]
        self.assertEqual(config["size"], 130)
        self.assertEqual(config["sha256"], EXPECTED_SHA256)
        self.assertIn("NATIVE_W3_CONFIG_PROVIDER_TEST success=1", capture["stdout"])
        self.assertEqual(config["setup_progress"]["crt_callback_count"], 19)
        self.assertEqual(config["setup_progress"]["argc"], "3")
        self.assertFalse(config["original_equivalence_claimed"])
        self.assertIn(config["next_frontier"]["trap_va"], capture["stdout"])
        if config["replay_status"] == "CONFIG_OPENED_AND_READ":
            self.assertEqual(config["bytes_read"], 130)
            self.assertEqual(config["sha256_read"], EXPECTED_SHA256)
            self.assertEqual(config["setup_progress"]["gate"], "1/1")
            self.assertEqual(config["setup_progress"]["setup_game_link_va"], "0x00094AC0")
            self.assertIsNotNone(config["close"])
        else:
            self.assertEqual(config["replay_status"], "CONFIG_PATH_NOT_REACHED")
            self.assertEqual(config["next_frontier"]["trap_va"], "000c8973")


if __name__ == "__main__":
    unittest.main()
