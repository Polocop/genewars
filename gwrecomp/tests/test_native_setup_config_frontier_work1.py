"""Evidence checks for setup_game entry and its first config.ini open."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeSetupConfigFrontierWork1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = json.loads((ROOT / "evidence" / "native_setup_config_work1_20261008.json").read_text(encoding="utf-8"))
        cls.stdout = cls.capture["stdout"]
        cls.fixture = json.loads((ROOT / "evidence" / "w3_authentic_fixture_manifest.json").read_text(encoding="utf-8"))

    def test_setup_callsite_entry_and_first_callee_are_observed(self):
        events = [re.search(r"W1_SETUP_EVENT ordinal=(\d+) kind=(\S+) cs=([0-9a-f]+) eip=([0-9a-f]+) cur_func=([0-9a-f]+).*?esp=([0-9a-f]+).*?stack0=([0-9a-f]+).*?target=([0-9a-f]+)", line).groups()
                  for line in self.stdout.splitlines() if line.startswith("W1_SETUP_EVENT")]
        callsite = next(e for e in events if e[3] == "0009433d")
        entry = next(e for e in events if e[3] == "00094ac0")
        first_callee = next(e for e in events if e[3] == "00014bf0")
        self.assertEqual((callsite[1], callsite[2], callsite[7]), ("callsite", "000c", "00094ac0"))
        self.assertEqual((entry[1], entry[2], entry[4], entry[7]), ("entry", "000c", "00094ac0", "00094ac0"))
        self.assertEqual((entry[6], first_callee[1], first_callee[4]), ("dead0000", "entry", "00014bf0"))
        self.assertIn("W1_MAIN_BLOCK va=0009432f", self.stdout)
        self.assertIn("eip=00098679 cur_func=00098658", self.stdout)
        self.assertIn("target=00098594", self.stdout)

    def test_config_ini_open_request_and_provider_failure_are_exact(self):
        line = next(line for line in self.stdout.splitlines() if line.startswith("W1_CRT_DOS_AH3D_GENERIC") and "pathname=config.ini" in line)
        self.assertIn("eip=000afcc4 cur_func=000afc8d", line)
        self.assertIn("eax_in=00003d00", line)
        self.assertIn("edx_in=0010d547 ds=0014 ds_base=00000000 pathname=config.ini", line)
        self.assertIn("eax_out=00000003", line)
        self.assertIn("carry=1 handled=1", line)
        self.assertIn("W1_SETUP_EVENT ordinal=7 kind=internal_callsite", self.stdout)
        self.assertIn("eip=00098602 cur_func=00098594", self.stdout)
        self.assertIn("W1_CRT_SUMMARY", self.stdout)
        self.assertIn("trap_va=000c8973", self.stdout)
        self.assertRegex(self.stdout, r"eip=00098616 cur_func=00098594 eax=ffffffff")

    def test_w3_config_ini_is_identified_but_not_from_a_valid_game_install(self):
        self.assertEqual(self.fixture["fixture_status"], "INVALID_INCOMPLETE_INSTALL_THREE_ATTEMPTS")
        config = next(item for item in self.fixture["actual_install"]["files"] if item["path"] == "CONFIG.INI")
        self.assertEqual(config["size_bytes"], 142)
        self.assertEqual(config["sha256"], "d3968e17012bc2da547778aa9be7056f2ef9c27c8d99fc23dfade04991af9719")
        self.assertEqual(config["provenance"]["kind"], "created_or_transformed_during_original_installer_run")
        self.assertEqual(self.fixture["actual_install"]["config_install_drive_value"], "C:\\AUTHENTIC\\GENEWARS\\")
        self.assertFalse(self.fixture["validation"]["game_executable_present"])
        self.assertFalse(self.fixture["validation"]["data_text_dat_present"])
        self.assertFalse(self.fixture["oracle_eligibility"]["eligible_for_w3_059"])


if __name__ == "__main__":
    unittest.main()
