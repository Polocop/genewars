"""Evidence regression for the W1/W2 startup replay reconciliation."""
import json
import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class NativeW1W2ReplayReconciliationWork1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prior_w1 = json.loads((ROOT / "evidence" / "native_setup_config_work1_20261008.json").read_text(encoding="utf-8"))
        cls.prior_w2 = json.loads((ROOT / "evidence" / "native_w3_config_frontier_work2.json").read_text(encoding="utf-8"))
        cls.w2_context = json.loads((ROOT / "evidence" / "native_w2_ax4400_context_work1_20261008.json").read_text(encoding="utf-8"))
        cls.current = json.loads((ROOT / "evidence" / "native_setup_config_reconciled_work1_20261008.json").read_text(encoding="utf-8"))

    def test_common_inputs_and_first_replay_frontier_are_explicit(self):
        self.assertEqual(self.prior_w1["target_sha256"], self.prior_w2["target_sha256"])
        self.assertEqual(self.prior_w1["target_sha256"], self.current["target_sha256"])
        self.assertEqual(self.prior_w1["command_tail"], " -k 38928")
        self.assertEqual(self.prior_w2["command_tail"], self.prior_w1["command_tail"])
        self.assertEqual(self.current["fixture_psp_tail_length"], 9)
        self.assertIn("--continue-dos-ax4400", self.current["replay_options"])
        self.assertIn("--continue-dos-ah40", self.current["replay_options"])
        self.assertEqual(self.prior_w2["w3_functional_config"]["replay_status"], "CONFIG_PATH_NOT_REACHED")
        self.assertEqual(self.prior_w2["w3_functional_config"]["next_frontier"]["trap_va"], "000c8973")
        self.assertIn("ebx_in=00000005", self.prior_w2["stdout"])
        self.assertIn("edx_out=00000005 carry=0 handled=0", self.prior_w2["stdout"])
        self.assertEqual(self.w2_context["replay_options"], [
            "--serve-w3-functional-config", "--continue-known-services", "--continue-selector-query",
            "--continue-time-query", "--continue-dpmi-linear-success", "--continue-dos-ah3d",
            "--continue-dos-ah3c", "--capture-crt-startup", "--reuse-compiled-closure"])
        w2_callbacks = [line for line in self.w2_context["stdout"].splitlines()
                        if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
        w1_callbacks = [line for line in self.current["stdout"].splitlines()
                        if line.startswith("W1_CRT_CALLBACK_DYNAMIC ")]
        self.assertEqual(w2_callbacks, w1_callbacks)
        self.assertEqual(self.w2_context["build_fingerprints"], self.current["build_fingerprints"])

    def test_w2_frontier_is_ax4400_callback_configuration_mismatch(self):
        w1_ax4400 = next(line for line in self.prior_w1["stdout"].splitlines()
                         if line.startswith("W1_CRT_DOS_AX4400_FILE") and "ecx_in=00004000" in line)
        w2_ax4400 = next(line for line in self.prior_w2["stdout"].splitlines()
                         if line.startswith("W1_CRT_DOS_AX4400_FILE"))
        self.assertIn("edx_out=00000042 carry=0 handled=1", w1_ax4400)
        self.assertIn("edx_out=00000005 carry=0 handled=0", w2_ax4400)
        self.assertIn("0x4400u", (ROOT / "runtime" / "gw_dos_services.c").read_text(encoding="utf-8"))
        self.assertIn("gw_dos_file_ioctl_info_configure", (ROOT / "runtime" / "gw_dos_services.h").read_text(encoding="utf-8"))
        runtime_source = (ROOT / "runtime" / "gw_dos_services.c").read_bytes()
        self.assertEqual(hashlib.sha256(runtime_source).hexdigest(),
                         self.current["build_fingerprints"]["dos_services_source_sha256"])

    def test_same_ax4400_instruction_context_before_service_return(self):
        context_lines = {}
        for name, capture in (("w2", self.w2_context), ("w1", self.current)):
            line = next(item for item in capture["stdout"].splitlines()
                        if item.startswith("W1_CRT_AX4400_CONTEXT ordinal=0 "))
            context_lines[name] = dict(token.split("=", 1) for token in line.split()[1:])
        for field in ("caller", "cs", "eip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                      "eflags_k", "eflags_a", "eflags_b", "cf", "ds", "ds_base", "es", "ss",
                      "stack0", "stack1", "stack2"):
            self.assertEqual(context_lines["w1"][field], context_lines["w2"][field], field)
        self.assertEqual(context_lines["w1"]["eip"], "000c8973")
        self.assertEqual(context_lines["w1"]["caller"], "000c896a")
        self.assertEqual(context_lines["w1"]["ebx"], "00000005")
        self.assertIn("--continue-dos-ax4400", self.current["replay_options"])
        self.assertNotIn("--continue-dos-ax4400", self.w2_context["replay_options"])

    def test_current_capture_reaches_setup_and_reads_exact_config_fixture(self):
        stdout = self.current["stdout"]
        cfg = self.current["w3_functional_config"]
        self.assertEqual(cfg["setup_progress"], {
            "crt_callback_count": 19, "argc": "3", "gate": "1/1", "setup_game_link_va": "0x00094AC0"})
        self.assertEqual(cfg["replay_status"], "CONFIG_OPENED_AND_READ")
        self.assertEqual(cfg["bytes_read"], 130)
        self.assertEqual(cfg["sha256_read"], "e7a4728ff07332c2f04320fda202ac5521818a47453e670f9f2842767ef36798")
        self.assertEqual(sum(int(re.search(r"transferred=(\d+)", line).group(1)) for line in cfg["reads"]), 130)
        self.assertEqual(cfg["open"].split()[0], "NATIVE_W3_CONFIG_OPEN")
        self.assertEqual(cfg["close"].split()[0], "NATIVE_W3_CONFIG_CLOSE")
        self.assertIn("W1_SETUP_EVENT ordinal=8 kind=callsite", stdout)
        self.assertIn("W1_SETUP_EVENT ordinal=9 kind=entry", stdout)
        self.assertIn("target=00014bf0", stdout)
        self.assertIn("path=c:\\address.txt", stdout)
        self.assertIn("W1_CRT_DOS_AX4400_FILE eip=000c8973 eax_in=00004400 ebx_in=00000005 ecx_in=00004000 edx_in=00000005 eax_out=00004400 ebx_out=00000005 ecx_out=00004000 edx_out=00000042 carry=0 handled=1", stdout)
        self.assertEqual(cfg["next_frontier"]["trap_va"], "000af93a")
        self.assertEqual(cfg["next_frontier"]["eax"], "00004300")
        self.assertFalse(cfg["original_equivalence_claimed"])

    def test_capture_records_build_fingerprints(self):
        hashes = self.current["build_fingerprints"]
        for field in ("closure_source_sha256", "routed_closure_object_sha256",
                      "capture_closure_object_sha256", "native_harness_source_sha256",
                      "replay_driver_sha256", "dos_services_source_sha256"):
            self.assertRegex(hashes[field], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
