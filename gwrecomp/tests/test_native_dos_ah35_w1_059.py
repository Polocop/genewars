"""Synthetic W1-059 capture-validator tests; no guest code or DOS service is run."""
import copy
import hashlib
import unittest
from datetime import datetime, timezone

from tools.verify_native_dos_ah35_w1_059 import ROOT, TARGET_SHA, validate_capture


def synthetic_capture():
    runtime_sha = hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest()
    return {
        "schema": "gwrecomp.native-setup-replay/v1", "execution_mode": "native_recompiled_guest",
        "evidence_level": "DIFF_VERIFIED", "capture_id": "synthetic-only",
        "captured_at": datetime.now(timezone.utc).isoformat(), "native_returncode": 0,
        "target_sha256": TARGET_SHA, "build_id": "exe", "build_artifact": {"sha256": "exe"},
        "replay_options": ["--continue-dpmi-ax0200", "--continue-dos-ah35", "--capture-crt-startup",
                           "--serve-w3-functional-config", "--serve-w3-address-seed", "--serve-w3-sound-ini",
                           "--reuse-compiled-closure"],
        "crt": {"callback_count": 19}, "argv": {"argc": 3},
        "gate": {"local_64": "01", "local_68": "01"},
        "roots": {"setup_game": {"observed": True}, "first_callee_14bf0": {"observed": True}},
        "config_ini": {"opened": True, "bytes_read": 130, "eof_observed": True},
        "fixtures": {"comparable": True},
        "w1_058_dpmi_ax0200": {"provider_response_events": [{"handled": "1"}]},
        "w1_059_dos_ah35": {
            "provider_response_event": {
                "eip": "000c8cdf", "vector": "21", "request_eax": "00003508", "request_ebx": "12340008",
                "provider": "gw_dos_services_callback", "handled": "1", "response_eax": "00003508",
                "response_ebx": "12340000", "response_es": "0000", "cf_out": "0",
            },
            "original_observation": {"response_ebx": "0x00000000", "response_cf": False,
                                     "response_es_measured": False},
            "native_contract_checks": {"response_ax_preserved": True, "response_bx_low_word_zero": True,
                                       "response_cf_clear": True,
                                       "original_es_comparison": "not measured in original evidence"},
            "runtime_source_hashes": {"gw_dos_services_c_sha256": runtime_sha},
            "next_frontier": {"eip": "000c8c8e"}, "original_equivalence_claimed": False,
        },
    }


class NativeDosAh35W1059Tests(unittest.TestCase):
    def test_accepts_measured_runtime_response_with_qualified_es(self):
        self.assertEqual(validate_capture(synthetic_capture()), [])

    def test_rejects_wrong_dynamic_site(self):
        capture = synthetic_capture()
        capture["w1_059_dos_ah35"]["provider_response_event"]["eip"] = "000c8cd2"
        self.assertTrue(any("0xC8CDF" in error for error in validate_capture(capture)))

    def test_rejects_wrong_vector(self):
        capture = synthetic_capture()
        capture["w1_059_dos_ah35"]["provider_response_event"]["request_ebx"] = "12340009"
        self.assertTrue(any("vector 8" in error for error in validate_capture(capture)))

    def test_rejects_carry_set(self):
        capture = synthetic_capture()
        capture["w1_059_dos_ah35"]["native_contract_checks"]["response_cf_clear"] = False
        self.assertTrue(any("clear CF" in error for error in validate_capture(capture)))

    def test_rejects_claim_that_original_es_was_measured(self):
        capture = synthetic_capture()
        capture["w1_059_dos_ah35"]["original_observation"]["response_es_measured"] = True
        self.assertTrue(any("original returned ES" in error for error in validate_capture(capture)))

    def test_rejects_repeated_frontier(self):
        capture = synthetic_capture()
        capture["w1_059_dos_ah35"]["next_frontier"]["eip"] = "000c8cdf"
        self.assertTrue(any("frontier" in error for error in validate_capture(capture)))


if __name__ == "__main__":
    unittest.main()
