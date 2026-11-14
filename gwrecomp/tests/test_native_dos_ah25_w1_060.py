"""Synthetic validator tests; no native guest process or DOS service is run."""
import hashlib
import unittest
from datetime import datetime, timezone

from tools.verify_native_dos_ah25_w1_060 import ROOT, TARGET_SHA, validate_capture


def synthetic_capture():
    runtime_sha = hashlib.sha256((ROOT / "runtime" / "gw_dos_services.c").read_bytes()).hexdigest()
    return {
        "schema": "gwrecomp.native-setup-replay/v1", "execution_mode": "native_recompiled_guest",
        "capture_id": "synthetic-only", "captured_at": datetime.now(timezone.utc).isoformat(),
        "native_returncode": 0, "target_sha256": TARGET_SHA, "build_id": "exe", "build_artifact": {"sha256": "exe"},
        "replay_options": ["--continue-dpmi-ax0200", "--continue-dos-ah35", "--continue-dos-ah25",
                           "--capture-crt-startup", "--serve-w3-functional-config", "--serve-w3-address-seed",
                           "--serve-w3-sound-ini", "--reuse-compiled-closure"],
        "crt": {"callback_count": 19}, "argv": {"argc": 3}, "gate": {"local_64": "01", "local_68": "01"},
        "roots": {"setup_game": {"observed": True}, "first_callee_14bf0": {"observed": True}},
        "config_ini": {"opened": True, "bytes_read": 130, "eof_observed": True}, "fixtures": {"comparable": True},
        "w1_059_dos_ah35": {"native_contract_checks": {"response_bx_low_word_zero": True}},
        "w1_060_dos_ah25": {
            "provider_response_event": {
                "eip": "000c8d0c", "vector": "21", "request_eax": "00002508", "request_ebx": "0000000c",
                "request_edx": "000c8a5e", "provider": "gw_dos_services_callback", "handled": "1", "cf_out": "0",
            },
            "runtime_contract_checks": {"unrelated_registers_preserved": True, "segments_preserved": True,
                                         "non_carry_flags_preserved": True, "carry_clear": True},
            "original_observation": {"link_va": "0x001C8D0C", "request_ds": "0x000C",
                                     "request_edx": "0x001C8A5E", "native_dx_is_not_compared_as_same_address": True},
            "runtime_source_hashes": {"gw_dos_services_c_sha256": runtime_sha},
            "next_frontier": {"eip": "000c8d38"}, "original_equivalence_claimed": False,
        },
        "recovery": {"manifest": "work/recovery/W1-060-test/manifest.json", "verification_sha256": "sha"},
    }


class NativeDosAh25W1060Tests(unittest.TestCase):
    def test_accepts_live_provider_request_and_new_frontier(self):
        self.assertEqual(validate_capture(synthetic_capture()), [])

    def test_rejects_non_natural_callsite(self):
        capture = synthetic_capture()
        capture["w1_060_dos_ah25"]["provider_response_event"]["eip"] = "000c8cdf"
        self.assertTrue(any("0xC8D0C" in error for error in validate_capture(capture)))

    def test_rejects_wrong_vector(self):
        capture = synthetic_capture()
        capture["w1_060_dos_ah25"]["provider_response_event"]["request_eax"] = "00002509"
        self.assertTrue(any("AL is not vector 8" in error for error in validate_capture(capture)))

    def test_rejects_register_mutation(self):
        capture = synthetic_capture()
        capture["w1_060_dos_ah25"]["runtime_contract_checks"]["unrelated_registers_preserved"] = False
        self.assertTrue(any("general register" in error for error in validate_capture(capture)))

    def test_rejects_dx_address_equivalence_assumption(self):
        capture = synthetic_capture()
        capture["w1_060_dos_ah25"]["original_observation"]["native_dx_is_not_compared_as_same_address"] = False
        self.assertTrue(any("same address" in error for error in validate_capture(capture)))

    def test_rejects_missing_frontier(self):
        capture = synthetic_capture()
        capture["w1_060_dos_ah25"]["next_frontier"] = {}
        self.assertTrue(any("frontier" in error for error in validate_capture(capture)))


if __name__ == "__main__":
    unittest.main()
