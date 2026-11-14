"""Synthetic W1-061 validator tests; no native replay or DOS response is run."""
import copy
import unittest
from datetime import datetime, timezone

from tools.verify_native_ax0501_post_ah25_w1_061 import TARGET_SHA, validate_capture


def synthetic_capture():
    stack = {"trap_va": "000c3cc1", "function": "000c3ca9", "esp": "001a8544", "ebp": "0010b4d0", "valid": "1"}
    stack.update({f"word{i}": f"{0x1000 + 4*i:08x}" for i in range(12)})
    return {
        "execution_mode": "native_recompiled_guest", "native_returncode": 0,
        "target_sha256": TARGET_SHA, "build_id": "exe", "build_artifact": {"sha256": "exe"},
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "replay_options": ["--continue-dos-ah25", "--continue-dos-ah35", "--continue-dpmi-ax0200",
                           "--capture-ax0501-stack", "--capture-crt-startup", "--serve-w3-functional-config",
                           "--serve-w3-address-seed", "--serve-w3-sound-ini", "--reuse-compiled-closure"],
        "crt": {"callback_count": 19}, "argv": {"argc": 3}, "gate": {"local_64": "01", "local_68": "01"},
        "roots": {"setup_game": {"observed": True}, "first_callee_14bf0": {"observed": True}},
        "config_ini": {"opened": True, "bytes_read": 130, "eof_observed": True}, "fixtures": {"comparable": True},
        "build_fingerprints": {"native_harness_source_sha256": "harness"},
        "w1_060_dos_ah25": {"provider_response_event": {"handled": "1"}},
        "w1_061_ax0501_context": {
            "natural_frontier": {"eip": "000c3cc1", "eax": "00000501", "ebx": "00000100",
                                 "ecx": "01001000", "function": "000c3ca9"},
            "stack_snapshot": stack,
            "request_size_bytes": "0x01001000",
            "w1_036_prior_request": {"ebx": "0x00000000", "ecx": "0x00008000"},
            "w1_036_request_size_bytes": "0x00008000", "same_request_registers": False,
            "same_dynamic_invocation": False, "dynamic_caller_identified": False,
            "caller_analysis": {"dynamic_callsite_observed_this_run": False,
                                "upstream_writer": "unknown in synthetic evidence",
                                "static_candidate_chain": [{}, {}, {}]},
            "segment_fault_state": {"pending": "1", "eip": "000d2247", "selector": "8674"},
            "original_contract_path": "evidence/w3_068_dpmi0501_success_contract.json",
            "original_equivalence_claimed": False,
        },
        "recovery": {"manifest": "work/recovery/W1-061/manifest.json", "verification_sha256": "sha"},
    }


class NativeAx0501PostAh25W1061Tests(unittest.TestCase):
    def test_accepts_distinct_live_request_and_stack(self):
        self.assertEqual(validate_capture(synthetic_capture()), [])

    def test_rejects_wrong_frontier(self):
        capture = synthetic_capture()
        capture["w1_061_ax0501_context"]["natural_frontier"]["eip"] = "000c8cdf"
        self.assertTrue(any("frontier" in error for error in validate_capture(capture)))

    def test_rejects_collapsed_request_sizes(self):
        capture = synthetic_capture()
        capture["w1_061_ax0501_context"]["natural_frontier"]["ebx"] = "00000000"
        capture["w1_061_ax0501_context"]["natural_frontier"]["ecx"] = "00008000"
        capture["w1_061_ax0501_context"]["request_size_bytes"] = "0x00008000"
        self.assertTrue(any("different live state" in error for error in validate_capture(capture)))

    def test_rejects_equivalence_claim(self):
        capture = synthetic_capture()
        capture["w1_061_ax0501_context"]["same_dynamic_invocation"] = True
        self.assertTrue(any("same dynamic invocation" in error for error in validate_capture(capture)))

    def test_rejects_missing_stack_words(self):
        capture = synthetic_capture()
        del capture["w1_061_ax0501_context"]["stack_snapshot"]["word11"]
        self.assertTrue(any("12 bounded words" in error for error in validate_capture(capture)))

    def test_rejects_missing_segment_fault_context(self):
        capture = synthetic_capture()
        capture["w1_061_ax0501_context"]["segment_fault_state"]["selector"] = "0000"
        self.assertTrue(any("segment-fault state" in error for error in validate_capture(capture)))

    def test_rejects_unqualified_dynamic_caller(self):
        capture = synthetic_capture()
        capture["w1_061_ax0501_context"]["caller_analysis"]["dynamic_callsite_observed_this_run"] = True
        self.assertTrue(any("dynamic caller observation" in error for error in validate_capture(capture)))


if __name__ == "__main__":
    unittest.main()
