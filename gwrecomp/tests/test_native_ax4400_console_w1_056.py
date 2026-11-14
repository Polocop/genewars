"""Synthetic validator tests; these tests never execute GeneWars or a replay."""
import hashlib
import json
import pathlib
import unittest

from tools.verify_native_ax4400_console_w1_056 import ROOT, validate_capture


def synthetic_capture():
    config = (ROOT / "tests" / "fixtures" / "w3_067_functional_config.ini").read_bytes()
    w2 = json.loads((ROOT / "evidence" / "w2_111_ax4400_stream_metadata.json").read_text(encoding="utf-8"))
    runtime_sha = w2["fingerprints"]["runtime_c_sha256"]
    return {
        "schema": "gwrecomp.native-setup-replay/v1", "execution_mode": "native_recompiled_guest",
        "capture_id": "synthetic-only", "captured_at": "2026-10-09T00:00:00+00:00", "native_returncode": 0,
        "command_tail": "-k 38928",
        "replay_options": ["--serve-w3-functional-config", "--serve-w3-address-seed", "--serve-w3-sound-ini",
                           "--continue-dos-ah3c", "--continue-dos-ax4400", "--continue-dos-ah40",
                           "--continue-dos-ax4400-console", "--capture-crt-startup"],
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "build_id": "build-sha", "build_artifact": {"sha256": "build-sha"},
        "build_fingerprints": {"closure_source_sha256": "a", "routed_closure_object_sha256": "b",
                                "capture_closure_object_sha256": "c", "native_harness_source_sha256": "d"},
        "runtime_fingerprint": {"c_h_sha256": "runtime-aggregate"},
        "crt": {"callback_count": 19, "destinations": [f"0x{i:08x}" for i in range(19)]},
        "argv": {"argc": 3, "values": ["C:\\GENEWARS\\GENEWARS.EXE", "-k", "38928"]},
        "gate": {"local_64": "01", "local_68": "01"},
        "roots": {"setup_game": {"link_va": "0x00094AC0", "observed": True},
                  "first_callee_14bf0": {"link_va": "0x00014BF0", "observed": True}},
        "config_ini": {"path": "C:\\GENEWARS\\CONFIG.INI", "opened": True, "bytes_read": 130,
                       "sha256_read": hashlib.sha256(config).hexdigest(), "eof_observed": True},
        "fixtures": {"comparable": True,
                     "components": {"address_txt_sha256": "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee",
                                    "config_ini_sha256": hashlib.sha256(config).hexdigest()},
                     "native": {"address_txt_sha256": "7b1c5391160e1d95393d3abe980dde978b8a79ecb2814e144ee032d9710ba6ee",
                                "address_provider_open": {"visible": True}}},
        "sound_ini_continuation": {"sha256": "339a99f3fac46182dc52bec753c7122a7fcb1e3cf762e79d6693a9461c8cb9c3", "size": 11},
        "w1_056_ax4400_console": {
            "runtime_matches_w2_111": True, "runtime_c_sha256": runtime_sha,
            "runtime_expected_w2_111_sha256": runtime_sha,
            "provider_setup": "NATIVE_W1_AX4400_CONSOLE_PROVIDER_SETUP handle=1 device_info=80d3 source=W3-091:BX=1:CON",
            "provider_response_events": [{
                "ordinal": "1", "eip": "000c8973", "request_eax": "00004400", "request_ebx": "00000001",
                "configured_device_info": "80d3", "request_edx": "0010a822", "response_eax": "000080d3", "response_edx": "001080d3",
                "cf_out": "0", "handled": "1", "request_ebx": "00000001", "response_ebx": "00000001",
                "request_ecx": "00000000", "response_ecx": "00000000", "request_esi": "00000001", "response_esi": "00000001",
                "request_edi": "00000002", "response_edi": "00000002", "request_ebp": "00000003", "response_ebp": "00000003",
                "request_esp": "00000004", "response_esp": "00000004", "request_cs": "0010", "response_cs": "0010",
                "request_ds": "0014", "response_ds": "0014", "request_es": "0014", "response_es": "0014",
                "request_ss": "0014", "response_ss": "0014", "request_flags_k": "2", "response_flags_k": "2",
                "request_flags_a": "4", "response_flags_a": "4", "request_flags_b": "8", "response_flags_b": "8",
            }],
            "next_frontier": {"trap_va": "000af93a"}, "original_equivalence_claimed": False,
        },
    }


class NativeAx4400ConsoleW1056Tests(unittest.TestCase):
    def test_valid_provider_backed_natural_request(self):
        self.assertEqual(validate_capture(synthetic_capture()), [])

    def test_rejects_mismatched_provider_response(self):
        data = synthetic_capture()
        data["w1_056_ax4400_console"]["provider_response_events"][0]["response_edx"] = "00000082"
        self.assertTrue(any("response differs" in error for error in validate_capture(data)))

    def test_rejects_repeated_service_as_next_frontier(self):
        data = synthetic_capture()
        data["w1_056_ax4400_console"]["next_frontier"]["trap_va"] = "000c8973"
        self.assertTrue(any("next natural frontier" in error for error in validate_capture(data)))

    def test_rejects_runtime_not_matching_w2_handoff(self):
        data = synthetic_capture()
        data["w1_056_ax4400_console"]["runtime_matches_w2_111"] = False
        self.assertTrue(any("Runtime fingerprint" in error for error in validate_capture(data)))


if __name__ == "__main__":
    unittest.main()
