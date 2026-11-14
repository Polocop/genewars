"""Synthetic validator tests; no guest process, replay, or DOS service is run."""
import hashlib
import pathlib
import unittest

from tools.verify_native_dpmi_0200_w1_058 import ROOT, RUNTIME_SHA, TARGET_SHA, ADDRESS_SHA, SOUND_SHA, validate_capture


def synthetic_capture():
    config = (ROOT / "tests" / "fixtures" / "w3_067_functional_config.ini").read_bytes()
    response = {
        "ordinal": "1", "vector": "31", "eip": "000c8cd2",
        "request_eax": "00000200", "request_ebx": "12340008", "request_ecx": "00000000", "request_edx": "000c0014",
        "request_esi": "001a8758", "request_edi": "0010bb5c", "request_ebp": "000009d3", "request_esp": "001a8760",
        "response_eax": "00000200", "response_ebx": "12340008", "response_ecx": "00000000", "response_edx": "000c0000",
        "response_esi": "001a8758", "response_edi": "0010bb5c", "response_ebp": "000009d3", "response_esp": "001a8760",
        "request_flags_k": "00000002", "response_flags_k": "00000002", "request_flags_a": "001a8758", "response_flags_a": "001a8758",
        "request_flags_b": "00000008", "response_flags_b": "00000008", "cf_in": "0", "cf_out": "0", "handled": "1",
        "request_cs": "000c", "response_cs": "000c", "request_ds": "0014", "response_ds": "0014",
        "request_es": "0014", "response_es": "0014", "request_fs": "0000", "response_fs": "0000",
        "request_gs": "0000", "response_gs": "0000", "request_ss": "0014", "response_ss": "0014",
    }
    return {
        "schema": "gwrecomp.native-setup-replay/v1", "execution_mode": "native_recompiled_guest",
        "capture_id": "synthetic-only", "captured_at": "2026-10-09T00:00:00+00:00", "native_returncode": 0,
        "target_sha256": TARGET_SHA, "command_tail": "-k 38928", "build_id": "exe", "build_artifact": {"sha256": "exe"},
        "replay_options": ["--serve-w3-functional-config", "--serve-w3-address-seed", "--serve-w3-sound-ini",
                           "--continue-known-services", "--continue-selector-query", "--continue-time-query",
                           "--continue-dpmi-linear-success", "--continue-dos-ah3d", "--continue-dos-ah3c",
                           "--continue-dos-ax4400", "--continue-dos-ax4400-console", "--continue-dos-ah40",
                           "--continue-dpmi-ax0200", "--capture-crt-startup", "--reuse-compiled-closure"],
        "build_fingerprints": {"closure_source_sha256": "closure", "capture_closure_object_sha256": "object", "native_harness_source_sha256": "harness"},
        "crt": {"callback_count": 19}, "argv": {"argc": 3, "values": ["C:\\GENEWARS\\GW.EXE", "-k", "38928"]},
        "gate": {"local_64": "01", "local_68": "01"},
        "roots": {"setup_game": {"observed": True, "link_va": "0x00094AC0"}, "first_callee_14bf0": {"observed": True}},
        "config_ini": {"opened": True, "path": "C:\\GENEWARS\\CONFIG.INI", "bytes_read": 130,
                       "eof_observed": True, "sha256_read": hashlib.sha256(config).hexdigest()},
        "fixtures": {"comparable": True, "components": {"address_txt_sha256": ADDRESS_SHA},
                     "native": {"address_txt_sha256": ADDRESS_SHA, "address_provider_open": "ADDRESS.TXT bytes=24", "address_provider_initial_visibility": "present"}},
        "sound_ini_continuation": {"size": 11, "sha256": SOUND_SHA},
        "w1_058_dpmi_ax0200": {"provider_response_events": [response], "next_frontier": {"eip": "000c8cdf"},
                                "runtime_source_hashes": dict(RUNTIME_SHA), "original_equivalence_claimed": False},
    }


class NativeDpmi0200W1058Tests(unittest.TestCase):
    def test_valid_original_contract_response(self):
        self.assertEqual(validate_capture(synthetic_capture()), [])

    def test_rejects_nonzero_vector_output(self):
        data = synthetic_capture()
        data["w1_058_dpmi_ax0200"]["provider_response_events"][0]["response_edx"] = "000c0001"
        self.assertTrue(any("CX:DX=0:0" in error for error in validate_capture(data)))

    def test_rejects_carry_set(self):
        data = synthetic_capture()
        data["w1_058_dpmi_ax0200"]["provider_response_events"][0]["cf_out"] = "1"
        self.assertTrue(any("CF clear" in error for error in validate_capture(data)))

    def test_rejects_non_preserved_upper_edx(self):
        data = synthetic_capture()
        data["w1_058_dpmi_ax0200"]["provider_response_events"][0]["response_edx"] = "00000000"
        self.assertTrue(any("upper ECX/EDX" in error for error in validate_capture(data)))

    def test_rejects_repeated_frontier(self):
        data = synthetic_capture()
        data["w1_058_dpmi_ax0200"]["next_frontier"]["eip"] = "000c8cd2"
        self.assertTrue(any("next native frontier" in error for error in validate_capture(data)))


if __name__ == "__main__":
    unittest.main()
