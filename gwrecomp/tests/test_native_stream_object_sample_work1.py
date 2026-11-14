"""Synthetic structural tests for the W1-055 evidence validator."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.verify_native_stream_object_sample_work1 import validate

ROOT = Path(__file__).resolve().parents[1]


class NativeStreamSampleValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = json.loads((ROOT / "evidence" / "w3_093_ds_edx_sample.json").read_text(encoding="utf-8"))
        self.w2_runtime = json.loads((ROOT / "evidence" / "native_dos_ah43_sound_ini_work2.json").read_text(encoding="utf-8"))
        original_hex = self.original["capture"]["target_sample_event"]["sample_bytes_hex"]
        original_bytes = bytes.fromhex(original_hex)
        native_bytes = bytes((value ^ (1 if index == 7 else 0) for index, value in enumerate(original_bytes)))
        self.event = {"ordinal": "11", "eip": "000c8973", "eax": "00004400", "ebx": "00000001",
                      "edx": "0010a822", "sample_address": "0010a822", "ds_base": "00000000",
                      "sample_valid": "1", "sample_length": "32", "sample_hex": native_bytes.hex()}
        self.data = {
            "schema": "gwrecomp.native-setup-replay/v1", "native_returncode": 0,
            "capture_id": "synthetic-test-capture", "captured_at": "synthetic-test-time",
            "runtime_fingerprint": {"c_h_sha256": self.w2_runtime["implementation"]["c"]["sha256"]},
            "frontier": {"guest_eip": "0x000c8973"},
            "sound_ini_continuation": {
                "dynamic_invocation_equivalence": False, "original_equivalence_claimed": False,
                "setup_game_entered": True, "callee_14bf0_entered": True,
                "crt_callbacks": 19, "argc": 3, "gate": "1/1",
                "runtime_fingerprint": {"gw_dos_services_c_sha256": self.w2_runtime["implementation"]["c"]["sha256"],
                                        "matches_w2_107": True},
                "ax4400_origin": {"requests_bx1": [self.event]},
            },
        }

    def test_accepts_one_bounded_sample_and_preserves_alignment_limit(self) -> None:
        self.assertEqual(validate(self.data, self.original, self.w2_runtime), [])

    def test_rejects_sample_address_mismatch(self) -> None:
        self.event["sample_address"] = "0010a823"
        self.assertIn("sample address differs from effective request EDX", validate(self.data, self.original, self.w2_runtime))

    def test_rejects_causal_claim_from_unaligned_seeds(self) -> None:
        self.data["sound_ini_continuation"]["original_equivalence_claimed"] = True
        self.assertIn("evidence must preserve the unproven invocation-alignment boundary", validate(self.data, self.original, self.w2_runtime))

    def test_rejects_unbounded_native_window(self) -> None:
        self.event["sample_hex"] = "00" * 33
        self.assertIn("native sample does not contain exactly 32 bytes", validate(self.data, self.original, self.w2_runtime))

    def test_rejects_wrong_service_frontier(self) -> None:
        self.event["eip"] = "000c8974"
        self.assertIn("sample was not captured at link VA 0xC8973", validate(self.data, self.original, self.w2_runtime))


if __name__ == "__main__":
    unittest.main()
