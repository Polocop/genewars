"""Synthetic validator and recovery checks for W1-079 evidence."""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.verify_w1_079_native_ax4400_created_file import validate_capture

ROOT = Path(__file__).resolve().parents[1]


def sample() -> dict:
    line = (
        "W1_079_AX4400_HANDLE2 ordinal=0 caller=000c896a eip=000c8973 slot=0 "
        "mapping_active=1 owner=gwerr callback_invoked=1 eax_in=00004400 ebx_in=00000002 "
        "ecx_in=00000000 edx_in=00004000 esi_in=001a8bc0 edi_in=00000002 ebp_in=00000002 "
        "esp_in=001a8b60 flags_k_in=00001803 flags_a_in=00000000 flags_b_in=3c000000 cf_in=0 "
        "cs=000c ds=0014 es=0014 ss=0014 eax_out=00000002 ebx_out=00000002 ecx_out=00000000 "
        "edx_out=00000002 esi_out=001a8bc0 edi_out=00000002 ebp_out=00000002 esp_out=001a8b60 "
        "flags_k_out=00001803 flags_a_out=00000000 flags_b_out=3c000000 cf_out=0 callback_handled=1"
    )
    return {
        "fresh_replay": True,
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "original_equivalence_claimed": False,
        "capture_id": "synthetic-test",
        "evidence_level": "NATIVE_REACHED",
        "w1_079_ax4400_handle2": {
            "observer_enabled": True,
            "event_cap": 1,
            "event_count": 1,
            "events": [line],
            "only_active_virtual_file_handle": True,
            "guest_state_injected": False,
        },
    }


class W1079Handle2Validator(unittest.TestCase):
    def test_valid_measured_callback_record_shape(self):
        self.assertEqual(validate_capture(sample()), [])

    def test_rejects_wrong_dynamic_service_or_inactive_callback_mapping(self):
        capture = sample()
        capture["w1_079_ax4400_handle2"]["events"][0] = capture["w1_079_ax4400_handle2"]["events"][0].replace(
            "ebx_in=00000002", "ebx_in=00000001").replace("mapping_active=1", "mapping_active=0")
        errors = validate_capture(capture)
        self.assertTrue(any("not the measured" in item for item in errors))
        self.assertTrue(any("does not match" in item for item in errors))

    def test_recovery_copy_and_isolated_restore_hashes(self):
        manifest_path = ROOT / "work" / "recovery" / "W1-079" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["task"], "W1-079")
        self.assertTrue(manifest["verification"]["all_hashes_match"])
        cache = ROOT / "cache"
        cache.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="w1_079_restore_", dir=cache) as tmp:
            destination = Path(tmp)
            for record in manifest["files"]:
                backup = Path(record["backup"])
                restored = destination / backup.name
                shutil.copyfile(backup, restored)
                digest = hashlib.sha256(restored.read_bytes()).hexdigest()
                self.assertEqual(digest, record["source_sha256"])


if __name__ == "__main__":
    unittest.main()
