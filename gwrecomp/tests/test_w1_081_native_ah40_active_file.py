"""Synthetic event-validation and recovery checks for W1-081."""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.verify_w1_081_native_ah40_active_file import validate_capture

ROOT = Path(__file__).resolve().parents[1]


def sample() -> dict:
    event = (
        "W1_081_AH40_ACTIVE_FILE ordinal=0 caller=000d214f eip=000d219c slot=0 mapping_active=1 "
        "owner=gwerr callback_invoked=1 eax_in=00004002 ebx_in=00000002 ecx_in=00000014 "
        "edx_in=00201038 esi_in=00000002 edi_in=00000014 ebp_in=00201038 esp_in=001a8b8c "
        "flags_k_in=00000001 flags_a_in=02000000 flags_b_in=80000000 cf_in=0 "
        "cs=000c ds=0014 es=0014 ss=0014 sample_valid=1 sample_length=20 sample_hex=0d0a000102030405060708090a0b0c0d0e0f1011 "
        "eax_out=00000014 ebx_out=00000002 ecx_out=00000014 edx_out=00201038 esi_out=00000002 "
        "edi_out=00000014 ebp_out=00201038 esp_out=001a8b8c flags_k_out=00000001 flags_a_out=02000000 "
        "flags_b_out=80000000 cf_out=0 callback_handled=1"
    )
    return {
        "fresh_replay": True,
        "original_equivalence_claimed": False,
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "w1_081_ah40_active_file": {
            "observer_enabled": True,
            "event_cap": 1,
            "max_sample_bytes": 64,
            "event_count": 1,
            "events": [event],
            "only_active_virtual_file_handle": True,
            "host_write": False,
            "guest_state_injected": False,
        },
    }


class W1081AH40Validator(unittest.TestCase):
    def test_accepts_bounded_virtual_write(self):
        self.assertEqual(validate_capture(sample()), [])

    def test_rejects_oversized_host_or_unmapped_write(self):
        capture = sample()
        observer = capture["w1_081_ah40_active_file"]
        observer["host_write"] = True
        observer["events"][0] = observer["events"][0].replace("mapping_active=1", "mapping_active=0")
        errors = validate_capture(capture)
        self.assertTrue(any("host-write" in item for item in errors))
        self.assertTrue(any("does not match active" in item for item in errors))

    def test_recovery_copies_restore_isolated(self):
        path = ROOT / "work" / "recovery" / "W1-081" / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["task"], "W1-081")
        self.assertTrue(manifest["verification"]["all_hashes_match"])
        cache = ROOT / "cache"
        cache.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="w1_081_restore_", dir=cache) as td:
            for record in manifest["files"]:
                backup = Path(record["backup"])
                restored = Path(td) / backup.name
                shutil.copyfile(backup, restored)
                self.assertEqual(hashlib.sha256(restored.read_bytes()).hexdigest(), record["source_sha256"])


if __name__ == "__main__":
    unittest.main()
