"""Synthetic bounded-event and recovery checks for W1-080."""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.verify_w1_080_native_ax4400_active_file import validate_capture

ROOT = Path(__file__).resolve().parents[1]


def line(ordinal: int, ecx: str, edx: str) -> str:
    return (
        f"W1_080_AX4400_ACTIVE_FILE ordinal={ordinal} caller=000c896a eip=000c8973 slot=0 "
        "mapping_active=1 owner=gwerr callback_invoked=1 eax_in=00004400 ebx_in=00000002 "
        f"ecx_in={ecx} edx_in={edx} esi_in=001a8bc0 edi_in=00000002 ebp_in=00000002 "
        f"esp_in=001a8b60 flags_k_in=00001803 flags_a_in=00000000 flags_b_in=3c000000 cf_in=0 "
        "cs=000c ds=0014 es=0014 ss=0014 eax_out=00000002 ebx_out=00000002 ecx_out=00000000 "
        "edx_out=00000002 esi_out=001a8bc0 edi_out=00000002 ebp_out=00000002 esp_out=001a8b60 "
        "flags_k_out=00001803 flags_a_out=00000000 flags_b_out=3c000000 cf_out=0 callback_handled=1"
    )


def sample() -> dict:
    return {
        "fresh_replay": True,
        "original_equivalence_claimed": False,
        "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
        "w1_080_ax4400_active_file": {
            "observer_enabled": True,
            "event_cap": 4,
            "event_count": 2,
            "events": [line(0, "00000000", "00004000"), line(1, "0010a83c", "0010a83c")],
            "only_active_virtual_file_handle": True,
            "guest_state_injected": False,
        },
    }


class W1080ActiveFileValidator(unittest.TestCase):
    def test_accepts_bounded_natural_sequence(self):
        self.assertEqual(validate_capture(sample()), [])

    def test_rejects_unbounded_or_unmapped_dispatch(self):
        capture = sample()
        capture["w1_080_ax4400_active_file"]["event_cap"] = 5
        capture["w1_080_ax4400_active_file"]["events"][1] = capture["w1_080_ax4400_active_file"]["events"][1].replace(
            "callback_invoked=1", "callback_invoked=0")
        errors = validate_capture(capture)
        self.assertTrue(any("four-event bound" in item for item in errors))
        self.assertTrue(any("does not match active mapping" in item for item in errors))

    def test_recovery_copies_restore_in_isolated_directory(self):
        path = ROOT / "work" / "recovery" / "W1-080" / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["task"], "W1-080")
        self.assertTrue(manifest["verification"]["all_hashes_match"])
        cache = ROOT / "cache"
        cache.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="w1_080_restore_", dir=cache) as td:
            for record in manifest["files"]:
                backup = Path(record["backup"])
                restored = Path(td) / backup.name
                shutil.copyfile(backup, restored)
                self.assertEqual(hashlib.sha256(restored.read_bytes()).hexdigest(), record["source_sha256"])


if __name__ == "__main__":
    unittest.main()
