import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.w3_283_replay_timing_audit import (
    branch_sequence_consistency,
    causality_from_correlation,
    extract_log_events,
    read_trace,
)


class ReplayTimingAuditTests(unittest.TestCase):
    def test_sequence_consistency_uses_jsonl_sequence_values(self):
        events = [
            {"sequence": 396, "event": "entry"},
            {"sequence": 397, "event": "load"},
            {"sequence": 398, "event": "test"},
            {"sequence": 399, "event": "target"},
        ]
        self.assertTrue(branch_sequence_consistency(events, {
            "entry": 396, "load": 397, "test": 398, "target": 399,
        }))
        self.assertFalse(branch_sequence_consistency(events, {
            "entry": 395, "load": 396, "test": 397, "target": 398,
        }))

    def test_trace_hash_and_row_count_are_checked(self):
        payload = b'{"sequence":1,"event":"checkpoint"}\n'
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "trace.jsonl"
            p.write_bytes(payload)
            rows, meta = read_trace(p, hashlib.sha256(payload).hexdigest())
            self.assertEqual(len(rows), 1)
            self.assertEqual(meta["rows"], 1)
            with self.assertRaises(ValueError):
                read_trace(p, "0" * 64)

    def test_log_timestamps_are_relative_to_initial_display(self):
        text = (
            "2026-10-10 00:00:00.000 | DISPLAY: Using windowed mode\n"
            "2026-10-10 00:00:24.936 | DISPLAY: VESA 640x480 mode\n"
            "2026-10-10 00:00:49.951 | ENVELOPE: SB done after 10 frames\n"
        )
        result = extract_log_events(text)
        self.assertEqual(result["vesa_modes"][0]["seconds_after_initial_display"], 24.936)
        self.assertEqual(result["sound_blaster_envelope_done"][0]["seconds_after_initial_display"], 49.951)

    def test_timing_correlation_does_not_assign_cause(self):
        self.assertEqual(causality_from_correlation(24.936, 35.738, 75.379, 115.713), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
