from __future__ import annotations

import unittest

from tools.verify_w1_069_ax0300_frame_audit import parse_marker, validate


def marker(**overrides):
    fields = {
        "eip": "000bc765", "eax": "00010300", "ebx": "00000021", "ecx": "00000000",
        "edx": "00000014", "esi": "0011272a", "edi": "001a8ba8", "ebp": "00000000",
        "esp": "001a8ba4", "flag_k": "00001803", "flag_a": "00000000", "flag_b": "00000000",
        "cf": "0", "cs": "000c", "ds": "0014", "es": "0014", "ss": "0014",
        "es_base": "00000000", "frame": "001a8ba8", "frame_valid": "1", "frame_bytes": "00" * 0x32,
        "inner_eax": "00006300", "env_address": "00011000", "env_segment": "00001100",
        "env_offset": "00000000", "env_valid": "1", "env_word": "4f43", "reject_mask": "080",
    }
    fields.update(overrides)
    return "W1_CRT_DPMI0300_CHECK " + " ".join(f"{k}={v}" for k, v in fields.items())


def valid_capture(**marker_overrides):
    raw = marker(**marker_overrides)
    fields = parse_marker(raw)
    return {"task": "W1-069", "task_schema": "gwrecomp.native-ax0300-frame-audit/v1",
            "target_sha256": "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f",
            "native_returncode": 0, "capture_only": True,
            "stdout": raw + "\nW1_CRT_DPMI0300 count=0\nNATIVE_NEXT_TRAP eip=000bc765\n",
            "native_ax0300_frame_audit": {"cpu_frame": {"frame_bytes": "0x" + fields["frame_bytes"]},
                "reject_mask_numeric": int(fields["reject_mask"], 16), "observer_mutated_guest_state": False,
                "result": "harness returned trapped; no DOS response was applied for this request"},
            "original_comparator": {"request_ax": "0x00006300", "response_ds": "0x00001100", "response_si": "0x00000000",
                "same_dynamic_invocation_claimed": False, "same_context_claimed": False, "config_size_bytes": 0,
                "command_tail": "-k"}}


class W1Ax0300AuditTests(unittest.TestCase):
    def test_marker_parses_cpu_and_frame_fields(self):
        fields = parse_marker(marker())
        self.assertEqual(fields["inner_eax"], "00006300")
        self.assertEqual(len(fields["frame_bytes"]), 100)
        self.assertEqual(int(fields["reject_mask"], 16), 0x80)

    def test_marker_rejects_malformed_text(self):
        with self.assertRaises(ValueError):
            parse_marker("NATIVE_NEXT_TRAP eip=000bc765")

    def test_validation_requires_rejected_frontier_not_response(self):
        data = valid_capture(reject_mask="000")
        errors = validate(data)
        self.assertTrue(any("rejected without a DOS response" in error for error in errors))

    def test_validation_rejects_incomplete_frame(self):
        data = valid_capture(frame_valid="0", frame_bytes="")
        errors = validate(data)
        self.assertTrue(any("frame was not captured" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
