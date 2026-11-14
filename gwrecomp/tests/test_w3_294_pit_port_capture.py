"""Synthetic-only W3-294 port filter, mapping, branch and size-limit tests."""

import json
import unittest
from pathlib import Path

from tools.w3_294_pit_port_capture import MAX_TRACE_BYTES, analyze, parse_trace

ROOT = Path(__file__).resolve().parents[1]


def row(event, **fields):
    return {"event": event, **fields}


def fixture_rows():
    base = 0x200000
    return [
        row("main_mapping", mapping_matches=True, code_rebase=base, runtime_linear=base + 0x93F30,
            link_va=0x93F30),
        row("w3_269_first_guest_checkpoint_after_present", runtime_linear=base + 0xC427E,
            code_rebase=base, link_va=0xC427E),
        row("W3_294_PIT_PORT_IO", sequence=3, ordinal=1, operation="OUT", port=0x43, width=1,
            value=0, io_completed=True, instruction_runtime=base + 0xC427A, link_va=0xC427A,
            code_rebase=base, instruction_bytes="e643"),
        row("W3_294_PIT_PORT_IO", sequence=4, ordinal=2, operation="IN", port=0x40, width=1,
            value=0x12, io_completed=True, instruction_runtime=base + 0xC427E, link_va=0xC427E,
            code_rebase=base, instruction_bytes="e440"),
        row("W3_294_PIT_PORT_IO", sequence=5, ordinal=3, operation="IN", port=0x40, width=1,
            value=0x34, io_completed=True, instruction_runtime=base + 0xC4282, link_va=0xC4282,
            code_rebase=base, instruction_bytes="e440"),
        row("W3_294_PIT_LOOP_BRANCH", sequence=6, ordinal=1, taken=False,
            instruction_runtime=base + 0xC4293, link_va=0xC4293,
            destination_runtime=base + 0xC4295, destination_link_va=0xC4295),
    ]


class W3294PitCaptureTests(unittest.TestCase):
    def test_source_hooks_are_instruction_scoped_and_value_preserving(self):
        decoder = (ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h").read_text(encoding="utf-8")
        core = (ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        self.assertIn("decode.op_start", decoder)
        self.assertIn("dyn_io_readB_w3_294", decoder)
        self.assertIn("dyn_io_writeB_w3_294", decoder)
        self.assertIn("value = IO_ReadB(port);", decoder)
        self.assertIn("w3_294_record_port_io(0, port, 1, value, instruction_runtime, ex);", decoder)
        self.assertIn("link_va == 0x000c427a", core)
        self.assertIn("link_va == 0x000c427e || link_va == 0x000c4282", core)
        self.assertIn("instruction_runtime - w3_294_main_code_rebase == 0x000c4293", core)
        self.assertNotIn("0x004c", core.lower())

    def test_fresh_mapping_and_natural_port_sequence(self):
        result = analyze(fixture_rows())
        self.assertEqual(result["code_rebase"], 0x200000)
        self.assertEqual(result["conclusion"], "ORIGINAL_PIT_SEQUENCE_OBSERVED")
        self.assertEqual([x["value"] for x in result["port_events"]], [0, 0x12, 0x34])
        self.assertEqual(result["branch_events"][0]["taken"], False)

    def test_rejects_selector_hardcode_or_wrong_runtime_mapping(self):
        rows = fixture_rows()
        rows[2]["code_rebase"] = 0x4C
        with self.assertRaisesRegex(ValueError, "fresh MAIN runtime mapping"):
            analyze(rows)

    def test_rejects_duplicate_or_out_of_scope_port_rows(self):
        rows = fixture_rows()
        duplicate = dict(rows[2])
        duplicate["ordinal"] = 2
        rows.insert(4, duplicate)
        with self.assertRaisesRegex(ValueError, "contiguous prefix"):
            analyze(rows)

    def test_trace_byte_and_row_caps(self):
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            parse_trace(b" " * (MAX_TRACE_BYTES + 1))
        raw = b"{}\n" * 4097
        with self.assertRaisesRegex(ValueError, "4096-row"):
            parse_trace(raw)

    def test_missing_sequence_remains_inconclusive(self):
        rows = fixture_rows()[:2]
        result = analyze(rows)
        self.assertEqual(result["conclusion"], "POST_PRESENT_CHECKPOINT_REACHED_PORT_CALLBACK_NOT_OBSERVED")
        self.assertFalse(result["framebuffer_pixels_verified"])

    def test_missing_mapping_remains_inconclusive(self):
        result = analyze([])
        self.assertEqual(result["conclusion"], "INCONCLUSIVE_MAIN_MAPPING_NOT_OBSERVED")
        self.assertIsNone(result["code_rebase"])


if __name__ == "__main__":
    unittest.main()
