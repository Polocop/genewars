import json
from pathlib import Path
import unittest

from tools.w3_224_ah4400_ordinal6_capture import pair_ordinal6_context
from tests.test_w3_221_original_ax4400_bx1_alignment import parse_trace

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


def row(sequence, event, **fields):
    return {"sequence": sequence, "event": event, **fields}


class W3224Ordinal6Tests(unittest.TestCase):
    def test_pairs_only_ordinal6_same_registers_and_same_process(self):
        rows = [
            row(10, "target_runtime_checkpoint", checkpoint="AH44_CHKTTY_ISATTY_CALL",
                link_va=0xBA4E4, process_psp=0x1E83, eax=5, ebx=2, edx=0x2E4001),
            row(11, "target_runtime_checkpoint", checkpoint="AH44_ISATTY_ENTRY",
                link_va=0xC896A, expected_return_link_va=0xC8975, process_psp=0x1E83,
                eax=5, ebx=2, edx=0x2E4001,
                stream_object_sample={"field_0d_u8": 0, "field_10_u32": 5}),
            row(12, "target_runtime_checkpoint", checkpoint="DOS_AH44_CALLSITE",
                link_va=0xC8973, process_psp=0x1E83, eax=0x4400, ebx=2,
                ecx=0x4000, edx=2),
            row(13, "original_int21_ah44", ordinal=6, process_psp=0x1E83,
                in_ax=0x4400, in_bx=2, in_cx=0x4000, in_dx=2, out_ax=2,
                out_dx=2, iret_flags=0x246, cf=False),
        ]
        parsed = parse_trace(b"\n".join(json.dumps(item).encode() for item in rows))
        paired = pair_ordinal6_context(parsed)
        self.assertTrue(paired["observed"])
        self.assertTrue(paired["has_same_register_int21_site"])
        self.assertTrue(paired["has_isatty_entry"])
        self.assertTrue(paired["has_chktty_caller"])
        self.assertTrue(paired["has_caller_chain"])
        self.assertTrue(paired["same_process"])
        self.assertEqual(paired["service"]["out_ax"], 2)

    def test_does_not_infer_caller_when_only_service_exists(self):
        parsed = parse_trace(json.dumps(row(1, "original_int21_ah44", ordinal=6,
                                             process_psp=0x1E83, in_ax=0x4400,
                                             in_bx=2, in_cx=0x4000, in_dx=2)).encode())
        paired = pair_ordinal6_context(parsed)
        self.assertTrue(paired["observed"])
        self.assertFalse(paired["has_same_register_int21_site"])
        self.assertFalse(paired["has_isatty_entry"])
        self.assertFalse(paired["has_chktty_caller"])

    def test_does_not_attach_an_earlier_isatty_call_to_ordinal6(self):
        rows = [
            row(10, "target_runtime_checkpoint", checkpoint="AH44_CHKTTY_ISATTY_CALL",
                link_va=0xBA4E4, process_psp=0x1E83),
            row(11, "target_runtime_checkpoint", checkpoint="AH44_ISATTY_ENTRY",
                link_va=0xC896A, process_psp=0x1E83),
            row(12, "target_runtime_checkpoint", checkpoint="DOS_AH44_CALLSITE",
                link_va=0xC8973, process_psp=0x1E83, eax=0x4400, ebx=2,
                ecx=0x4000, edx=2),
            row(13, "original_int21_ah44", ordinal=4, process_psp=0x1E83,
                in_ax=0x4400, in_bx=2, in_cx=0x4000, in_dx=2),
            row(30, "target_runtime_checkpoint", checkpoint="DOS_AH44_CALLSITE",
                link_va=0xC8973, process_psp=0x1E83, eax=0x4400, ebx=2,
                ecx=0x4000, edx=2),
            row(31, "original_int21_ah44", ordinal=6, process_psp=0x1E83,
                in_ax=0x4400, in_bx=2, in_cx=0x4000, in_dx=2),
        ]
        parsed = parse_trace(b"\n".join(json.dumps(item).encode() for item in rows))
        paired = pair_ordinal6_context(parsed)
        self.assertTrue(paired["has_same_register_int21_site"])
        self.assertFalse(paired["has_isatty_entry"])
        self.assertFalse(paired["has_chktty_caller"])
        self.assertFalse(paired["has_caller_chain"])

    def test_cpp_window_is_opt_in_bounded_and_targets_measured_callers(self):
        source = CORE.read_text(encoding="utf-8", errors="replace")
        for marker in (
            'string_from_env("GWRECOMP_W3_224_AH44_CAPTURE_ONLY") == "1"',
            "candidate_link_va >= 0x000ba4d0 && candidate_link_va <= 0x000ba4ec",
            "candidate_link_va >= 0x000c8960 && candidate_link_va <= 0x000c8978",
            "linked_candidate_link_va == 0x000ba4e4",
            "linked_candidate_link_va == 0x000c8973",
            "w3_224_ah44_probe_window) {",
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
