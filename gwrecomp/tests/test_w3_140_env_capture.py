import json
import unittest
from pathlib import Path

from tools.w3_140_env_capture import decode_environment_event, parse_jsonl, summarize


class SetenvpCaptureTests(unittest.TestCase):
    def test_bounded_environment_trailer_decode(self):
        block = b"A=B\0C=D\0\0\x03\x00C:\\GENEWARS\\GENEWARS.EXE\0"
        event = {
            "w3_140_env_descriptor_valid": True,
            "w3_140_env_sample_hex": block.hex(),
            "w3_140_env_sample_bytes": len(block),
            "w3_140_env_trailer_path_complete": True,
        }
        result = decode_environment_event(event)
        self.assertEqual(result["environment_strings"], ["A=B", "C=D"])
        self.assertEqual(result["dos_count"], 3)
        self.assertEqual(result["executable_path"], "C:\\GENEWARS\\GENEWARS.EXE")

    def test_invalid_descriptor_and_caps_fail_closed(self):
        self.assertFalse(decode_environment_event({"w3_140_env_descriptor_valid": False})["valid"])
        with self.assertRaises(ValueError):
            decode_environment_event({"w3_140_env_descriptor_valid": True,
                                      "w3_140_env_sample_hex": "00" * 4097,
                                      "w3_140_env_sample_bytes": 4097})
        with self.assertRaises(ValueError):
            parse_jsonl(b"x" * (1_048_576 + 1))

    def test_capture_classification_requires_complete_environment_trailer(self):
        event = {"event": "target_runtime_checkpoint", "checkpoint": "W3_140_SETENVP_DFE04",
                 "link_va": 0xDFE04, "eip": 0x1FBE04, "process_psp": 1, "cs": 0x160,
                 "w3_140_env_descriptor_valid": True,
                 "w3_140_env_sample_hex": b"A=B\0".hex(), "w3_140_env_sample_bytes": 4}
        result = summarize([event])
        self.assertEqual(result["classification"], "ORIGINAL_SETENVP_ENVIRONMENT_PARTIAL")

    def test_only_exact_ordered_target_sites_are_summarized(self):
        base = 0x1EB000
        rows = []
        for i, (name, link) in enumerate((
            ("W3_140_SETENVP_DFE04", 0xDFE04),
            ("W3_140_SETENVP_DFE08", 0xDFE08),
            ("W3_140_SETENVP_DFE0D", 0xDFE0D),
            ("W3_140_SETENVP_DFE12", 0xDFE12),
        ), 1):
            rows.append({"event": "target_runtime_checkpoint", "sequence": i,
                         "checkpoint": name, "link_va": link, "eip": link + base,
                         "process_psp": 10, "cs": 0x160})
        rows.append({"event": "target_runtime_checkpoint", "checkpoint": "W3_140_SETENVP_DFE04",
                     "link_va": 0xDFE05, "eip": 0x1FBE05, "process_psp": 10, "cs": 0x160})
        result = summarize(rows)
        self.assertEqual(result["runtime_rebases"], ["0x001EB000"])
        self.assertTrue(result["same_run_dfe0d_dfe12"])
        self.assertEqual(result["target_event_count"], 4)

    def test_source_gate_is_dynamic_and_bounded(self):
        source = Path(
            "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"
        ).read_text(encoding="utf-8")
        for address in ("0x000dfe04", "0x000dfe08", "0x000dfe0d"):
            self.assertIn(address, source)
        self.assertIn("n < 4096", source)
        self.assertIn("cpu.gdt.GetDescriptor(SegValue(es), w3_140_es_descriptor)", source)
        self.assertNotIn("GWORACLE", source)


if __name__ == "__main__":
    unittest.main()
