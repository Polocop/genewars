import json
import unittest

from tools.w3_089_address_writer_trace import (
    MAX_TRACE_BYTES,
    TraceLimitError,
    parse_trace_bytes,
    summarize,
)


def line(sequence, event, **fields):
    return json.dumps({"sequence": sequence, "event": event, **fields}).encode() + b"\n"


class AddressWriterTraceTests(unittest.TestCase):
    def test_filters_and_correlates_natural_writer_chain(self):
        raw = b"".join([
            line(1, "target_runtime_checkpoint", checkpoint="MAIN_ENTRY_CHECKPOINT", link_va=0x93F30),
            line(2, "target_runtime_checkpoint", checkpoint="MAIN_LOCAL_WRITER_CHECKPOINT", link_va=0x93F4C),
            line(3, "target_runtime_checkpoint", checkpoint="ADDRESS_WRITER_ENTRY", link_va=0x27D70),
            line(4, "dos_handle_open", path="C:\\ADDRESS.TXT", entry=5, internal_handle=3),
            line(5, "dos_address_txt_write", path="ADDRESS.TXT", entry=5, requested=4, written=4, sample_hex="74657374"),
            line(6, "dos_handle_close", path="ADDRESS.TXT", entry=5),
            line(7, "target_runtime_checkpoint", checkpoint="MAIN_LOCAL_WRITER_CHECKPOINT", link_va=0x93F56),
            line(8, "dos_handle_open", path="C:\\OTHER.TXT", entry=6),
        ])
        events = parse_trace_bytes(raw)
        result = summarize(events)
        self.assertEqual(result["classification"], "ORIGINAL_WRITER_CHAIN_OBSERVED")
        self.assertTrue(result["dynamic_function_entry_observed"])
        self.assertTrue(result["function_return_to_main_observed"])
        self.assertEqual(len(result["address_writes"]), 1)
        self.assertFalse(any(event.get("path", "").endswith("OTHER.TXT") for event in events))

    def test_suppresses_duplicate_event_sequence(self):
        event = line(4, "dos_address_txt_write", path="ADDRESS.TXT", requested=1, written=1, sample_hex="41")
        parsed = parse_trace_bytes(event + event)
        self.assertEqual(len(parsed), 1)

    def test_unique_output_and_later_main_gate_preserve_entry_pc_limit(self):
        raw = b"".join([
            line(1, "target_runtime_checkpoint", checkpoint="MAIN_ENTRY_CHECKPOINT", link_va=0x93F30),
            line(2, "dos_handle_open", path="C:\\ADDRESS.TXT", entry=5),
            line(3, "dos_address_txt_write", path="ADDRESS.TXT", requested=24, written=24,
                 sample_hex=b"offsetFunction 212d70.\r\n".hex()),
            line(4, "dos_handle_close", path="ADDRESS.TXT", entry=5),
            line(5, "target_runtime_checkpoint", checkpoint="MAIN_GATE_CHECKPOINT", link_va=0x9432F),
        ])
        result = summarize(parse_trace_bytes(raw))
        self.assertEqual(result["classification"], "ORIGINAL_WRITER_EFFECT_AND_MAIN_CONTINUATION_OBSERVED")
        self.assertTrue(result["unique_output_signature_observed"])
        self.assertTrue(result["main_continuation_after_close_observed"])
        self.assertFalse(result["dynamic_function_entry_observed"])
        self.assertTrue(result["direct_entry_pc_missing"])

    def test_rejects_oversized_trace_or_write_sample(self):
        with self.assertRaises(TraceLimitError):
            parse_trace_bytes(b" " * (MAX_TRACE_BYTES + 1))
        raw = line(5, "dos_address_txt_write", path="ADDRESS.TXT", sample_hex="41" * 65)
        with self.assertRaises(TraceLimitError):
            parse_trace_bytes(raw)

    def test_rejects_filtered_event_count_over_cap(self):
        raw = b"".join(line(seq, "dos_address_txt_write", path="ADDRESS.TXT", sample_hex="")
                        for seq in range(1, 514))
        with self.assertRaises(TraceLimitError):
            parse_trace_bytes(raw)

    def test_incomplete_sequence_stays_inconclusive(self):
        parsed = parse_trace_bytes(line(1, "target_runtime_checkpoint", checkpoint="ADDRESS_WRITER_ENTRY", link_va=0x27D70))
        self.assertEqual(summarize(parsed)["classification"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
