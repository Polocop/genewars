import json
import unittest

from tools.w3_091_ah4400_bx1_caller import (
    MAX_TRACE_BYTES,
    TraceLimitError,
    parse_trace,
    summarize,
)


def line(sequence, event, **fields):
    return json.dumps({"sequence": sequence, "event": event, **fields}).encode() + b"\n"


def cpu_entry(sequence=1, ordinal=1, link=0xC8973, **extra):
    fields = {
        "process_psp": 7811,
        "setup_dos_api_callback_ordinal": ordinal,
        "mapping_valid": True,
        "int21_bytes_verified": True,
        "int_instruction_link_va": link,
    }
    fields.update(extra)
    return line(
        sequence,
        "original_cpu_int21_ah44_bx1_entry",
        **fields,
    )


def callback(sequence=2, ordinal=1, **extra):
    return line(
        sequence,
        "setup_dos_api",
        process_psp=7811,
        operation="INT21_AH44",
        in_ax=0x4400,
        in_bx=1,
        ordinal=ordinal,
        out_ax=0x80D3,
        out_dx=0x80D3,
        cf=False,
        entry=1,
        resolved_path="CON",
        cwd="GENEWARS",
        **extra,
    )


class Ah4400Bx1CallerTests(unittest.TestCase):
    def test_pairs_same_callback_ordinal_and_exact_callsite(self):
        events = parse_trace(cpu_entry() + callback())
        result = summarize(events)
        self.assertEqual(result["classification"], "ORIGINAL_CALLER_AND_RESPONSE_CORRELATED")
        self.assertTrue(result["matches_native_link_c8973"])
        self.assertEqual(result["pairs"][0]["response"]["ax"], 0x80D3)
        self.assertFalse(result["pairs"][0]["response"]["cf"])

    def test_different_original_caller_is_not_equated_to_native_site(self):
        result = summarize(parse_trace(cpu_entry(link=0xC8A00) + callback()))
        self.assertEqual(result["classification"], "ORIGINAL_CALLER_AND_RESPONSE_CORRELATED")
        self.assertFalse(result["matches_native_link_c8973"])
        self.assertEqual(result["pairs"][0]["caller_int_instruction_link_va"], 0xC8A00)

    def test_unmatched_ordinal_stays_inconclusive(self):
        result = summarize(parse_trace(cpu_entry(ordinal=8) + callback(ordinal=9)))
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertEqual(result["pairs"], [])

    def test_filters_other_requests_and_suppresses_duplicates(self):
        event = cpu_entry()
        raw = event + event + line(3, "setup_dos_api", operation="INT21_AH44",
                                  in_ax=0x4400, in_bx=2, ordinal=2)
        parsed = parse_trace(raw + callback())
        self.assertEqual(len([e for e in parsed if e["event"] == "original_cpu_int21_ah44_bx1_entry"]), 1)
        self.assertEqual(len([e for e in parsed if e["event"] == "setup_dos_api"]), 1)

    def test_enforces_trace_and_cpu_event_caps(self):
        with self.assertRaises(TraceLimitError):
            parse_trace(b" " * (MAX_TRACE_BYTES + 1))
        raw = b"".join(cpu_entry(sequence=i, ordinal=i) for i in range(1, 10))
        with self.assertRaises(TraceLimitError):
            parse_trace(raw)

    def test_invalid_int_bytes_do_not_claim_a_link_instruction(self):
        result = summarize(parse_trace(cpu_entry(int21_bytes_verified=False) + callback()))
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertEqual(result["pairs"], [])
        self.assertFalse(result["matches_native_link_c8973"])

    def test_same_ordinal_unmapped_dispatch_does_not_duplicate_caller_pair(self):
        realmode = cpu_entry(
            sequence=2,
            link=None,
            cs_base=142528,
            mapping_valid=False,
            int21_bytes_verified=False,
            int_instruction_link_va=None,
        )
        result = summarize(parse_trace(cpu_entry() + realmode + callback(sequence=3)))
        self.assertEqual(len(result["pairs"]), 1)
        self.assertEqual(len(result["protected_caller_entries"]), 1)
        self.assertEqual(len(result["unmapped_dispatch_entries"]), 1)
        self.assertTrue(result["matches_native_link_c8973"])


if __name__ == "__main__":
    unittest.main()
