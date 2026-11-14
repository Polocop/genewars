import json
import unittest
from pathlib import Path

from tools.w3_127_restart_coverage import (
    CORE, CAP, contract_summary, parse_jsonl, restart_events, source_coverage, summarize,
)


class RestartCoverageTests(unittest.TestCase):
    def test_source_filter_is_narrow_bounded_and_duplicate_suppressed(self):
        result = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertTrue(all(result.values()), result)

    def test_synthetic_event_filter_limits_and_deduplicates(self):
        rows = [{"event": "w3_127_target_instruction_restart", "link_va": link}
                for link in (0x92B71, 0x92B71, 0x92B76, 0x92B7D, 0x91E00, 0x92B82)]
        rows += [{"event": "w3_127_target_instruction_restart", "link_va": 0x92B70}]
        events = restart_events(rows)
        self.assertEqual([event["link_va"] for event in events],
                         [0x92B71, 0x92B76, 0x92B7D, 0x91E00, 0x92B82])
        self.assertTrue(summarize(events)["bounded"])

    def test_summary_pairs_callee_and_return_after_anchor_not_before(self):
        rows = [{"event": "w3_127_target_instruction_restart", "link_va": link}
                for link in (0x91E00, 0x92B71, 0x92B76, 0x91E00, 0x92B82)]
        result = summarize(restart_events(rows))
        self.assertEqual(result["post_anchor_link_vas"],
                         ["0x00092B71", "0x00092B76", "0x00091E00", "0x00092B82"])
        self.assertTrue(result["callee_then_return_observed"])

    def test_byte_cap_and_jsonl(self):
        self.assertEqual(parse_jsonl(b'{"e":1}\n'), [{"e": 1}])
        with self.assertRaises(ValueError):
            parse_jsonl(b"12345", max_bytes=4)

    def test_empty_result_is_explicit(self):
        self.assertEqual(summarize(restart_events([]))["count"], 0)
        self.assertFalse(summarize([])["callee_restart_observed"])

    def test_w3_125_original_gap_remains_separate(self):
        evidence = json.loads(Path("evidence/w3_125_lbmemoryalloc_boundary.json").read_text(encoding="utf-8"))
        self.assertFalse(evidence["capture"]["callee_entry_observed"])
        self.assertIn("0x00092B71", evidence["trace"]["summary"]["link_vas"])

    def test_guarded_restart_capture_records_same_run_entry_return_mapping(self):
        evidence = json.loads(Path("evidence/w3_127_restart_coverage.json").read_text(encoding="utf-8"))
        summary = evidence["trace"]["summary"]
        self.assertEqual(summary["post_anchor_link_vas"],
                         ["0x00092B71", "0x00092B76", "0x00091E00", "0x00092B82"])
        self.assertFalse(summary["callsite_restart_observed"])
        self.assertTrue(summary["callee_then_return_observed"])
        self.assertEqual(summary["same_run_mapping_delta"], 0x1EB000)
        self.assertEqual(summary["same_run_cs"], 0x0160)
        self.assertEqual(summary["entry_to_return_esp_delta"], 4)
        self.assertEqual(summary["callee_entry_registers"]["eax"], 307200)


if __name__ == "__main__":
    unittest.main()
