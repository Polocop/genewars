"""Synthetic-only validation of W3-195 source wiring and bounded runner."""
import unittest

from tools import w3_192_ecd40_progress_runner as shared
from tools.w3_195_ecd40_armed_runner import (
    DOSBOX_SHA256,
    OPERATION,
    RESULT,
    RUN_ID,
    TRACE,
    inspect_source,
    synthetic_preflight,
)


class Ecd40ArmedReplay195Tests(unittest.TestCase):
    def test_preflight_binds_corrected_source_and_unique_run_paths(self):
        result = synthetic_preflight()
        self.assertEqual(result["binary_sha256"], DOSBOX_SHA256)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["trace_path"], str(TRACE.relative_to(shared.ROOT)))
        self.assertEqual(result["result_path"], str(RESULT.relative_to(shared.ROOT)))
        self.assertTrue(result["probe"]["all_checks_pass"])
        self.assertNotIn("W3_194", result["trace_path"])
        self.assertEqual(OPERATION, shared.OPERATION)

    def test_source_validator_requires_handler_armed_one_shot_result(self):
        source = shared.base.CORE.read_text(encoding="utf-8", errors="replace")
        result = inspect_source(source)
        self.assertTrue(result["all_checks_pass"])
        self.assertTrue(result["checks"]["result_event_requires_armed_handler"])
        self.assertTrue(result["checks"]["event_is_one_shot_before_append"])

    def test_classifier_rejects_pre_handler_target_and_accepts_ordered_target(self):
        rebase, data, psp = 0x1EB000, 0x1DA000, 7811
        target = min(shared.base.allowed_callback_links())
        rows = [
            {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 1,
             "link_va": 0xAF96C, "eip": rebase + 0xAF96C,
             "process_psp": psp, "data_rebase": data},
            {"checkpoint": "W3_177_UNSMACK_DISPATCH_FIRST", "sequence": 2,
             "link_va": 0xEDE94, "eip": rebase + 0xEDE94,
             "process_psp": psp, "data_rebase": data, "w3_177_table_valid": True,
             "w3_177_table_index": 0, "eax": 0,
             "w3_177_table_index_source": "eax_low2_verified_at_dispatch_entry",
             "w3_177_table_address": data + 0x10C950,
             "w3_177_selected_target_valid": True,
             "w3_177_selected_target_link_va": target},
            {"checkpoint": "W3_181_SMACKINTERNAL010_PROGRESS", "sequence": 3,
             "link_va": 0xECD40, "eip": rebase + 0xECD40, "process_psp": psp,
             "w3_181_progress_checkpoint": True},
            {"checkpoint": "W3_177_UNSMACK_HANDLER_ENTRY", "sequence": 4,
             "link_va": target, "eip": rebase + target, "process_psp": psp},
        ]
        early = shared.base.classify(rows, shared.base.allowed_callback_links())
        self.assertNotEqual(early["classification"], "PROGRESS_CAPTURED")
        # A pre-handler cache observation is not evidence of the armed progress
        # event; model its sequence before the exact selected handler entry.
        rows[2]["sequence"] = 3
        pre_handler = shared.base.classify(rows, shared.base.allowed_callback_links())
        self.assertNotEqual(pre_handler["classification"], "PROGRESS_CAPTURED")
        rows[2]["sequence"] = 5
        ordered = shared.base.classify(rows, shared.base.allowed_callback_links())
        self.assertEqual(ordered["classification"], "PROGRESS_CAPTURED")


if __name__ == "__main__":
    unittest.main()
