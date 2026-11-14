"""Synthetic-only validation for W3-196; it never starts Oracle or DOSBox."""
import unittest

from tools import w3_192_ecd40_progress_runner as shared
from tools.w3_196_ecd40_armed_runner import (
    DOSBOX_SHA256, OPERATION, RESULT, RUN_ID, TRACE, inspect_source, synthetic_preflight,
)


class Ecd40ArmedReplay196Tests(unittest.TestCase):
    def test_preflight_binds_exact_binary_fixture_config_and_unique_outputs(self):
        result = synthetic_preflight()
        self.assertEqual(result["binary_sha256"], DOSBOX_SHA256)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["trace_path"], str(TRACE.relative_to(shared.ROOT)))
        self.assertEqual(result["result_path"], str(RESULT.relative_to(shared.ROOT)))
        self.assertTrue(result["probe"]["all_checks_pass"])
        self.assertEqual(OPERATION, shared.OPERATION)

    def test_source_invariants_keep_event_after_handler_and_one_shot(self):
        result = inspect_source(shared.base.CORE.read_text(encoding="utf-8", errors="replace"))
        self.assertTrue(result["all_checks_pass"])
        self.assertTrue(result["checks"]["result_event_requires_armed_handler"])
        self.assertTrue(result["checks"]["event_is_one_shot_before_append"])
        self.assertTrue(result["checks"]["event_is_after_normal_core_step"])

    def test_classifier_rejects_pre_handler_event_then_accepts_post_handler(self):
        rebase, data, psp = 0x1EB000, 0x1DA000, 7811
        target = min(shared.base.allowed_callback_links())
        rows = [
            {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 1, "link_va": 0xAF96C,
             "eip": rebase + 0xAF96C, "process_psp": psp, "data_rebase": data},
            {"checkpoint": "W3_177_UNSMACK_DISPATCH_FIRST", "sequence": 2,
             "link_va": 0xEDE94, "eip": rebase + 0xEDE94, "process_psp": psp,
             "data_rebase": data, "w3_177_table_valid": True, "w3_177_table_index": 0,
             "eax": 0, "w3_177_table_index_source": "eax_low2_verified_at_dispatch_entry",
             "w3_177_table_address": data + 0x10C950,
             "w3_177_selected_target_valid": True,
             "w3_177_selected_target_link_va": target},
            {"checkpoint": "W3_177_UNSMACK_HANDLER_ENTRY", "sequence": 3,
             "link_va": target, "eip": rebase + target, "process_psp": psp},
            {"checkpoint": "W3_181_SMACKINTERNAL010_PROGRESS", "sequence": 2,
             "link_va": 0xECD40, "eip": rebase + 0xECD40, "process_psp": psp,
             "w3_181_progress_checkpoint": True},
        ]
        classifier = shared.base.classify
        allowed = shared.base.allowed_callback_links()
        self.assertNotEqual(classifier(rows, allowed)["classification"], "PROGRESS_CAPTURED")
        rows[3]["sequence"] = 4
        self.assertEqual(classifier(rows, allowed)["classification"], "PROGRESS_CAPTURED")


if __name__ == "__main__":
    unittest.main()
