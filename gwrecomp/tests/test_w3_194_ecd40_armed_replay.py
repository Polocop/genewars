import unittest

from tools import w3_192_ecd40_progress_runner as shared
from tools.w3_194_ecd40_armed_runner import DOSBOX_SHA256, RUN_ID, synthetic_preflight


class Ecd40ArmedReplayTests(unittest.TestCase):
    def test_preflight_uses_new_binary_and_unique_bounded_output(self):
        result = synthetic_preflight()
        self.assertEqual(result["binary_sha256"], DOSBOX_SHA256)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertIn("W3_194_ECD40_ARMED", result["trace_path"])

    def test_classifier_accepts_progress_only_after_handler_entry(self):
        rebase, data, psp = 0x1EB000, 0x1DA000, 7811
        target = min(shared.base.allowed_callback_links())
        rows = [
            {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 1, "link_va": 0xAF96C,
             "eip": rebase + 0xAF96C, "process_psp": psp, "data_rebase": data},
            {"checkpoint": "W3_177_UNSMACK_DISPATCH_FIRST", "sequence": 2,
             "link_va": 0xEDE94, "eip": rebase + 0xEDE94, "process_psp": psp,
             "data_rebase": data, "w3_177_table_valid": True, "w3_177_table_index": 0,
             "eax": 0, "w3_177_table_index_source": "eax_low2_verified_at_dispatch_entry",
             "w3_177_table_address": data + 0x10C950, "w3_177_selected_target_valid": True,
             "w3_177_selected_target_link_va": target},
            {"checkpoint": "W3_177_UNSMACK_HANDLER_ENTRY", "sequence": 3,
             "link_va": target, "eip": rebase + target, "process_psp": psp},
            {"checkpoint": "W3_181_SMACKINTERNAL010_PROGRESS", "sequence": 4,
             "link_va": 0xECD40, "eip": rebase + 0xECD40, "process_psp": psp,
             "w3_181_progress_checkpoint": True},
        ]
        result = shared.base.classify(rows, shared.base.allowed_callback_links())
        self.assertEqual(result["classification"], "PROGRESS_CAPTURED")
        rows[-1]["sequence"] = 1
        self.assertNotEqual(shared.base.classify(rows, shared.base.allowed_callback_links())["classification"], "PROGRESS_CAPTURED")


if __name__ == "__main__":
    unittest.main()
