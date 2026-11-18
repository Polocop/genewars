import unittest

from tools import w3_181_smackinternal010_progress_runner as base
from tools.w3_192_ecd40_progress_runner import DOSBOX_SHA256, RUN_ID, synthetic_preflight


class Ecd40OriginalReplayTests(unittest.TestCase):
    def test_local_preflight_binds_exact_binary_fixture_and_probe_without_running_guest(self):
        result = synthetic_preflight()
        self.assertEqual(result["binary_sha256"], DOSBOX_SHA256)
        self.assertEqual(result["run_id"], RUN_ID)
        self.assertEqual(result["probe"]["target_link_vas"][-1], "0xecd40")

    def test_original_progress_classifier_accepts_only_ordered_target_checkpoints(self):
        rebase, data_rebase, psp = 0x1EB000, 0x1DA000, 7811
        target = min(base.allowed_callback_links())
        rows = [
            {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 1, "link_va": 0xAF96C,
             "eip": rebase + 0xAF96C, "process_psp": psp, "data_rebase": data_rebase},
            {"checkpoint": "W3_177_UNSMACK_DISPATCH_FIRST", "sequence": 2,
             "link_va": 0xEDE94, "eip": rebase + 0xEDE94, "process_psp": psp,
             "data_rebase": data_rebase, "w3_177_table_valid": True,
             "w3_177_table_index": 0, "eax": 0, "w3_177_table_index_source": "eax_low2_verified_at_dispatch_entry",
             "w3_177_table_address": data_rebase + 0x10C950, "w3_177_selected_target_valid": True,
             "w3_177_selected_target_link_va": target},
            {"checkpoint": "W3_177_UNSMACK_HANDLER_ENTRY", "sequence": 3,
             "link_va": target, "eip": rebase + target, "process_psp": psp},
            {"checkpoint": "W3_181_SMACKINTERNAL010_PROGRESS", "sequence": 4,
             "link_va": 0xECD40, "eip": rebase + 0xECD40, "process_psp": psp,
             "w3_181_progress_checkpoint": True},
        ]
        result = base.classify(rows, base.allowed_callback_links())
        self.assertEqual(result["classification"], "PROGRESS_CAPTURED")
        rows[-1]["sequence"] = 2
        self.assertNotEqual(base.classify(rows, base.allowed_callback_links())["classification"], "PROGRESS_CAPTURED")


if __name__ == "__main__":
    unittest.main()
