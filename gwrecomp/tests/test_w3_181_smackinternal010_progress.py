import unittest
from unittest import mock

from tools.w3_181_smackinternal010_progress_runner import (
    allowed_callback_links,
    classify,
    main,
    verify_dispatch_instruction,
)


class SmackInternalProgressTests(unittest.TestCase):
    def setUp(self):
        self.main = {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 2,
                     "link_va": 0x93F30, "eip": 0x0027EF30,
                     "process_psp": 7811, "data_rebase": 0x001DA000}
        self.first = {
            "checkpoint": "W3_177_UNSMACK_DISPATCH_FIRST", "sequence": 10,
            "link_va": 0xEDE94, "eip": 0x002D8E94, "process_psp": 7811,
            "data_rebase": 0x001DA000, "eax": 0x390000,
            "w3_177_table_valid": True, "w3_177_table_index": 0,
            "w3_177_table_index_source": "eax_low2_verified_at_dispatch_entry",
            "w3_177_table_address": 0x002E6950,
            "w3_177_selected_target_valid": True,
            "w3_177_selected_target_link_va": 0xECCF0,
            "w3_177_selected_target_runtime": 0x002D7CF0,
        }
        self.handler = {"checkpoint": "W3_177_UNSMACK_HANDLER_ENTRY", "sequence": 11,
                        "link_va": 0xECCF0, "eip": 0x002D7CF0, "process_psp": 7811}
        self.progress = {
            "checkpoint": "W3_181_SMACKINTERNAL010_PROGRESS", "sequence": 12,
            "link_va": 0xECD40, "eip": 0x002D7D40, "process_psp": 7811,
            "w3_181_progress_checkpoint": True, "w3_181_globals_valid": True,
            "w3_181_global_10caf0": 0x100, "w3_181_global_10caf4": 0x101,
            "w3_181_global_10caf8": 0x1000,
        }

    def test_dispatch_instruction_and_progress_branch_are_source_verified(self):
        static = verify_dispatch_instruction()
        self.assertEqual(static["indirect_jmp_link_va"], "0xedead")
        self.assertEqual(static["jmp_bytes"], "ff248d50c91000")
        self.assertIn(0xeccf0, allowed_callback_links())

    def test_progress_requires_same_process_mapping_and_order(self):
        result = classify([self.main, self.first, self.handler, self.progress], {0xeccf0})
        self.assertEqual(result["classification"], "PROGRESS_CAPTURED")
        self.assertEqual(result["sequence_order"], [10, 11, 12])
        self.assertEqual(result["raw_globals"]["0x10CAF4"], "0x101")

    def test_no_progress_remains_incomplete(self):
        result = classify([self.main, self.first, self.handler], {0xeccf0})
        self.assertEqual(result["classification"], "HANDLER_ENTRY_ONLY")

    def test_invalid_progress_mapping_is_not_promoted(self):
        bad = dict(self.progress, eip=self.progress["eip"] + 1)
        result = classify([self.main, self.first, self.handler, bad], {0xeccf0})
        self.assertEqual(result["classification"], "UNKNOWN")
        self.assertFalse(result["progress_checkpoint_valid"])

    def test_invalid_global_bounds_do_not_emit_values(self):
        no_globals = dict(self.progress, w3_181_globals_valid=False)
        result = classify([self.main, self.first, self.handler, no_globals], {0xeccf0})
        self.assertEqual(result["classification"], "PROGRESS_CAPTURED")
        self.assertFalse(result["raw_globals_valid"])
        self.assertIsNone(result["raw_globals"])

    def test_wrong_derived_index_is_rejected(self):
        bad = dict(self.first, w3_177_table_index=1)
        result = classify([self.main, bad, self.handler, self.progress], {0xeccf0})
        self.assertEqual(result["classification"], "DISPATCH_TARGET_UNKNOWN")

    def test_help_does_not_enter_preflight_or_launch(self):
        with mock.patch("tools.w3_181_smackinternal010_progress_runner.sys.argv",
                        ["runner.py", "--help"]):
            self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
