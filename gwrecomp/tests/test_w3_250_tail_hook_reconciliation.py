import unittest

from tools.w3_250_tail_hook_reconciliation import (
    EXPECTED_TAILS,
    callsite_hook_status,
    launch_tail_status,
)


class W3250ReconciliationTests(unittest.TestCase):
    def test_full_dos_exec_tail_chain_is_observed_in_order(self):
        events = [{"event": "dos_execute", "command_tail": value}
                  for value in EXPECTED_TAILS]
        self.assertEqual(launch_tail_status(events), "OBSERVED_IN_ORDER")

    def test_checkpoint_psp_field_does_not_replace_exec_chain_evidence(self):
        events = [
            {"event": "dos_execute", "command_tail": value}
            for value in EXPECTED_TAILS
        ] + [{"event": "target_runtime_checkpoint", "psp_tail_text": ""}]
        self.assertEqual(launch_tail_status(events), "OBSERVED_IN_ORDER")

    def test_missing_dos4gw_tail_is_not_assumed(self):
        events = [{"event": "dos_execute", "command_tail": value}
                  for value in EXPECTED_TAILS[:-2]]
        self.assertEqual(launch_tail_status(events), "NOT_OBSERVED")

    def test_return_site_match_does_not_hide_missing_hook(self):
        result = callsite_hook_status(0x29ACF4, 0x1EB000, 0xAFCF4, False)
        self.assertEqual(result["mapped_return_link"], "0x000AFCF4")
        self.assertEqual(result["mapped_callsite"], "0x000AFCEF")
        self.assertEqual(result["status"], "RETURN_LINK_MATCH_HOOK_NOT_EMITTED_CAUSE_UNKNOWN")

    def test_unknown_mapping_stays_unknown(self):
        result = callsite_hook_status(None, None, 0xAFCF4, False)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["mapped_callsite"])


if __name__ == "__main__":
    unittest.main()
