import unittest

from tools.w3_179_unsmack_dispatch_runner import allowed_callback_links, classify, verify_dispatch_instruction


def sample_row(checkpoint, seq, link, point, *, pointer=0x394920, fill="00"):
    return {
        "checkpoint": checkpoint, "sequence": seq, "link_va": link,
        "eip": 0x00100000 + link, "process_psp": 7811, "data_rebase": 0x001da000,
        "ds_descriptor_valid": True, "w3_177_wscreen_pointer_valid": True,
        "w3_177_wscreen_pointer": pointer, "w3_177_sample_bounds_valid": True,
        "w3_177_sample_valid": True, "w3_177_sample_bytes": 48,
        "w3_177_target_sample_point": point,
        "w3_177_sample_windows": [
            {"offset": offset, "bytes": 16, "hex": fill * 16}
            for offset in (0, 32000, 63984)],
    }


class UnsmackDispatchTests(unittest.TestCase):
    def test_exact_target_indirect_jmp_address_and_bytes(self):
        verified = verify_dispatch_instruction()
        self.assertEqual(verified["entry_link_va"], "0xede94")
        self.assertEqual(verified["indirect_jmp_link_va"], "0xedead")
        self.assertEqual(verified["jmp_bytes"], "ff248d50c91000")
        self.assertEqual(verified["pre_jmp_index_setup"], "mov ecx,eax; and ecx,3")

    def test_derived_index_must_match_eax_low_two_bits(self):
        mismatch = dict(self.first, eax=0x390001)
        result = classify([self.main, mismatch, self.handler, self.reentry], {0xeccf0})
        self.assertEqual(result["classification"], "DISPATCH_TARGET_UNKNOWN")

    def setUp(self):
        self.main = {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 2,
                     "link_va": 0x93f30, "eip": 0x00193f30,
                     "process_psp": 7811, "data_rebase": 0x001da000}
        self.first = sample_row("W3_177_UNSMACK_DISPATCH_FIRST", 10, 0xede94, "first_dispatch")
        self.first.update({"w3_177_table_valid": True, "w3_177_table_index": 2,
                           "w3_177_table_index_source": "eax_low2_verified_at_dispatch_entry",
                           "eax": 0x390002,
                           "w3_177_table_address": 0x001da000 + 0x10c950 + 8,
                           "w3_177_selected_target_valid": True,
                           "w3_177_selected_target_link_va": 0xeccf0,
                           "w3_177_selected_target_runtime": 0x001eccf0})
        self.handler = {"checkpoint": "W3_177_UNSMACK_HANDLER_ENTRY", "sequence": 11,
                        "link_va": 0xeccf0, "eip": 0x001eccf0, "process_psp": 7811}
        self.reentry = sample_row("W3_177_UNSMACK_DISPATCH_REENTRY", 12,
                                  0xede94, "dispatcher_reentry")

    def test_dispatch_target_and_reentry_are_same_run_and_bounded(self):
        result = classify([self.main, self.first, self.handler, self.reentry], {0xeccf0})
        self.assertEqual(result["classification"], "SAMPLED_BYTES_STABLE")
        self.assertEqual(result["sample_bytes_total"], 96)
        self.assertEqual(result["sequence_order"], [10, 11, 12])

    def test_changed_samples_are_reported_only_at_configured_windows(self):
        changed = sample_row("W3_177_UNSMACK_DISPATCH_REENTRY", 12,
                             0xede94, "dispatcher_reentry", fill="7f")
        result = classify([self.main, self.first, self.handler, changed], {0xeccf0})
        self.assertEqual(result["classification"], "SAMPLED_BYTES_CHANGED")
        self.assertEqual(result["sampled_offsets_changed"], [0, 32000, 63984])

    def test_invalid_table_or_target_is_not_promoted(self):
        invalid = dict(self.first, w3_177_table_index=4)
        result = classify([self.main, invalid, self.handler, self.reentry], {0xeccf0})
        self.assertEqual(result["classification"], "DISPATCH_TARGET_UNKNOWN")
        self.assertFalse(result["first_dispatch_valid"])

    def test_handler_must_match_exact_candidate_and_reentry_order(self):
        result = classify([self.main, self.first, self.handler, self.reentry], {0xed030})
        self.assertEqual(result["classification"], "DISPATCH_TARGET_UNKNOWN")
        wrong_order = dict(self.reentry, sequence=9)
        result = classify([self.main, self.first, self.handler, wrong_order], {0xeccf0})
        self.assertEqual(result["classification"], "UNKNOWN")

    def test_missing_reentry_remains_incomplete(self):
        result = classify([self.main, self.first, self.handler], {0xeccf0})
        self.assertEqual(result["classification"], "HANDLER_ENTRY_ONLY")

    def test_exact_target_callback_candidates_are_resolved_from_disassembly(self):
        self.assertIn(0xeccf0, allowed_callback_links())
        self.assertIn(0xeb240, allowed_callback_links())


if __name__ == "__main__":
    unittest.main()
