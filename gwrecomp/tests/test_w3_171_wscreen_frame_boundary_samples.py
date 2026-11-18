import unittest

from tools.w3_171_wscreen_frame_boundary_runner import compare_samples, validate_checkpoint


PSP = 7811
CODE = 0x1EB000
DATA = 0x1DA000
OFFSETS = (0, 32000, 63984)


def row(checkpoint, link, point, seq, *, pointer=0x394920, esi=0x394920,
        psp=PSP, code_rebase=CODE, data_rebase=DATA, valid=True, sample="00" * 16):
    return {
        "checkpoint": checkpoint, "link_va": link, "eip": code_rebase + link,
        "process_psp": psp, "sequence": seq, "w3_171_data_rebase": data_rebase,
        "w3_171_sample_point": point, "w3_171_wscreen_global_valid": valid,
        "w3_171_wscreen_pointer_valid": valid, "w3_171_sample_bounds_valid": valid,
        "w3_171_sample_valid": valid, "w3_171_pointer_matches_copy_source": pointer == esi,
        "w3_171_wscreen_pointer": pointer, "w3_171_sample_bytes": 48 if valid else 0,
        "w3_171_sample_windows": ([{"offset": offset, "bytes": 16, "hex": sample}
                                   for offset in OFFSETS] if valid else []),
    }


class WScreenFrameBoundaryTests(unittest.TestCase):
    def test_exact_checkpoints_and_three_windows_validate(self):
        ok, reason = validate_checkpoint(row("W3_148_SMACKDOFRAME_RETURN", 0xAE466,
                                              "smackdoframe_return", 10),
                                         name="W3_148_SMACKDOFRAME_RETURN", link_va=0xAE466,
                                         psp=PSP, code_rebase=CODE, data_rebase=DATA,
                                         point="smackdoframe_return")
        self.assertTrue(ok, reason)

    def test_wrong_process_rebase_and_invalid_bounds_fail_closed(self):
        base = row("W3_148_SMACKDOFRAME_RETURN", 0xAE466, "smackdoframe_return", 10)
        self.assertEqual(validate_checkpoint({**base, "process_psp": 4}, name=base["checkpoint"],
                                             link_va=0xAE466, psp=PSP, code_rebase=CODE,
                                             data_rebase=DATA, point="smackdoframe_return")[1],
                         "process_psp_mismatch")
        self.assertEqual(validate_checkpoint({**base, "w3_171_data_rebase": DATA + 1},
                                             name=base["checkpoint"], link_va=0xAE466,
                                             psp=PSP, code_rebase=CODE, data_rebase=DATA,
                                             point="smackdoframe_return")[1], "data_mapping_mismatch")
        self.assertEqual(validate_checkpoint({**base, "w3_171_sample_bounds_valid": False},
                                             name=base["checkpoint"], link_va=0xAE466,
                                             psp=PSP, code_rebase=CODE, data_rebase=DATA,
                                             point="smackdoframe_return")[1],
                         "descriptor_or_pointer_bounds_invalid")

    def test_copy_pre_must_match_live_esi_source(self):
        bad = row("W3_151_COPY_NONVESA_PRE", 0xA0013, "copy_pre", 20,
                  pointer=0x394920, esi=0x394921)
        result = compare_samples(row("W3_148_SMACKDOFRAME_RETURN", 0xAE466,
                                     "smackdoframe_return", 10), bad,
                                psp=PSP, code_rebase=CODE, data_rebase=DATA)
        self.assertEqual(result["classification"], "UNKNOWN")
        self.assertEqual(result["copy_reason"], "copy_source_pointer_mismatch")

    def test_changed_samples_are_compared_only_in_same_valid_run(self):
        before = row("W3_148_SMACKDOFRAME_RETURN", 0xAE466,
                     "smackdoframe_return", 10, sample="00" * 16)
        after = row("W3_151_COPY_NONVESA_PRE", 0xA0013, "copy_pre", 20,
                    sample="01" * 16)
        result = compare_samples(before, after, psp=PSP, code_rebase=CODE, data_rebase=DATA)
        self.assertEqual(result["classification"], "SAMPLED_BYTES_CHANGED")
        self.assertEqual(result["sampled_offsets_changed"], list(OFFSETS))
        self.assertEqual(result["sample_bytes_total"], 96)

    def test_identical_sampled_windows_stay_bounded_and_unknown_is_conservative(self):
        before = row("W3_148_SMACKDOFRAME_RETURN", 0xAE466,
                     "smackdoframe_return", 10, sample="00" * 16)
        after = row("W3_151_COPY_NONVESA_PRE", 0xA0013, "copy_pre", 20,
                    sample="00" * 16)
        result = compare_samples(before, after, psp=PSP, code_rebase=CODE, data_rebase=DATA)
        self.assertEqual(result["classification"], "SAMPLED_BYTES_STABLE")
        self.assertEqual(result["sample_bytes_total"], 96)
        unknown = compare_samples(None, after, psp=PSP, code_rebase=CODE, data_rebase=DATA)
        self.assertEqual(unknown["classification"], "UNKNOWN")
        self.assertEqual(unknown["sample_bytes_total"], 0)


if __name__ == "__main__":
    unittest.main()
