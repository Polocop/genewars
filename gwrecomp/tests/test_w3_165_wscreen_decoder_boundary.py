import unittest
from pathlib import Path

from tools.w3_165_wscreen_decoder_runner import boundary_decision, decoder_source_contract

ROOT = Path(__file__).resolve().parents[1]
DECODER = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h"


class WScreenDecoderBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = DECODER.read_text(encoding="utf-8")

    def test_exact_target_split_preserves_guest_eip(self):
        split, eip = boundary_decision(psp=0x1234, target_psp=0x1234,
                                       file_complete=True, protected_mode=True,
                                       rebase=0x1EB000, code=0x1EB000 + 0x94CEE,
                                       code_start=0x1EB000 + 0x94CDA)
        self.assertTrue(split)
        self.assertEqual(eip, 0x94CEE)

    def test_non_target_falls_through(self):
        split, eip = boundary_decision(psp=1, target_psp=1, file_complete=True,
                                       protected_mode=True, rebase=0x100000,
                                       code=0x194CDE, code_start=0x194CDA)
        self.assertFalse(split)
        self.assertIsNone(eip)

    def test_other_process_and_incomplete_file_fall_through(self):
        for kwargs in (
            dict(psp=2, target_psp=1, file_complete=True, protected_mode=True),
            dict(psp=1, target_psp=1, file_complete=False, protected_mode=True),
        ):
            split, _ = boundary_decision(**kwargs, rebase=0x100000,
                                         code=0x194CE1, code_start=0x194CDA)
            self.assertFalse(split)

    def test_non_protected_mode_falls_through(self):
        split, _ = boundary_decision(psp=1, target_psp=1, file_complete=True,
                                     protected_mode=False, rebase=0x100000,
                                     code=0x194CE1, code_start=0x194CDA)
        self.assertFalse(split)

    def test_block_entry_does_not_make_empty_block(self):
        split, _ = boundary_decision(psp=1, target_psp=1, file_complete=True,
                                     protected_mode=True, rebase=0x100000,
                                     code=0x194CE1, code_start=0x194CE1)
        self.assertFalse(split)

    def test_predecode_termination_and_state_preservation_contract(self):
        contract = decoder_source_contract(self.source)
        self.assertTrue(all(contract.values()), contract)


if __name__ == "__main__":
    unittest.main()
