import unittest
from tools.w3_297_sound_gate_static import decode, gate_predicate
from pathlib import Path

class SoundGateTests(unittest.TestCase):
    def test_gate_has_three_measured_control_cases(self):
        self.assertIn('before GetSoundDriver_',gate_predicate(1,1))
        self.assertIn('returns zero',gate_predicate(0,0))
        self.assertIn('SMACKSOUNDUSEMSS',gate_predicate(0,1))

    def test_exact_bounded_target_decode(self):
        image=Path('build/dosboxx_oracle/C/GENEWARS/GW.EXE').read_bytes()
        w=decode(image,0xAE308,0xAE368,(0xAE32D,0xAE340))
        self.assertTrue(any(i['mnemonic']=='je' for i in w['instructions']))

    def test_decode_window_rejects_unbounded_input(self):
        with self.assertRaises(ValueError): decode(b'\x90'*1024,0,1024)

if __name__=='__main__':unittest.main()
