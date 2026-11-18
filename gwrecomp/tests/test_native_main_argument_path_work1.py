import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class NativeMainArgumentPathEvidenceTests(unittest.TestCase):
    def test_default_native_entry_has_psp_tail_but_no_initialized_argv(self):
        s=(ROOT/'evidence/native_main_default_args_gdb_work1_20261008.txt').read_text(encoding='utf-8')
        self.assertIn('MAIN_ENTRY eax=0 edx=0',s)
        self.assertRegex(s,r'0x00000000\s+0x00000000')
        self.assertIn('0x09\t0x20\t0x2d\t0x6b\t0x20\t0x33\t0x38\t0x39',s)
        self.assertIn('MAIN_FRAME argc=0 argv=0 local64=0x1 local68=0',s)
        self.assertIn('"\\nType \\\"genewars\\\" to play."',s)

    def test_synthetic_argv_changes_parser_locals_without_touching_them_directly(self):
        s=(ROOT/'evidence/native_main_argv_k_watch_diagnostic_work1_20261008.txt').read_text(encoding='utf-8')
        entry=(ROOT/'evidence/native_main_argv_k_setup_diagnostic_work1_20261008.txt').read_text(encoding='utf-8')
        self.assertIn('MAIN eax=0x2 edx=0x1a7020',entry)
        self.assertIn('"-k 38928"',entry)
        self.assertIn('WATCH_2 esp=0x1a8bc0 cur=0x93f30 l64=0x1 l68=0',s)
        self.assertIn('WATCH_3 esp=0x1a8bc0 cur=0x93f30 l64=0x1 l68=0x1',s)
        self.assertIn('New value = 1',s)

    def test_original_k_handler_and_gate_are_evidence_bound(self):
        d=json.loads((ROOT/'evidence/startup_option_gate_work3.json').read_text(encoding='utf-8'))
        self.assertEqual(d['option_dispatch']['ascii'],'k')
        self.assertEqual(d['option_dispatch']['handler_link_va'],'0x000941d2')
        self.assertEqual(d['gate']['local_64'],'01')
        self.assertEqual(d['gate']['local_68'],'01')
        self.assertIn('setup_game',d['result'])

if __name__=='__main__': unittest.main()

