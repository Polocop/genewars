import json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class DynamicSetupCallchain(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.d=json.loads((ROOT/'evidence/dynamic_setup_game_callchain_work3.json').read_text())
 def test_target_fixture_and_capture_points(self):
  d=self.d;self.assertEqual(d['target_sha256'],'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f');self.assertTrue(d['cue_unchanged']);self.assertEqual(d['config_sha256'],'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  self.assertEqual([x['label'] for x in d['captures']],['main_to_setup_game_callsite','setup_game_entry','this_global_read'])
 def test_dynamic_return_address_and_cpu_context(self):
  call,entry,read=self.d['captures'];self.assertEqual(call['runtime_eip'],'0x0019433d');self.assertEqual(entry['runtime_eip'],'0x00194ac0')
  self.assertEqual(entry['stack_dwords'][0],'0x00194342');self.assertEqual(entry['segments']['cs'],'0x000c');self.assertIn('gdtr',entry);self.assertIn('segment_descriptors',entry)
  self.assertEqual(read['runtime_eip'],'0x00194b51');self.assertTrue(all(x['stack_bytes_0x80'] for x in (call,entry,read)))
 def test_original_byte_fault_not_native_or_menu(self):
  self.assertEqual(self.d['last_guest_eip'],'0x00194b5a');self.assertEqual(self.d['executed_instruction_count'],7771728);self.assertFalse(self.d['menu_reached']);self.assertIn('original-byte',self.d['command'])
if __name__=='__main__':unittest.main()
