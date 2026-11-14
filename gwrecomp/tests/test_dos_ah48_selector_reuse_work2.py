import json, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class DosAh48SelectorReuseTests(unittest.TestCase):
 def test_original_byte_cleanup_reuses_freed_selectors_and_continues(self):
  evidence=json.loads((ROOT/'evidence'/'dos_ah48_selector_reuse_work2.json').read_text())
  self.assertEqual(evidence['target_sha256'],'2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f')
  self.assertEqual(evidence['fixture']['sha256'],'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  self.assertEqual(evidence['first_unsupported'],None)
  self.assertEqual(evidence['stop_reason'],'process_terminated')
  self.assertEqual(evidence['process_exit']['code'],0)
  self.assertEqual(evidence['process_exit']['eip'],'0x001afc33')
  aliases=evidence['dos4gw_segment_aliases']
  self.assertGreaterEqual(len(aliases),500)
  self.assertEqual({item['selector'] for item in aliases},{0x4c})
  memory=evidence['dos_memory_state']
  self.assertEqual(memory['dos_ah48_allocations'],{})
  self.assertEqual(memory['profile'],'post_dos4gw_le_entry')
if __name__=='__main__': unittest.main()
