import unittest
from tools.video_closure_preflight_work1 import ROOT, TARGETS, build_report

class VideoClosurePreflightTests(unittest.TestCase):
    def test_six_bodies_and_direct_targets_are_present(self):
        r = build_report(ROOT)
        self.assertEqual(set(r['functions']), set(TARGETS))
        for va, f in r['functions'].items():
            with self.subTest(va=va):
                self.assertTrue(f['body_present'])
                self.assertEqual(f['unresolved_direct_targets'], [])
                self.assertEqual(f['unsupported_markers'], [])
                self.assertEqual(f['raw_segment_assignments'], [])

    def test_int10_sites_use_guest_trap_bridge(self):
        r = build_report(ROOT)
        page = r['functions']['0x000A3A5C']['int10_sites']
        self.assertEqual([x['va'] for x in page], ['0x000A3A91', '0x000A3AB7'])
        self.assertTrue(all(x['dispatch_bridge'] and x['unhandled_trap_returns'] for x in page))
        self.assertEqual(r['int10_closure_sites'], ['0x000A3A91', '0x000A3AB7'])

    def test_compiled_object_and_link_artifacts_match_current_source(self):
        r = build_report(ROOT)
        self.assertTrue(r['compile']['passed'])
        self.assertTrue(r['link']['passed'])

if __name__ == '__main__':
    unittest.main()
