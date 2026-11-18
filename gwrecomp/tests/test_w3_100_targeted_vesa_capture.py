import unittest
from tools.w3_100_targeted_vesa_capture import step
from tools.w3_100_capture_runner import parse_trace_jsonl


class TargetedVesaCaptureTests(unittest.TestCase):
    def test_jsonl_reader_preserves_targeted_marker_rows(self):
        raw = (b'{"event":"target_runtime_checkpoint",'
               b'"checkpoint":"VIDEO_VESA_MODE_CALLSITE",'
               b'"w3_100_targeted_vesa":true}\n')
        rows = parse_trace_jsonl(raw)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["w3_100_targeted_vesa"])
        self.assertEqual(rows[0]["checkpoint"], "VIDEO_VESA_MODE_CALLSITE")

    def test_wrong_mode_or_edx_does_not_arm(self):
        for eax, edx in ((0x100, 0x180), (0x101, 0x100), (0x101, 0x181)):
            got = step(0x9FDCC, eax, edx, False, False, 0)
            self.assertEqual(got, (False, False, False, 0))

    def test_earlier_edx_100_call_does_not_arm(self):
        self.assertFalse(step(0x9FDCC, 0x101, 0x100, False, False, 0)[0])

    def test_unarmed_successors_are_filtered(self):
        for link in (0xA3A00, 0x9FDD1, 0x9FDEF, 0x9FDF9):
            self.assertFalse(step(link, 0, 0, False, False, 0)[0])

    def test_exact_target_bypasses_global_cap_and_arms(self):
        # Broad video count may be exhausted; the target-specific counter is local.
        global_video_count = 10
        self.assertEqual(global_video_count, 10)
        admitted, armed, complete, count = step(0x9FDCC, 0x101, 0x180, False, False, 0)
        self.assertTrue(admitted)
        self.assertTrue(armed)
        self.assertFalse(complete)
        self.assertEqual(count, 1)
        admitted, armed, complete, count = step(0xA3A00, 0, 0, armed, complete, count)
        self.assertTrue(admitted)
        self.assertTrue(armed)
        self.assertEqual(count, 2)

    def test_five_record_cap_and_clean_termination(self):
        armed, complete, count = False, False, 0
        for link in (0x9FDCC, 0xA3A00, 0x9FDD1, 0x9FDEF, 0x9FDF9):
            admitted, armed, complete, count = step(
                link, 0x101 if link == 0x9FDCC else 0,
                0x180 if link == 0x9FDCC else 0, armed, complete, count)
            self.assertTrue(admitted)
        self.assertEqual((armed, complete, count), (False, True, 5))
        self.assertEqual(step(0xA3A00, 0, 0, armed, complete, count),
                         (False, False, True, 5))


if __name__ == "__main__":
    unittest.main()
