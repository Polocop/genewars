import unittest

from tools.w3_103_vesa_page_filter import step
from tools.w3_100_capture_runner import parse_trace_jsonl


class VesaPageFilterTests(unittest.TestCase):
    def test_wrong_mode_or_edx_does_not_arm(self):
        for eax, edx in ((0x100, 0x180), (0x101, 0x100), (0x101, 0x181)):
            self.assertEqual(step(0x9FDCC, eax, edx, False, False, False, 0),
                             (False, False, False, False, 0))

    def test_page_and_int10_before_trigger_are_filtered(self):
        for link in (0xA3A5C, 0xA3A91, 0xA3A93, 0xA3AB7, 0xA3AB9):
            self.assertFalse(step(link, 0, 0, False, False, False, 0)[0])

    def test_exact_mode_arms_but_only_page_entry_afterwards_is_admitted(self):
        self.assertEqual(step(0x9FDCC, 0x101, 0x180, False, False, False, 0),
                         (False, True, False, False, 0))
        admitted = step(0xA3A5C, 0, 0, True, False, False, 0)
        self.assertEqual(admitted, (True, True, True, False, 1))

    def test_five_event_order_and_clean_termination(self):
        state = (False, False, False, 0)
        _, armed, seen, complete, count = step(0x9FDCC, 0x101, 0x180, *state)
        state = (armed, seen, complete, count)
        for link in (0xA3A5C, 0xA3A91, 0xA3A93, 0xA3AB7, 0xA3AB9):
            admitted, *state = step(link, 0, 0, *state)
            self.assertTrue(admitted)
        self.assertEqual(state, [False, True, True, 5])
        self.assertFalse(step(0xA3A5C, 0, 0, *state)[0])

    def test_jsonl_preserves_target_marker(self):
        raw = b'{"event":"target_runtime_checkpoint","w3_103_targeted_page":true}\n'
        rows = parse_trace_jsonl(raw)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["w3_103_targeted_page"])


if __name__ == "__main__":
    unittest.main()
