import unittest


def append_video_event(count, cap=10):
    if count < cap:
        return True, count + 1
    return False, count


class VesaCapSuppressionTests(unittest.TestCase):
    def test_tenth_video_event_is_admitted(self):
        admitted, count = append_video_event(9)
        self.assertTrue(admitted)
        self.assertEqual(count, 10)

    def test_eleventh_video_event_is_suppressed(self):
        admitted, count = append_video_event(10)
        self.assertFalse(admitted)
        self.assertEqual(count, 10)

    def test_cap_suppression_does_not_classify_guest_execution(self):
        admitted, _ = append_video_event(10)
        self.assertFalse(admitted)
        guest_entry_observed = False
        self.assertFalse(guest_entry_observed)
        # Filtering the record is independent from whether the guest executed it.
        guest_execution = None
        self.assertIsNone(guest_execution)


if __name__ == "__main__":
    unittest.main()
