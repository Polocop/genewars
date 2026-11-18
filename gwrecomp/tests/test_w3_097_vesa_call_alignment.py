import unittest


def classify(events):
    video = [e for e in events if e.get("kind") == "video"]
    sites = [e for e in video if e.get("name") == "callsite"]
    entries = [e for e in video if e.get("name") == "entry"]
    after_last = [e for e in video if e.get("seq", -1) > sites[-1]["seq"]] if sites else []
    return {
        "later_entry": any(e.get("link") == 0xA3A00 for e in after_last),
        "last_callsite_is_trace_end": bool(sites and sites[-1]["seq"] == max(e["seq"] for e in events)),
        "returned": None if not after_last else any(e.get("name") == "return" for e in after_last),
        "first_entry_exists": any(e.get("link") == 0xA3A00 for e in entries),
    }


class VesaCallAlignmentTests(unittest.TestCase):
    def test_earlier_entry_does_not_imply_later_call_returned(self):
        events = [
            {"seq": 10, "kind": "video", "name": "callsite", "edx": 0x100},
            {"seq": 11, "kind": "video", "name": "entry", "link": 0xA3A00},
            {"seq": 12, "kind": "video", "name": "assign_after"},
            {"seq": 20, "kind": "video", "name": "callsite", "edx": 0x180},
        ]
        got = classify(events)
        self.assertTrue(got["first_entry_exists"])
        self.assertFalse(got["later_entry"])
        self.assertTrue(got["last_callsite_is_trace_end"])
        self.assertIsNone(got["returned"])

    def test_later_entry_is_only_proved_by_later_checkpoint(self):
        events = [
            {"seq": 20, "kind": "video", "name": "callsite", "edx": 0x180},
            {"seq": 21, "kind": "video", "name": "entry", "link": 0xA3A00},
        ]
        self.assertTrue(classify(events)["later_entry"])


if __name__ == "__main__":
    unittest.main()
