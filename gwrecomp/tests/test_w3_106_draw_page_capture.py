import unittest

from tools.w3_106_draw_page_capture import CAP, FilterState, accept, parse_target_events, validate_mapping


class DrawPageFilterTests(unittest.TestCase):
    def test_requires_natural_order_and_accepts_either_draw_callsite(self):
        state = FilterState()
        self.assertFalse(accept(state, 0xA3A5C))
        path = (0x92710, 0x928A0, 0x834C0, 0x839A2, 0x9FFE0, 0xA0049, 0xA3A5C)
        self.assertTrue(all(accept(state, address) for address in path))
        self.assertEqual(state.stage, len(path))

    def test_deduplicates_by_sequence_stage_and_stops_on_cap(self):
        state = FilterState()
        for address in (0x92710, 0x928A0, 0x834C0, 0x83985):
            self.assertTrue(accept(state, address))
        self.assertFalse(accept(state, 0x839A2))
        state.events.extend({} for _ in range(CAP - len(state.events)))
        self.assertFalse(accept(state, 0x9FFE0))

    def test_maps_each_event_and_refuses_mismatched_rebase(self):
        event = {"link_va": 0x92710, "eip": 0x27D710}
        self.assertEqual(validate_mapping(event), 0x1EB000)
        with self.assertRaisesRegex(ValueError, "mapping"):
            validate_mapping(event, 0x1DA000)

    def test_target_parser_is_bounded(self):
        rows = [{"w3_106_targeted_game_page": True, "i": i} for i in range(CAP + 3)]
        self.assertEqual(len(parse_target_events(rows)), CAP)


if __name__ == "__main__":
    unittest.main()
