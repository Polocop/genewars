import unittest

from tools.w3_107_main_transition import CAP, FilterState, accept, measured_rebase, parse_target_events


class MainTransitionTests(unittest.TestCase):
    def test_filter_arms_only_at_natural_main_entry_and_preserves_order(self):
        state = FilterState()
        self.assertFalse(accept(state, 0x94347))
        self.assertTrue(accept(state, 0x93F30))
        self.assertTrue(accept(state, 0x94342))
        self.assertTrue(accept(state, 0x92930))
        self.assertEqual([e["link_va"] for e in state.events], [0x93F30, 0x94342, 0x92930])

    def test_first_hit_deduplicates_and_modes_require_exact_natural_arguments(self):
        state = FilterState()
        accept(state, 0x93F30)
        self.assertFalse(accept(state, 0x9FDCC, eax=0x101, edx=0x100))
        self.assertTrue(accept(state, 0x9FDCC, eax=0x101, edx=0x180))
        self.assertFalse(accept(state, 0x9FDCC, eax=0x101, edx=0x180))

    def test_mode_successors_require_preceding_events(self):
        state = FilterState()
        accept(state, 0x93F30)
        self.assertFalse(accept(state, 0xA3A00))
        accept(state, 0x9FDCC, eax=0x101, edx=0x180)
        self.assertTrue(accept(state, 0xA3A00))
        self.assertTrue(accept(state, 0x9FDF9))

    def test_cap_and_same_run_mapping(self):
        state = FilterState()
        accept(state, 0x93F30)
        state.events = [{} for _ in range(CAP)]
        self.assertFalse(accept(state, 0x94347))
        rows = [{"w3_107_targeted_main_transition": True, "link_va": 0x93F30} for _ in range(CAP + 2)]
        self.assertEqual(len(parse_target_events(rows)), CAP)
        self.assertEqual(measured_rebase({"link_va": 0x93F30, "eip": 0x27EF30}), 0x1EB000)


if __name__ == "__main__":
    unittest.main()
