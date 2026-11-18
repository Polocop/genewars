import json
import pathlib
import unittest

from tools.w3_111_playintro_return_capture import (
    CAP,
    FilterState,
    accept,
    observe_prior,
    parse_jsonl,
    parse_target_events,
    summarize,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


class PlayIntroTargetOrderTests(unittest.TestCase):
    def test_first_play_smacker_screen_setup_must_follow_first_callsite(self):
        state = FilterState()
        observe_prior(state, 0x93F30)
        observe_prior(state, 0x94342)
        self.assertFalse(accept(state, 0x92A11))
        self.assertTrue(accept(state, 0x92983))
        self.assertTrue(accept(state, 0x92A11))
        self.assertEqual([row["link_va"] for row in state.events], [0x92983, 0x92A11])

    def test_full_static_chain_order_and_first_hit_cap(self):
        state = FilterState()
        observe_prior(state, 0x93F30)
        observe_prior(state, 0x94342)
        chain = [0x92983, 0x92A11]
        for link in chain:
            self.assertTrue(accept(state, link))
        observe_prior(state, 0x9FDF9)
        chain = [0x9FEAF, 0x962FC, 0x962FF, 0x92A16, 0x92A24, 0x92ADD,
                 0x92996, 0x929A9, 0x929C8, 0x94347]
        for link in chain:
            self.assertTrue(accept(state, link))
        self.assertEqual(len(state.events), CAP)
        self.assertTrue(state.complete)
        self.assertFalse(accept(state, 0x94347))
        self.assertFalse(accept(state, 0x92A11))

    def test_instrumenter_prerequisite_matches_static_first_call(self):
        source = CORE.read_text(encoding="utf-8")
        self.assertIn("link_va == 0x00092a11 && (w3_109_seen_mask & (1u << 7))", source)
        self.assertNotIn("link_va == 0x00092a11 && (w3_109_seen_mask & (1u << 9))", source)

    def test_event_parser_is_bounded(self):
        raw = b"\n".join(json.dumps({
            "w3_109_targeted_playintro_return": True,
            "link_va": link,
            "eip": link + 0x1EB000,
        }).encode() for link in (0x92983, 0x92A11))
        events = parse_target_events(parse_jsonl(raw))
        self.assertEqual(len(events), 2)
        self.assertTrue(summarize(events)["mapping_consistent"])
        self.assertLessEqual(len(raw), 1024)


if __name__ == "__main__":
    unittest.main()
