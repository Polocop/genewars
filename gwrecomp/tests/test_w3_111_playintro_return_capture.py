import json
import pathlib
import unittest

from tools.w3_111_playintro_return_capture import (
    CAP,
    TARGETS,
    FilterState,
    accept,
    measured_rebase,
    observe_prior,
    parse_jsonl,
    parse_target_events,
    source_coverage,
    summarize,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


class PlayIntroReturnCaptureTests(unittest.TestCase):
    def test_actual_source_covers_every_target_and_probe_window(self):
        coverage = source_coverage(CORE.read_text(encoding="utf-8"))
        self.assertEqual(set(coverage), set(TARGETS))
        self.assertTrue(all(row["observable"] for row in coverage.values()))

    def test_ordered_natural_arm_first_hit_and_completion(self):
        state = FilterState()
        self.assertFalse(accept(state, 0x92983))
        observe_prior(state, 0x93F30)
        observe_prior(state, 0x94342)
        observe_prior(state, 0x9FDF9)
        chain = [0x92983, 0x92996, 0x929A9, 0x92A11, 0x9FEAF,
                 0x962FC, 0x962FF, 0x92A16, 0x92A24, 0x92ADD, 0x929C8, 0x94347]
        for link in chain:
            self.assertTrue(accept(state, link))
        self.assertEqual(len(state.events), CAP)
        self.assertTrue(state.complete)
        self.assertFalse(accept(state, 0x94347))

    def test_absent_and_out_of_order_targets_are_rejected(self):
        state = FilterState()
        observe_prior(state, 0x93F30)
        self.assertFalse(accept(state, 0x92A16))
        self.assertFalse(accept(state, 0x12345))
        self.assertEqual(state.events, [])

    def test_bounded_jsonl_and_rebase_consistency(self):
        base = 0x1EB000
        raw = b"\n".join(json.dumps({
            "w3_109_targeted_playintro_return": True,
            "link_va": link,
            "eip": link + base,
            "checkpoint": f"P_{link:x}",
        }).encode() for link in (0x9FEAF, 0x962FC))
        rows = parse_jsonl(raw)
        events = parse_target_events(rows)
        self.assertEqual(len(events), 2)
        self.assertEqual(measured_rebase(events[0]), base)
        self.assertTrue(summarize(events)["mapping_consistent"])
        self.assertLessEqual(len(raw), 1024)


if __name__ == "__main__":
    unittest.main()
