import json
import unittest
from pathlib import Path

TARGETS = (0x94CE1, 0x94CEE, 0x94CF4, 0x94D9F, 0x94DBC)


def cached_span_targets(*, current_page: int, block_start: int, block_end: int,
                        rebase: int, targets=TARGETS) -> tuple[int, ...]:
    """Synthetic 4 KiB page-offset model; guest state is deliberately immutable."""
    if block_start > block_end:
        return ()
    return tuple(target for target in targets
                 if ((rebase + target) >> 12) == current_page
                 and block_start <= ((rebase + target) & 0xFFF) <= block_end)


def should_single_step(*, target_runtime: int, current_runtime: int, target_seen: bool,
                       cache_hit: bool, target_context: bool) -> bool:
    return (cache_hit and target_context and not target_seen
            and target_runtime > current_runtime)


def append_event_once(mask: int, index: int, event_count: int,
                      event_limit: int = 5) -> tuple[bool, int]:
    bit = 1 << index
    if event_count >= event_limit or mask & bit:
        return False, mask
    return True, mask | bit


class CachedWscreenSpanTests(unittest.TestCase):
    def test_detects_only_exact_targets_inside_same_page_span(self):
        rebase = 0x1EB000
        page = (rebase + 0x94CE1) >> 12
        found = cached_span_targets(current_page=page, block_start=0xCDA,
                                    block_end=0xDBC, rebase=rebase)
        self.assertEqual(found, (0x94CE1, 0x94CEE, 0x94CF4, 0x94D9F, 0x94DBC))

    def test_excludes_targets_outside_block_span(self):
        rebase = 0x1EB000
        page = (rebase + 0x94CE1) >> 12
        found = cached_span_targets(current_page=page, block_start=0xCE2,
                                    block_end=0xD9E, rebase=rebase)
        self.assertNotIn(0x94CE1, found)
        self.assertNotIn(0x94D9F, found)

    def test_excludes_other_page_and_invalid_span(self):
        rebase = 0x1EB000
        page = (rebase + 0x94CE1) >> 12
        self.assertEqual(cached_span_targets(current_page=page + 1,
                                             block_start=0, block_end=4095,
                                             rebase=rebase), ())
        self.assertEqual(cached_span_targets(current_page=page,
                                             block_start=0xD00, block_end=0xC00,
                                             rebase=rebase), ())

    def test_never_targets_unrelated_instruction(self):
        rebase = 0x1EB000
        page = (rebase + 0x94CE1) >> 12
        found = cached_span_targets(current_page=page, block_start=0xCE0,
                                    block_end=0xD9E, rebase=rebase)
        self.assertEqual(set(found), {0x94CE1, 0x94CEE, 0x94CF4})

    def test_cache_hit_miss_target_context_and_seen_disarm(self):
        target, current = 0x27FCEE, 0x27FCDA
        self.assertTrue(should_single_step(target_runtime=target, current_runtime=current,
                                           target_seen=False, cache_hit=True,
                                           target_context=True))
        self.assertFalse(should_single_step(target_runtime=target, current_runtime=current,
                                            target_seen=False, cache_hit=False,
                                            target_context=True))
        self.assertFalse(should_single_step(target_runtime=target, current_runtime=current,
                                            target_seen=False, cache_hit=True,
                                            target_context=False))
        self.assertFalse(should_single_step(target_runtime=target, current_runtime=current,
                                            target_seen=True, cache_hit=True,
                                            target_context=True))

    def test_event_mask_is_deduplicated_and_bounded(self):
        mask = 0
        emitted, mask = append_event_once(mask, 2, event_count=0)
        self.assertTrue(emitted)
        emitted_again, same_mask = append_event_once(mask, 2, event_count=1)
        self.assertFalse(emitted_again)
        self.assertEqual(same_mask, mask)
        self.assertFalse(append_event_once(mask, 3, event_count=5)[0])

    def test_policy_model_does_not_mutate_guest_state(self):
        before = (0x1234, 0x8, 0x202, 0x3000)  # synthetic EIP, EAX, EFLAGS, ESP
        after = before
        self.assertTrue(should_single_step(target_runtime=0x27FDBC,
                                           current_runtime=0x27FDA0,
                                           target_seen=False, cache_hit=True,
                                           target_context=True))
        self.assertEqual(after, before)

    def test_emulator_source_guards_cache_span_and_steps_natural_instruction(self):
        root = Path(__file__).resolve().parents[1]
        core = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        decoder = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86/decoder.h").read_text(encoding="utf-8")
        runner = (root / "tools/w3_167_wscreen_cached_span_runner.py").read_text(encoding="utf-8")
        self.assertIn("target_context && target_main_rebase && block", core)
        self.assertIn("block->page.handler == chandler", core)
        self.assertIn("target_page_offset < block->page.start", core)
        self.assertIn("target_page_offset > block->page.end", core)
        self.assertIn("target_runtime > ip_point && !target_seen", core)
        self.assertIn("W3_167_CACHE_SPAN_HIT", core)
        self.assertIn("sync_dh_fpu_and_run_normal_core()", core)
        self.assertIn("W3_167_DECODER_SPLIT_MATCH", decoder)
        self.assertIn("W3_167_CACHE_SPAN_HIT", runner)
        self.assertIn("W3_167_DECODER_SPLIT_MATCH", runner)
        self.assertIn('str(GUARD), "run"', runner)
        self.assertIn('"--timeout-s", "30"', runner)
        self.assertIn("MAX_TRACE_BYTES", runner)

    def test_gate_checkpoint_candidates_are_not_in_trace_candidate_filter(self):
        root = Path(__file__).resolve().parents[1]
        core = (root / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp").read_text(encoding="utf-8")
        selected_start = core.index("const bool selected_capture_site")
        selected_end = core.index("// Before MAIN's runtime mapping", selected_start)
        selected = core[selected_start:selected_end]
        for candidate in ("w3_160_gate_117662_candidate",
                          "w3_160_gate_1174a4_candidate",
                          "w3_160_gate_fallthrough_candidate",
                          "w3_160_loader_block_candidate"):
            self.assertNotIn(candidate, selected)
        trace_candidate = core.index("const bool trace_candidate =")
        body_start = core.index("if (trace_candidate) {", trace_candidate)
        checkpoint_name = core.index("const char* checkpoint_name = nullptr;", body_start)
        self.assertLess(body_start, checkpoint_name)
        normal_return = core.index("case BR_Normal:", checkpoint_name)
        self.assertIn("goto restart_core;", core[normal_return:normal_return + 500])

    def test_replay_measured_split_match_at_first_gate_but_no_gate_record(self):
        root = Path(__file__).resolve().parents[1]
        result = json.loads((root / "evidence/w3_167_wscreen_cached_span.json").read_text(encoding="utf-8"))
        split = result["decoder_split_events"]
        self.assertEqual(len(split), 1)
        self.assertEqual(split[0]["target_link_va"], 0x94CE1)
        self.assertEqual(split[0]["block_start_runtime"] + split[0]["decoded_prefix_bytes"],
                         split[0]["target_runtime"])
        self.assertEqual(result["cache_span_events"], [])
        self.assertIsNone(result["checkpoints"]["gate_117662"])


if __name__ == "__main__":
    unittest.main()
