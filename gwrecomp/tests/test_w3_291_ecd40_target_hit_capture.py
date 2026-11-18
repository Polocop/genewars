import json
import unittest

from tools.w3_291_ecd40_target_hit_capture import analyze, parse_trace


def make_row(event, seq, **kwargs):
    return {"event": event, "sequence": seq, **kwargs}


class W3291TargetHitTests(unittest.TestCase):
    def rows(self):
        rows = [make_row("main_mapping", 1, mapping_matches=True, code_rebase=0x1EB000)]
        transitions = [(0xECD31, 0xECD34), (0xECD34, 0xECD3A), (0xECD3A, 0xECD3C), (0xECD3C, 0xECD3E), (0xECD3E, 0xECD40)]
        rows.extend(make_row("W3_198_ECD40_CONTINUATION_STEP", i + 1, ordinal=i,
                             before_link_va=before, after_link_va=after,
                             before_runtime=0x1EB000 + before, after_runtime=0x1EB000 + after)
                    for i, (before, after) in enumerate(transitions, 1))
        return rows

    def test_target_hit_is_accepted_only_after_final_step_and_mapping(self):
        rows = self.rows()
        rows.append(make_row("w3_291_ecd40_target_hit", 8, process_psp=7811, cs=352,
                             ds=360, es=360, ss=360, eip=0x2D7D40, runtime_linear=0x2D7D40,
                             link_va=0xECD40, code_rebase=0x1EB000, continuation_steps=5,
                             trigger="W3_198_target_hit_branch_before_disarm"))
        result = analyze(rows)
        self.assertTrue(result["target_hit_seen"])
        self.assertEqual(result["target_hit"]["link_va"], 0xECD40)
        self.assertEqual(result["conclusion"], "ECD40_TARGET_HIT_BRANCH_ORIGINAL_OBSERVED")

    def test_absent_target_hit_remains_inconclusive(self):
        result = analyze(self.rows())
        self.assertFalse(result["target_hit_seen"])
        self.assertFalse(result["framebuffer_pixels_verified"])
        self.assertEqual(result["conclusion"], "INCONCLUSIVE_ECD40_TARGET_HIT_NOT_OBSERVED")

    def test_partial_prefix_records_initial_step_mismatch(self):
        rows = [make_row("main_mapping", 1, mapping_matches=True, code_rebase=0x1EB000),
                make_row("target_runtime_checkpoint", 2, checkpoint="W3_177_UNSMACK_HANDLER_ENTRY", link_va=0xECCF0),
                make_row("W3_193_ECD40_STEP_RESULT", 3, before_link_va=0xECD31, after_link_va=0xECD34,
                         target_runtime=0x2D7D40, normal_core_return=0),
                make_row("W3_198_ECD40_CONTINUATION_STOP", 4, reason="initial_step_did_not_reach_measured_successor",
                         link_va=0xECD31, runtime_eip=0x2D7D31, steps=0)]
        result = analyze(rows)
        self.assertFalse(result["continuation_armed_by_initial_step"])
        self.assertFalse(result["target_hit_seen"])
        self.assertEqual(result["continuation_stop"]["steps"], 0)
        self.assertEqual(result["last_emitted_event"]["event"], "W3_198_ECD40_CONTINUATION_STOP")

    def test_wrong_fresh_mapping_fails_closed(self):
        rows = self.rows()
        rows[0]["code_rebase"] = 0x1EA000
        with self.assertRaisesRegex(ValueError, "fresh mapped ECD40"):
            analyze(rows)

    def test_duplicate_one_shot_event_fails(self):
        rows = self.rows()
        event = make_row("w3_291_ecd40_target_hit", 8, runtime_linear=0x2D7D40,
                         link_va=0xECD40, code_rebase=0x1EB000, continuation_steps=5,
                         trigger="W3_198_target_hit_branch_before_disarm")
        rows.extend([event, {**event, "sequence": 9}])
        with self.assertRaisesRegex(ValueError, "duplicated"):
            analyze(rows)

    def test_bounded_jsonl_parser(self):
        raw = ("\n".join(json.dumps(r) for r in self.rows()) + "\n").encode()
        self.assertEqual(len(parse_trace(raw)), len(self.rows()))
        with self.assertRaisesRegex(ValueError, "byte cap"):
            parse_trace(b"x" * (1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
