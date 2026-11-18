import unittest

from tools.w3_113_playintro_dynrec_coverage import (
    PLAYINTRO_HIGH,
    PLAYINTRO_LOW,
    PLAYINTRO_TARGETS,
    build_evidence,
    in_probe_window,
    source_facts,
)


class PlayIntroDynrecCoverageTests(unittest.TestCase):
    def test_live_source_covers_entry_prelude_and_all_targets(self):
        result = build_evidence()
        facts = result["source_facts"]
        self.assertTrue(facts["create_block_limits_selected_candidate"])
        self.assertTrue(facts["normal_core_one_cycle_fallback"])
        self.assertTrue(facts["playintro_entry_selected_site"])
        self.assertTrue(result["updated_window"]["entry_in_one_cycle_window"])
        self.assertTrue(result["updated_window"]["all_targets_covered"])
        self.assertTrue(all(in_probe_window(x, facts) for x in PLAYINTRO_TARGETS))

    def test_half_open_boundary_is_closed_and_bounded(self):
        facts = source_facts(
            "const bool video_probe_window = target_context && "
            "(candidate_link_va >= 0x00092930 && candidate_link_va <= 0x00092add);\n"
            "in_target_function = video_probe_window;\n"
            "CreateCacheBlock(chandler, ip_point, in_target_function ? 1 : 32);"
        )
        self.assertTrue(in_probe_window(PLAYINTRO_LOW, facts))
        self.assertTrue(in_probe_window(PLAYINTRO_HIGH, facts))
        self.assertFalse(in_probe_window(PLAYINTRO_LOW - 1, facts))
        self.assertFalse(in_probe_window(PLAYINTRO_HIGH + 1, facts))


if __name__ == "__main__":
    unittest.main()
