import unittest

from tools.w3_110_hook_coverage_audit import build_evidence, extract_source_coverage, in_range


class HookCoverageAuditTests(unittest.TestCase):
    def test_source_derived_capture_and_probe_windows(self):
        source = """
        const bool selected_capture_site = target_main_rebase &&
            (candidate_link_va == 0x00094347 || candidate_link_va == 0x0009fdf9);
        // Before MAIN's runtime mapping is known
        const bool possible_main_entry = false;
        const bool trace_candidate = target_context && (selected_capture_site || possible_main_entry);
        const bool video_probe_window = target_context &&
            (candidate_link_va == 0x00092930 ||
             (candidate_link_va >= 0x00094342 && candidate_link_va <= 0x0009434c) ||
             (candidate_link_va >= 0x0009fd40 && candidate_link_va <= 0x0009fdf9));
        in_target_function = trace_candidate || video_probe_window;
        if (trace_candidate) {
          const char* checkpoint_name = nullptr;
          uint32_t w3_109_target_bit = 0;
        }
        """
        coverage = extract_source_coverage(source)
        self.assertIn(0x94347, coverage["selected_capture_sites"])
        self.assertTrue(in_range(0x9FDF9, coverage["video_probe_ranges"]))
        self.assertFalse(in_range(0x9FEAF, coverage["video_probe_ranges"]))
        self.assertTrue(coverage["checkpoint_code_is_inside_trace_candidate_gate"])

    def test_real_source_explains_w3_109_suppression(self):
        evidence = build_evidence()
        targets = {int(row["link_va"], 16): row for row in evidence["source_coverage"]["targets"]}
        for target in (0x92983, 0x9FEAF, 0x92A16):
            self.assertFalse(targets[target]["in_selected_capture_site_whitelist"])
            self.assertFalse(targets[target]["in_one_cycle_video_probe_window"])
            self.assertFalse(targets[target]["trace_candidate_can_run_for_target_context"])
        self.assertTrue(targets[0x94347]["in_selected_capture_site_whitelist"])
        self.assertEqual(evidence["replay_reconciliation"]["w3_109_target_event_count"], 0)
        self.assertIn("instrumentation coverage suppression", evidence["root_cause"])


if __name__ == "__main__":
    unittest.main()
