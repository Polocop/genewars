import unittest

from tools.w3_261_staging_video_source import collect


class StagingVideoSourceAuditTests(unittest.TestCase):
    def test_pinned_source_and_reference_anchors(self):
        result = collect()
        self.assertTrue(result["validation"]["revision_matches"])
        self.assertTrue(result["validation"]["all_source_files_match_head"])
        self.assertTrue(result["validation"]["all_anchors_found"])

    def test_source_mapping_is_conditional_and_not_present_proof(self):
        result = collect()
        route = result["source_findings"]["a0000_memory_route"]["semantics"]
        self.assertIn("current VGA mode and graphics-controller memory-map bits", route)
        self.assertFalse(result["conclusion"]["dynamic_a0000_handler_for_gene_wars_proven"])
        self.assertFalse(result["conclusion"]["first_framebuffer_verified"])
        self.assertFalse(result["conclusion"]["menu_verified"])

    def test_mlin8_palette_and_present_gate_are_separate_claims(self):
        result = collect()
        scanout = result["source_findings"]["mode_101_scanout"]["semantics"]
        present = result["source_findings"]["frame_and_present"]["semantics"]
        self.assertIn("DAC palette", scanout)
        self.assertIn("timing/capture condition", present)
        self.assertEqual("NOT_CAPTURED", result["original_observations_from_w3_260"]["current_gfx_memory_map_bits"])
        self.assertEqual("NOT_CAPTURED", result["original_observations_from_w3_260"]["dac_palette_contents"])


if __name__ == "__main__":
    unittest.main()
