from __future__ import annotations

import copy
import unittest

from tools.w3_260_a0000_video_mapping import collect, validate


class A0000VideoMappingReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = collect()

    def test_original_traces_match_manifests(self):
        self.assertTrue(all(v["trace_matches_manifest"]
                            for v in self.data["trace_integrity"].values()))
        self.assertEqual(validate(self.data), [])

    def test_a0000_copy_is_not_mislabeled_as_visible_frame(self):
        original = self.data["original_observed"]["w3_234"]
        self.assertEqual(original["destination"], "0x000A0000")
        self.assertEqual(original["bytes_copied"], 64000)
        self.assertEqual(original["postcopy_sample_bytes"], 16)
        self.assertTrue(original["postcopy_sample_all_zero"])
        self.assertFalse(self.data["conclusion"]["first_framebuffer_verified"])
        self.assertFalse(self.data["conclusion"]["validated_frame_presented"])

    def test_bscreen_sample_is_bounded_and_uninterpreted(self):
        sample = self.data["original_observed"]["w3_203"]
        self.assertEqual(sample["allocation_bytes"], 0x4B000)
        self.assertEqual(sample["sample_bytes"], 64)
        self.assertEqual(sample["nonzero_bytes"], 0)
        self.assertFalse(self.data["conclusion"]["guest_A0000_to_host_surface_mapping_established"])

    def test_runtime_review_is_static_and_source_hash_bound(self):
        runtime = self.data["runtime_static_only"]
        self.assertEqual(runtime["evidence_level"], "STATIC_CODE_REVIEW")
        self.assertFalse(runtime["video_sink"]["guest_A0000_mapping_found"])
        self.assertTrue(all(item["matches"] for item in runtime["source_hash_checks"].values()))

    def test_rejects_invented_mapping_or_visible_frame_claim(self):
        forged = copy.deepcopy(self.data)
        forged["conclusion"]["guest_A0000_to_host_surface_mapping_established"] = True
        forged["conclusion"]["validated_frame_presented"] = True
        errors = validate(forged)
        self.assertIn("unsupported host display mapping claim", errors)
        self.assertIn("unsupported visible-frame claim", errors)


if __name__ == "__main__":
    unittest.main()
