import unittest

from tools.w3_120_post_media_successor import (
    CONTINUATION, FALLTHROUGH, MAP, RESULT, TARGET, TRACE, derive,
)
from tools.w3_117_play_smacker_call_boundary import relative_call_target


class PostMediaSuccessorTests(unittest.TestCase):
    def test_signed_rel32_decodes_target_and_return(self):
        self.assertEqual(
            relative_call_target(CONTINUATION, bytes.fromhex("e8998dfcff")),
            (TARGET, FALLTHROUGH),
        )

    def test_hash_bound_original_event_matches_map_symbol(self):
        result = derive()
        self.assertEqual(result["dynamic_observation"]["link_va"], CONTINUATION)
        self.assertEqual(result["static_decode"]["relative_target_link_va"], TARGET)
        self.assertIn("ResetAllInputs", result["static_decode"]["map_line"])

    def test_persisted_frontier_preserves_dynamic_static_boundary(self):
        import json
        data = json.loads((RESULT.parent / "w3_120_post_media_successor.json").read_text(encoding="utf-8"))
        self.assertEqual(data["dynamic_observation"]["link_va"], CONTINUATION)
        self.assertEqual(data["static_decode"]["relative_target_link_va"], TARGET)
        self.assertTrue(any("not dynamically observed" in item for item in data["limitations"]))


if __name__ == "__main__":
    unittest.main()
