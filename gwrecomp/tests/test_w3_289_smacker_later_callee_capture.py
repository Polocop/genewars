import json
import unittest

from tools.w3_289_smacker_later_callee_capture import analyze, parse_trace, source_instrumentation_valid


def checkpoint(seq, event, link, **extra):
    return {"sequence": seq, "event": event, "link_va": link, **extra}


class LaterSmackerCalleeCaptureTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            checkpoint(1, "main_mapping", 0x1000, mapping_matches=True, code_rebase=0x1EB000),
            checkpoint(2, "w3_275_second_smacker_callsite", 0x92ADD),
            checkpoint(3, "w3_275_second_smacker_media_entry", 0xAE2D0),
            checkpoint(4, "w3_278_later_play_smk_entry", 0xAE2D0),
            checkpoint(5, "w3_278_branch_target", 0xAE2E3),
            checkpoint(6, "w3_289_smacker_callee_entry", 0xAE308,
                       callee="play_smk_direct", code_rebase=0x1EB000,
                       runtime_linear=0x299308, sequence=6),
        ]

    def test_real_callee_requires_mapping_and_latch_order(self):
        result = analyze(self.rows)
        self.assertEqual(result["conclusion"], "ORIGINAL_OBSERVED_LATER_CALLEE")
        self.assertEqual(result["callee"]["link_va"], 0xAE308)
        self.assertTrue(result["callee_entry_ordered"])

    def test_alternate_callee_is_accepted_only_as_measured(self):
        alt = [dict(r) for r in self.rows]
        alt[-1].update(link_va=0xAE4D8, runtime_linear=0x2994D8, callee="play_smk_buffer")
        result = analyze(alt)
        self.assertEqual(result["callee"]["link_va"], 0xAE4D8)

    def test_no_callee_is_inconclusive_not_negative_branch_claim(self):
        result = analyze(self.rows[:-1])
        self.assertEqual(result["conclusion"], "INCONCLUSIVE_NO_LATER_CALLEE_EVENT")
        self.assertFalse(result["menu_verified"])

    def test_bad_mapping_is_rejected(self):
        bad = [dict(r) for r in self.rows]
        bad[-1]["runtime_linear"] += 1
        with self.assertRaisesRegex(ValueError, "mapping mismatch"):
            analyze(bad)

    def test_trace_caps_and_source_gate(self):
        self.assertEqual(len(parse_trace((json.dumps(self.rows[0]) + "\n").encode())), 1)
        with self.assertRaisesRegex(ValueError, "byte cap"):
            parse_trace(b"x" * (1024 * 1024 + 1))
        source = "GWRECOMP_W3_289_CAPTURE w3_275_second_smacker_callsite_seen w3_275_second_smacker_media_entry_seen w3_278_branch_target_seen candidate_link_va == 0x000ae308 || candidate_link_va == 0x000ae4d8 w3_289_smacker_callee_entry"
        self.assertTrue(source_instrumentation_valid(source))


if __name__ == "__main__":
    unittest.main()
