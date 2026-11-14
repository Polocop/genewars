import unittest

from tools.w3_104_vesa_page_callers import (
    parse_disassembly_call_count,
    parse_page_calls,
    validate_records,
)


class VesaPageCallersTests(unittest.TestCase):
    def test_maps_multiple_calls_to_current_owner(self):
        source = """void sub_000A0090(void) {
    RECOMP_CALL(sub_000A3A5C); /* 0x000A00F2: call 0xa3a5c */
    RECOMP_CALL(sub_000A3A5C); /* 0x000A017D: call 0xa3a5c */
}
"""
        records = parse_page_calls(source)
        self.assertEqual([r["caller"] for r in records], ["sub_000A0090"] * 2)
        self.assertEqual(records[1]["callsite_link_va"], "0x000A017D")

    def test_ignores_other_targets_and_counts_disassembly_calls(self):
        self.assertEqual(
            parse_disassembly_call_count(
                "call LbVesaSetPage_\ncall LbVesaSetMode_\ncall LbVesaSetPage_"
            ),
            2,
        )
        self.assertEqual(
            parse_page_calls("void f(void) {\n RECOMP_CALL(x); /* 0x123: call 0xa3a5c */\n}")[0]["caller"],
            "f",
        )

    def test_rejects_duplicate_callsite_addresses(self):
        records = [
            {"callsite_link_va": "0x00000010", "caller": "f", "source_line": 1},
            {"callsite_link_va": "0x00000010", "caller": "g", "source_line": 2},
        ]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_records(records, 2)


if __name__ == "__main__":
    unittest.main()
