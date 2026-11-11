import unittest

from tools.w3_251_pairing import pair_events


def token_event(checkpoint, sequence, ordinal, return_link, **extra):
    return {"checkpoint": checkpoint, "sequence": sequence,
            "w3_237_event_ordinal": ordinal,
            "w3_237_correlated_isatty_entry_ordinal": ordinal,
            "w3_251_entry_return_runtime": return_link + 0x1EB000,
            "w3_251_main_code_rebase": 0x1EB000,
            "w3_251_entry_return_link_va": return_link,
            "w3_251_token_valid": True, **extra}


class W3251EntryReturnPairingTests(unittest.TestCase):
    def test_pairs_bx1_to_chktty_using_same_run_return_token(self):
        events = [
            token_event("W3_237_ISATTY_ENTRY", 10, 7, 0xBA4E9, eax=1, edi=1),
            token_event("W3_237_AH4400_REQUEST", 11, 9, 0xBA4E9,
                        w3_237_correlated_isatty_entry_ordinal=7,
                        eax=0x4400, ebx=1, edx=0x10A822, eflags=0x202),
            token_event("W3_237_AH4400_RETURN", 12, 9, 0xBA4E9,
                        w3_237_correlated_isatty_entry_ordinal=7,
                        eax=0x80D3, edx=0x80D3, eflags=0x202),
        ]
        result = pair_events(events)
        self.assertEqual(result["dynamic_caller"], "__chktty_")
        self.assertEqual(result["pairs"][0]["status"], "PAIRED")
        self.assertEqual(result["pairs"][0]["return"]["eax"], 0x80D3)

    def test_bx5_request_is_not_classified_as_target_bx1(self):
        events = [
            token_event("W3_237_ISATTY_ENTRY", 1, 1, 0xAFCF4, eax=5, edi=5),
            token_event("W3_237_AH4400_REQUEST", 2, 1, 0xAFCF4,
                        eax=0x4400, ebx=5),
            token_event("W3_237_AH4400_RETURN", 3, 1, 0xAFCF4,
                        eax=2, edx=2, eflags=0x216),
        ]
        result = pair_events(events)
        self.assertEqual(result["bx1_requests"], [])
        self.assertEqual(result["dynamic_caller"], "UNKNOWN")

    def test_missing_or_invalid_entry_token_stays_unknown(self):
        events = [
            {"checkpoint": "W3_237_ISATTY_ENTRY", "sequence": 1,
             "w3_237_event_ordinal": 1, "w3_251_token_valid": False},
            {"checkpoint": "W3_237_AH4400_REQUEST", "sequence": 2,
             "w3_237_correlated_isatty_entry_ordinal": 1,
             "eax": 0x4400, "ebx": 1, "w3_251_token_valid": False},
            {"checkpoint": "W3_237_AH4400_RETURN", "sequence": 3,
             "w3_237_correlated_isatty_entry_ordinal": 1,
             "eax": 0x80D3, "edx": 0x80D3, "eflags": 0},
        ]
        result = pair_events(events)
        self.assertEqual(result["dynamic_caller"], "UNKNOWN")
        self.assertEqual(result["pairs"][0]["status"], "REQUEST_WITHOUT_COMPLETE_TOKEN_PAIR")

    def test_return_must_match_same_entry_ordinal(self):
        events = [
            token_event("W3_237_ISATTY_ENTRY", 1, 4, 0xBA4E9, eax=1),
            token_event("W3_237_AH4400_REQUEST", 2, 4, 0xBA4E9,
                        eax=0x4400, ebx=1),
            token_event("W3_237_AH4400_RETURN", 3, 5, 0xBA4E9,
                        eax=0x80D3, edx=0x80D3, eflags=0),
        ]
        result = pair_events(events)
        self.assertIsNone(result["pairs"][0]["return"])
        self.assertEqual(result["dynamic_caller"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
