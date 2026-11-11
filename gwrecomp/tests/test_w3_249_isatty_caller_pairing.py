import struct
import unittest

from tools.w3_249_isatty_caller_pairing import pair_events


def call_event(name, site, eax=1, sequence=10, target=0xC896A):
    displacement = target - (site + 5)
    code = b"\xe8" + struct.pack("<i", displacement) + b"\x90" * 11
    return {"event": "target_runtime_checkpoint", "checkpoint": name,
            "sequence": sequence, "link_va": site, "eax": eax,
            "bytes": code.hex(), "w3_249_static_callee_link_va": 0xC896A,
            "w3_249_expected_return_link_va": site + 5}


class W3249IsattyCallerPairingTests(unittest.TestCase):
    def test_pairs_callsite_entry_bx1_and_return_with_same_token(self):
        events = [
            call_event("W3_249_ISATTY_CALL_CHKTTY", 0xBA4E4, sequence=10),
            {"checkpoint": "W3_237_ISATTY_ENTRY", "sequence": 11,
             "w3_237_event_ordinal": 4, "eax": 1,
             "w3_237_isatty_return_address": 0xBA4E9},
            {"checkpoint": "W3_237_AH4400_REQUEST", "sequence": 12,
             "w3_237_event_ordinal": 7, "w3_237_correlated_isatty_entry_ordinal": 4,
             "w3_237_isatty_return_address": 0xBA4E9,
             "eax": 0x4400, "ebx": 1},
            {"checkpoint": "W3_237_AH4400_RETURN", "sequence": 13,
             "w3_237_correlated_isatty_entry_ordinal": 4,
             "eax": 0x80D3, "edx": 0x80D3, "eflags": 0x246},
        ]
        result = pair_events(events)
        self.assertEqual(result["dynamic_caller"], "__chktty_")
        pair = result["pairs"][0]
        self.assertEqual(pair["caller"]["return_link_va"], 0xBA4E9)
        self.assertEqual(pair["result"]["eax"], 0x80D3)
        self.assertFalse(pair["result"]["carry"])

    def test_same_entry_value_without_paired_return_address_stays_unknown(self):
        events = [
            call_event("W3_249_ISATTY_CALL_SOPEN_PRIMARY", 0xAFCEF, eax=5, sequence=1),
            {"checkpoint": "W3_237_ISATTY_ENTRY", "sequence": 2,
             "w3_237_event_ordinal": 1, "eax": 5,
             "w3_237_isatty_return_address": 0xAFCF4},
            {"checkpoint": "W3_237_AH4400_REQUEST", "sequence": 30,
             "w3_237_event_ordinal": 5, "eax": 0x4400, "ebx": 1},
        ]
        result = pair_events(events)
        self.assertEqual(result["dynamic_caller"], "UNKNOWN")
        self.assertEqual(result["pairs"][0]["caller_status"], "UNKNOWN")

    def test_wrong_static_target_is_rejected(self):
        event = call_event("W3_249_ISATTY_CALL_IOMODE", 0xC89C7, target=0xC8973)
        result = pair_events([event])
        self.assertEqual(result["candidate_callsites"], [])

    def test_later_callsite_cannot_be_attributed_back_to_request(self):
        events = [
            {"checkpoint": "W3_237_AH4400_REQUEST", "sequence": 1,
             "w3_237_event_ordinal": 1, "eax": 0x4400, "ebx": 1},
            call_event("W3_249_ISATTY_CALL_AIL_STARTUP", 0xB0181, sequence=2),
        ]
        self.assertEqual(pair_events(events)["dynamic_caller"], "UNKNOWN")

    def test_bx5_return_is_not_misreported_as_bx1_return(self):
        events = [
            {"checkpoint": "W3_237_AH4400_REQUEST", "sequence": 1,
             "w3_237_correlated_isatty_entry_ordinal": 1,
             "eax": 0x4400, "ebx": 5},
            {"checkpoint": "W3_237_AH4400_RETURN", "sequence": 2,
             "w3_237_correlated_isatty_entry_ordinal": 1,
             "eax": 2, "edx": 2, "eflags": 0x216},
        ]
        result = pair_events(events)
        self.assertEqual(result["bx1_requests"], [])
        self.assertEqual(result["bx1_returns"], [])
        self.assertEqual(result["ah4400_returns"][0]["eax"], 2)


if __name__ == "__main__":
    unittest.main()
