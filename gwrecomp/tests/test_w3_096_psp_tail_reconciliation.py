import json
import unittest


def reconcile(original, native):
    o = original["original"]
    n = native["native"]
    tail = bytes.fromhex(o["psp_tail"]["tail_bytes_hex"])
    native_tail = n["command_tail"].encode("ascii")
    return {
        "same_tail": tail == native_tail and len(tail) == n["psp_tail_length"],
        "same_callsite": o["call"]["int_instruction_link_va"] == int(n["dos_int_link_va"], 16),
        "same_bx": o["call"]["ebx"] == int(n["request_bx"], 16),
        "different_addresses": o["call"]["edx"] != int(n["stream_object_pointer"], 16),
        "seed_parity_proven": False,
    }


class PspTailReconciliationTests(unittest.TestCase):
    def test_exact_tail_and_callsite_match_without_seed_claim(self):
        original = {
            "original": {
                "psp_tail": {"tail_bytes_hex": "202d6b203338393238", "tail_length": 9},
                "call": {"int_instruction_link_va": 0xC8973, "ebx": 1, "edx": 0x2E4822},
            }
        }
        native = {"native": {"command_tail": " -k 38928", "psp_tail_length": 9,
                              "dos_int_link_va": "0xc8973", "request_bx": "0x1",
                              "stream_object_pointer": "0x0010a822"}}
        result = reconcile(original, native)
        self.assertTrue(result["same_tail"])
        self.assertTrue(result["same_callsite"])
        self.assertTrue(result["same_bx"])
        self.assertTrue(result["different_addresses"])
        self.assertFalse(result["seed_parity_proven"])

    def test_tail_mismatch_is_not_masked_by_callsite_match(self):
        original = {"original": {"psp_tail": {"tail_bytes_hex": "2d78", "tail_length": 2},
                                  "call": {"int_instruction_link_va": 0xC8973, "ebx": 1, "edx": 0x2E4822}}}
        native = {"native": {"command_tail": "-y", "psp_tail_length": 2,
                              "dos_int_link_va": "0xc8973", "request_bx": "0x1",
                              "stream_object_pointer": "0x0010a822"}}
        self.assertFalse(reconcile(original, native)["same_tail"])


if __name__ == "__main__":
    unittest.main()
