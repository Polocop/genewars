import unittest

from tools.verify_native_alloc_chain_w1_062 import validate


def event(kind, address_field, address):
    row = {
        "kind": kind, "ordinal": "0", address_field: address,
        "eax": "00000040", "ebx": "00000040", "ecx": "00000000", "edx": "00000000",
        "esi": "00000040", "edi": "00000040", "ebp": "0010b4d0", "esp": "001a8544",
        "flags_k": "2", "flags_a": "00000000", "flags_b": "00000000", "cf": "0",
        "cs": "000c", "ds": "0014", "es": "0014", "ss": "0014", "valid": "1",
    }
    row.update({f"stack{i}": "00000000" for i in range(8)})
    if kind == "NATIVE_ALLOC_CALLSITE":
        row["caller"] = "000c3e2a" if address == "000c3e54" else "000c3d7a"
        row["target"] = "000c3d7a" if address == "000c3e54" else "000c3ca9"
        row["stack0"] = "00001000"
    return row


def sample():
    rows = [event("NATIVE_ALLOC_ENTRY", "va", x) for x in ("000c3e2a", "000c3d7a", "000c3ca9")]
    rows += [event("NATIVE_ALLOC_CALLSITE", "site", x) for x in ("000c3e54", "000c3db0")]
    return {
        "w1_062_allocator_chain": {
            "events": rows, "dynamic_caller_chain_observed": True,
            "native_ax0501_frontier": {"eip": "000c3cc1", "eax": "00000501", "ebx": "00000000", "ecx": "00001000"},
            "native_request_size_bytes": "0x00001000",
            "original_w3_070": {"same_dynamic_invocation_claimed": False},
        }
    }


class NativeAllocatorChainEvidenceTests(unittest.TestCase):
    def test_accepts_bounded_chain_and_separate_run_qualification(self):
        self.assertEqual(validate(sample()), [])

    def test_rejects_missing_dynamic_caller_evidence(self):
        data = sample()
        data["w1_062_allocator_chain"]["dynamic_caller_chain_observed"] = False
        self.assertTrue(any("caller chain" in x for x in validate(data)))

    def test_rejects_missing_entry_or_callsite(self):
        data = sample()
        data["w1_062_allocator_chain"]["events"] = data["w1_062_allocator_chain"]["events"][:-1]
        self.assertTrue(any("callsites" in x for x in validate(data)))

    def test_rejects_original_native_invocation_equivalence_claim(self):
        data = sample()
        data["w1_062_allocator_chain"]["original_w3_070"]["same_dynamic_invocation_claimed"] = True
        self.assertTrue(any("invocation identity" in x for x in validate(data)))

    def test_rejects_wrong_frontier(self):
        data = sample()
        data["w1_062_allocator_chain"]["native_ax0501_frontier"]["eip"] = "000c3d46"
        self.assertTrue(any("natural AX=0501" in x for x in validate(data)))


if __name__ == "__main__":
    unittest.main()
