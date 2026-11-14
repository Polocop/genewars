import unittest

from tools.w3_214_ax6300_pointer_capture import summarize


def base_rows():
    main = {"event": "target_code_anchor", "anchor": "MAIN_ENTRY", "link_va": 0xAF96C,
            "candidate_rebase": 0x1EB000, "byte_signature_matches": True,
            "process_psp": 7811}
    entry = {"event": "target_runtime_checkpoint", "checkpoint": "W3_182_DPMI0300_ENTRY",
             "link_va": 0xBC765, "eip": 0xBC765 + 0x1EB000,
             "process_psp": 7811, "sequence": 2}
    frame = bytearray(48)
    frame[4:6] = (0).to_bytes(2, "little")
    frame[28:32] = (0x6300).to_bytes(4, "little")
    frame[32:34] = (0x0002).to_bytes(2, "little")
    frame[36:38] = (0xC808).to_bytes(2, "little")
    returned = {"event": "target_runtime_checkpoint", "checkpoint": "W3_182_DPMI0300_RETURN",
                "link_va": 0xBC767, "eip": 0xBC767 + 0x1EB000,
                "process_psp": 7811, "sequence": 3,
                "w3_182_frame_valid": True, "w3_182_frame_bytes": 48,
                "w3_182_frame_hex": frame.hex(),
                "w3_214_capture_enabled": True, "w3_214_pointer_valid": True,
                "w3_214_inner_ds": 0xC808, "w3_214_inner_si": 0,
                "w3_214_inner_linear": 0xC8080,
                "w3_214_dos_dbcs_segment": 0xC808, "w3_214_dos_dbcs_offset": 0,
                "w3_214_dos_dbcs_linear": 0xC8080,
                "w3_214_matches_dos_dbcs_table": True,
                "w3_214_pointer_bounds_valid": True,
                "w3_214_sample_bytes": 16, "w3_214_sample_hex": "00" * 16}
    return [main, entry, returned]


class Ax6300PointerCaptureTests(unittest.TestCase):
    def test_requires_mapping_frame_real_mode_bounds_and_same_dos_table_pointer(self):
        result = summarize(base_rows())
        self.assertEqual(result["classification"], "ORIGINAL_DBCS_POINTER_CAPTURED")
        self.assertTrue(result["mapping_valid"])
        self.assertTrue(result["matches_dos_tables_dbcs"])
        self.assertEqual(result["return"]["w3_214_sample_bytes"], 16)

    def test_rejects_bad_bounds_or_unmatched_pointer(self):
        rows = base_rows()
        rows[-1]["w3_214_pointer_bounds_valid"] = False
        self.assertEqual(summarize(rows)["classification"], "INCONCLUSIVE")
        rows = base_rows()
        rows[-1]["w3_214_matches_dos_dbcs_table"] = False
        self.assertEqual(summarize(rows)["classification"], "INCONCLUSIVE")

    def test_rejects_duplicate_returns_and_wrong_mapping(self):
        rows = base_rows()
        rows.append(dict(rows[-1]))
        self.assertEqual(summarize(rows)["classification"], "INCONCLUSIVE")
        rows = base_rows()
        rows[-1]["eip"] += 1
        self.assertEqual(summarize(rows)["classification"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
