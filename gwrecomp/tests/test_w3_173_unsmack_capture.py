import unittest
import json

from tools.w3_173_unsmack_boundary_runner import classify


def row(checkpoint, seq, *, link=0xedb20, point="unsmack_entry", pointer=0x394920,
        hex_value="00" * 16, return_runtime=0x001c5c84, return_link=0x000c5c84):
    return {
        "checkpoint": checkpoint, "sequence": seq, "link_va": link,
        "eip": 0x00100000 + link, "process_psp": 7811, "data_rebase": 0x001da000,
        "ds_descriptor_valid": True, "w3_173_wscreen_pointer_valid": True,
        "w3_173_wscreen_pointer": pointer, "w3_173_sample_bounds_valid": True,
        "w3_173_sample_valid": True, "w3_173_sample_point": point,
        "w3_173_sample_bytes": 48, "w3_173_sample_windows": [
            {"offset": o, "bytes": 16, "hex": hex_value} for o in (0, 32000, 63984)],
        "w3_173_expected_return_runtime": return_runtime,
        "w3_173_expected_return_link_va": return_link,
    }


class UnsmackCaptureTests(unittest.TestCase):
    def setUp(self):
        self.main = {"checkpoint": "MAIN_ENTRY_CHECKPOINT", "sequence": 2,
                     "link_va": 0x93f30, "eip": 0x00193f30,
                     "process_psp": 7811, "data_rebase": 0x001da000}

    def test_matching_entry_return_compares_only_bounded_windows(self):
        entry = row("W3_173_UNSMACK_ENTRY", 10)
        ret = row("W3_173_UNSMACK_RETURN", 11, link=0xc5c84,
                  point="unsmack_return", return_runtime=0, return_link=0)
        ret["eip"] = entry["w3_173_expected_return_runtime"]
        result = classify([self.main, entry, ret])
        self.assertEqual(result["classification"], "SAMPLED_BYTES_STABLE")
        self.assertEqual(result["sample_bytes_total"], 96)

    def test_invalid_bounds_fail_closed(self):
        entry = row("W3_173_UNSMACK_ENTRY", 10)
        entry["w3_173_sample_windows"] = []
        ret = row("W3_173_UNSMACK_RETURN", 11, link=0xc5c84,
                  point="unsmack_return", return_runtime=0, return_link=0)
        ret["eip"] = entry["w3_173_expected_return_runtime"]
        ret["w3_173_sample_bounds_valid"] = False
        self.assertEqual(classify([self.main, entry, ret])["classification"], "UNKNOWN")

    def test_process_and_mapping_mismatches_are_rejected(self):
        entry = row("W3_173_UNSMACK_ENTRY", 10)
        entry["process_psp"] = 9
        result = classify([self.main, entry])
        self.assertEqual(result["classification"], "ENTRY_ONLY")
        self.assertFalse(result["entry_sample_valid"])
        entry = row("W3_173_UNSMACK_ENTRY", 10)
        entry["eip"] += 0x1000
        self.assertEqual(classify([self.main, entry])["classification"], "UNKNOWN")

    def test_dynamic_arguments_and_earliest_entry_are_preserved(self):
        entry = row("W3_173_UNSMACK_ENTRY", 10)
        entry.update({"w3_173_args_valid": True, "w3_173_arg1": 80,
                      "w3_173_arg2": 50, "w3_173_arg3": 956})
        duplicate = dict(entry, sequence=12, w3_173_arg1=999)
        ret = row("W3_173_UNSMACK_RETURN", 11, link=0xc5c84,
                  point="unsmack_return", return_runtime=0, return_link=0)
        ret["eip"] = entry["w3_173_expected_return_runtime"]
        result = classify([self.main, entry, ret, duplicate])
        self.assertEqual(result["unsmack_entry"]["w3_173_arg1"], 80)
        self.assertEqual(result["unsmack_entry"]["w3_173_arg2"], 50)
        self.assertEqual(result["unsmack_entry"]["w3_173_arg3"], 956)
        self.assertEqual(len(json.dumps(result)), len(json.dumps(json.loads(json.dumps(result)))))

    def test_sample_cap_is_exactly_96_bytes(self):
        entry = row("W3_173_UNSMACK_ENTRY", 10)
        ret = row("W3_173_UNSMACK_RETURN", 11, link=0xc5c84,
                  point="unsmack_return", return_runtime=0, return_link=0)
        ret["eip"] = entry["w3_173_expected_return_runtime"]
        entry["w3_173_sample_bytes"] = 49
        self.assertEqual(classify([self.main, entry, ret])["classification"], "UNKNOWN")

    def test_entry_without_dynamic_return_is_not_promoted(self):
        result = classify([self.main, row("W3_173_UNSMACK_ENTRY", 10)])
        self.assertEqual(result["classification"], "ENTRY_ONLY")

    def test_missing_main_anchor_is_unknown(self):
        self.assertEqual(classify([])["classification"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
