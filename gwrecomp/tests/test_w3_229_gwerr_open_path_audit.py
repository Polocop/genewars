import json
import tempfile
import unittest
from pathlib import Path

from tools.w3_229_gwerr_open_path_audit import build_audit


class W3229GwerrOpenPathAuditTests(unittest.TestCase):
    def test_trace_does_not_attribute_service_from_generic_open(self):
        result = build_audit()
        self.assertEqual(result["classification"], "SERVICE_UNKNOWN_AH6C_PLAUSIBLE_NOT_PROVEN")
        self.assertEqual(result["observed"]["gwerr_handle_open"][0]["sequence"], 51)
        self.assertEqual(result["observed"]["gwerr_handle_open"][0]["flags"], 1)
        self.assertEqual(result["observed"]["gwerr_ah3d_dispatch_rows"], [])
        self.assertEqual(result["observed"]["w3_228_cpu_entry_rows"], [])
        self.assertGreater(result["observed"]["all_ah3d_dispatch_rows_in_trace"], 0)
        self.assertTrue(result["observed"]["trace_under_cap"])

    def test_source_maps_ah3d_and_ah6c_distinctly(self):
        result = build_audit()
        facts = result["source_dispatch_facts"]
        self.assertTrue(facts["ah3d"]["verified_source_patterns"])
        self.assertTrue(facts["ah6c"]["verified_source_patterns"])
        self.assertGreaterEqual(facts["dos_openfile_callsite_count"], 20)
        self.assertTrue(any(x["service_or_context"].startswith("DOS_OpenFileExtended")
                            for x in facts["dos_openfile_callsite_inventory"]))

    def test_execution_frontier_keeps_pointer_not_frame_claim_separate(self):
        result = build_audit()
        frontier = result["execution_frontier"]
        self.assertEqual(frontier["stop_cause"], "TIMEOUT")
        self.assertTrue(frontier["framebuffer_assign_after"])
        self.assertTrue(all(x["pointer_value_u32"] == 0xA0000 and x["sample_bytes"] == 0
                            for x in frontier["framebuffer_assign_after"]))
        self.assertFalse(frontier["first_framebuffer_verified"])

    def test_json_serialization_and_bounded_callsite_inventory(self):
        result = build_audit()
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertLess(len(encoded.encode("utf-8")), 100_000)
        self.assertEqual(len(result["source_dispatch_facts"]["dos_openfile_callsite_inventory"]),
                         result["source_dispatch_facts"]["dos_openfile_callsite_count"])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "result.json"
            path.write_text(encoded, encoding="utf-8")
            json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
