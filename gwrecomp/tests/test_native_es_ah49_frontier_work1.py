import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class NativeEsAh49FrontierTests(unittest.TestCase):
    def test_focused_lift_uses_checked_segment_write(self):
        source = (ROOT / "build/entry_path_closure.c").read_text(encoding="utf-8")
        self.assertIn("if (!recomp_write_segment(RECOMP_SEG_ES, (uint16_t)(eax), 0x000C3D42u)) return;", source)
        self.assertNotIn("(void)(eax) /* seg reg write */; /* 0x000C3D42: mov es, eax */", source)

    def test_native_frontier_is_exact_and_fail_closed(self):
        data = json.loads((ROOT / "evidence/native_w1_037_es_ah49.json").read_text())
        self.assertEqual(data["target_sha256"], "2a0a51a5a8170cb7555cc0a745c08ed371c1500503d5cec08d77190d39822a3f")
        self.assertTrue(data["passed"])
        progress = data["native_generated_c_progress"]
        site = progress["dos_ah49_contract_test"]
        self.assertIsNone(site["live_frontier"])
        self.assertEqual(site["segment_write_fault"], {
            "segment_id": 2, "selector": "0x004C", "instruction_va": "0x000C3D42",
            "matches_measured_runtime_gap": True,
        })
        self.assertIn("NATIVE_SEGMENT_FAULT segment=2 selector=004c eip=000c3d42", data["stdout"])
        self.assertEqual(progress["dos_ah48"]["response_eax"], "0x0000004C")
        self.assertEqual(progress["dos_ah48_retry"]["instruction_va"], "0x000C3D35")
        self.assertEqual(progress["next_frontier"]["instruction_va"], "0x000AF93A")
        self.assertTrue(progress["cd_fixture_preflight"]["cue_read_only_mount"])

    def test_compile_evidence_matches_corrected_closure(self):
        report = json.loads((ROOT / "evidence/entry_path_closure_routed_compile.json").read_text())
        source_hash = __import__("hashlib").sha256((ROOT / "build/entry_path_closure.c").read_bytes()).hexdigest()
        self.assertTrue(report["passed"])
        self.assertEqual(report["function_definitions"], 1112)
        self.assertEqual(report["source_sha256"], source_hash)
        self.assertIn("0x000C3D42u", (ROOT / "build/entry_path_closure.c").read_text())

if __name__ == "__main__":
    unittest.main()


