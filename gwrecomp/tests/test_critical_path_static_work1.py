import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("gwrecomp_critical_path_static", ROOT / "tools" / "critical_path_static_work1.py")
_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)
TARGET, build_evidence = _module.TARGET, _module.build_evidence


class CriticalPathStaticWork1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = build_evidence(ROOT)

    def test_static_isatty_callers_and_local_argument_provenance_are_complete(self):
        trace = self.evidence["static_ah44_provenance"]
        callers = trace["static_callers"]
        self.assertEqual({x["callsite"] for x in callers}, {
            "0x000AFCEF", "0x000AFE09", "0x000C89C7", "0x000BA4E4", "0x000B0181"
        })
        self.assertTrue(all(x["entry_eax"] and x["guard"] and x["memory_inputs"] for x in callers))
        self.assertFalse(trace["dynamic_callsite_pairing"])
        self.assertFalse(trace["fixture_seed_parity"])
        self.assertFalse(trace["first_causal_divergence_known"])

    def test_setup_play_game_and_video_static_edges_are_pinned_and_bounded(self):
        path = self.evidence["static_critical_path"]
        self.assertEqual(path["main_gate"]["calls"][0], {"callsite": "0x0009433D", "target": "0x00094AC0"})
        self.assertEqual(path["main_gate"]["calls"][1], {"callsite": "0x00094342", "target": "0x00092930"})
        self.assertEqual(path["main_gate"]["calls"][2], {"callsite": "0x00094347", "target": "0x00092710"})
        route = path["screen_route"]
        self.assertEqual([x["va"] for x in route["core_preflight"]], ["0x0009FD40", "0x000A3A00", "0x000A3A5C"])
        self.assertEqual(route["int10_sites"], ["0x000A3A91", "0x000A3AB7"])
        self.assertFalse(route["dynamic_reachability"])
        self.assertFalse(route["first_visible_image_observed"])

    def test_source_candidates_keep_exact_1_1_and_beta2_addresses_separate(self):
        matches = {x["symbol"]: x for x in self.evidence["source_guided_matches"]["matches"]}
        self.assertEqual(matches["LbScreenSetupAnyMode_"]["gene_wars_va"], "0x0009FD40")
        self.assertEqual(matches["LbScreenSetupAnyMode_"]["candidate_va_comment"], "0x000954E0")
        self.assertEqual(matches["LbVesaSetMode_"]["gene_wars_va"], "0x000A3A00")
        self.assertEqual(matches["LbVesaSetMode_"]["candidate_va_comment"], "0x000B2838")
        self.assertIn("Beta2", self.evidence["source_guided_matches"]["version_rule"])
        self.assertIsNone(matches["isatty_"]["path"])

    def test_reports_preserve_seed_and_oracle_gates(self):
        evidence = self.evidence
        self.assertEqual(evidence["target_sha256"], TARGET)
        self.assertFalse(evidence["safety"]["oracle_launched"])
        self.assertFalse(evidence["safety"]["gene_wars_fx_written"])
        self.assertFalse(evidence["static_critical_path"]["dynamic_limits"]["oracle_vhdx_present"])
        self.assertFalse(evidence["static_critical_path"]["dynamic_limits"]["oracle_sandbox_verified"])


if __name__ == "__main__":
    unittest.main()
