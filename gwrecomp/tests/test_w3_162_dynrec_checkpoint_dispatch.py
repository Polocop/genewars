import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "evidence/w3_161_wscreen_instruction_boundary.json"
TRACE = ROOT / "build/dosboxx_oracle/C/W3_161_WSCREEN_BOUNDARY_20261009_01.jsonl"
CORE = ROOT / "third_party/dosbox-staging-w3-059-instrumented/src/cpu/core_dyn_x86.cpp"


class DynrecCheckpointDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = json.loads(RESULT.read_text(encoding="utf-8"))
        cls.rows = [json.loads(line) for line in TRACE.read_text(encoding="utf-8").splitlines() if line]
        cls.source = CORE.read_text(encoding="utf-8")

    def test_trace_supports_only_inconclusive_checkpoint_claim(self):
        self.assertFalse(self.result["capture_complete"])
        self.assertEqual(self.result["observations"]["main_code_rebase_hex"], "0x1EB000")
        self.assertEqual(self.result["observations"]["main_data_rebase_hex"], "0x1DA000")
        active = self.result["observations"]["selected_checkpoints_inside_probe_window"]
        self.assertEqual(active, [{"sequence": 167,
                                   "checkpoint": "W3_157_WSCREEN_LOADER_RETURN",
                                   "link_va": "0x94DC1", "probe_active": True}])
        for link_va in (0x94CE1, 0x94CEE, 0x94CF4, 0x94D9F, 0x94DBC):
            self.assertFalse(any(row.get("event") == "target_runtime_checkpoint"
                                 and row.get("link_va") == link_va for row in self.rows))

    def test_linked_dynrec_block_can_bypass_restart_core_dispatch(self):
        restart = self.source.index("restart_core:")
        candidate = self.source.index("const bool w3_161_probe_window", restart)
        fallback = self.source.index("if (w3_143_postopen_probe_window ||", candidate)
        lookup = self.source.index("CacheBlock * block=chandler->FindCacheBlock", fallback)
        link_case = self.source.index("case BR_Link1:", lookup)
        linked_return = self.source.index("if (!block || !cache.block.running) goto restart_core;", link_case)
        direct_link = self.source.index("cache.block.running->LinkTo(ret==BR_Link2,block);", linked_return)
        direct_run = self.source.index("goto run_block;", direct_link)
        self.assertLess(restart, candidate)
        self.assertLess(candidate, fallback)
        self.assertLess(fallback, lookup)
        self.assertLess(lookup, link_case)
        self.assertLess(linked_return, direct_link)
        self.assertLess(direct_link, direct_run)

    def test_loader_entry_and_return_are_observed_even_without_w3158_callsite_event(self):
        entry = next(row for row in self.rows if row.get("sequence") == 166)
        returned = next(row for row in self.rows if row.get("sequence") == 167)
        rebase = self.result["mapping"]["code_rebase"]
        self.assertEqual(entry["checkpoint"], "W3_157_WSCREEN_LOADER_ENTRY")
        self.assertEqual(entry["link_va"], 0x15090)
        self.assertEqual(entry["w3_157_descriptor_name"], "*W_SCREEN")
        self.assertEqual(entry["return_address"] - rebase, 0x94DC1)
        self.assertEqual(returned["checkpoint"], "W3_157_WSCREEN_LOADER_RETURN")
        self.assertEqual(returned["link_va"], 0x94DC1)
        self.assertEqual(entry["w3_158_event_kind"], "")
        self.assertIsNone(self.result["checkpoints"]["callsite"])
        self.assertIsNone(self.result["checkpoints"]["loader_entry"])
        self.assertIsNone(self.result["checkpoints"]["call_return"])

    def test_probe_is_bounded_and_checked_at_restart_dispatch(self):
        self.assertIn("candidate_link_va >= 0x00094cda && candidate_link_va <= 0x00094dc1",
                      self.source)
        self.assertIn("w3_161_probe_window ||", self.source)
        self.assertIn("CPU_Cycles = 1;", self.source)
        self.assertIn("const auto nc_retcode = sync_dh_fpu_and_run_normal_core();", self.source)
        self.assertIn("goto restart_core;", self.source)
        # The trace proves one selected checkpoint had the probe flag, not that
        # every guest instruction in the interval became an observed restart.
        self.assertEqual(len(self.result["observations"]["selected_checkpoints_inside_probe_window"]), 1)


if __name__ == "__main__":
    unittest.main()
