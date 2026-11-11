import json
import unittest
from pathlib import Path

from tools.w3_159_wscreen_call_cfg import (
    CODE,
    CODE_BASE,
    RESULT,
    TARGET_SHA,
    build_cfg,
    parse_target,
)


class WscreenCallCfgTests(unittest.TestCase):
    def test_target_parser_handles_synthetic_hex_operands(self):
        self.assertEqual(parse_target("0x94d9f"), 0x94D9F)
        self.assertEqual(parse_target("15090"), 0x15090)
        self.assertIsNone(parse_target("dword ptr [eax]"))

    def test_synthetic_conditional_path_reaches_callsite_without_following_call_target(self):
        # jne 10006; four nops; call 1000b; ret
        data = bytes.fromhex("750490909090e800000000c3")
        cfg = build_cfg(data, start=0x10000, end=0x1000C, call_va=0x10006)
        self.assertTrue(cfg["reached_callsite_static"])
        self.assertEqual(cfg["call_instruction"]["mnemonic"], "call")
        self.assertEqual(cfg["callsite_block_start"], 0x10006)
        self.assertEqual(cfg["route_to_callsite"][-1]["to_block"], 0x10006)
        self.assertEqual(len({b["start"] for b in cfg["blocks"]}), len(cfg["blocks"]))

    def test_exact_target_provenance_and_call_edges(self):
        raw = CODE.read_bytes()
        self.assertEqual(parse_target("0x15090"), 0x15090)
        cfg = build_cfg(raw)
        self.assertTrue(cfg["reached_callsite_static"])
        self.assertEqual(cfg["call_instruction"]["address"], 0x94DBC)
        self.assertEqual(cfg["call_instruction"]["bytes"], "e8cf02f8ff")
        self.assertEqual(cfg["callsite_previous_instruction"]["address"], 0x94DB6)

    def test_persisted_gate_and_dynamic_absence_are_not_conflated(self):
        result = json.loads(RESULT.read_text(encoding="utf-8"))
        self.assertEqual(result["provenance"]["target_sha256"], TARGET_SHA)
        self.assertTrue(result["call_target_verified"])
        self.assertTrue(result["cfg"]["reached_callsite_static"])
        self.assertFalse(result["interpretation"]["dynamic_call_observed_in_w3_158"])
        gate_addresses = {int(x["link_va"], 16) for x in result["call_gate"]}
        self.assertTrue({0x94CE1, 0x94CEE}.issubset(gate_addresses))
        self.assertIn("not established", result["gate_global_references_in_range"]["scope_limit"])

    def test_json_round_trip_and_output_size_is_bounded(self):
        raw = RESULT.read_bytes()
        decoded = json.loads(raw)
        self.assertEqual(json.loads(json.dumps(decoded)), decoded)
        self.assertLess(len(raw), 1_000_000)


if __name__ == "__main__":
    unittest.main()
